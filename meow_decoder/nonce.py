"""
Deterministic Nonce Generation for AES-256-GCM

Implements collision-resistant, deterministic nonce derivation using
HKDF-SHA-256 to prevent catastrophic nonce reuse.

Nonce Construction (Synthetic IV):
    nonce = HKDF-SHA-256(
        IKM  = transfer_root_key,
        salt = frame_counter (u64 BE) || transfer_manifest_hash,
        info = b"aes-gcm-nonce-v1",
        len  = 12
    )

Security Properties:
    1. Deterministic: same inputs always produce the same nonce.
    2. Collision-resistant: different frame_counter or manifest_hash
       guarantee different nonces (HKDF collision resistance).
    3. Crash-safe: no persistent state needed — frame_counter is
       derived from the transfer context (e.g., monotonic frame index).
    4. Multi-process safe: nonce depends on transfer_manifest_hash,
       which is unique per transfer session.
    5. Domain-separated: unique info string prevents cross-context reuse.

Comparison with random nonces:
    - Random 96-bit nonce: ~2^48 encryptions before birthday collision
      (acceptable with fresh key per transfer, but fragile under HSM reuse).
    - Synthetic IV: collision requires HKDF collision, which is
      computationally infeasible for SHA-256.

Usage:
    from meow_decoder.nonce import NonceGenerator

    gen = NonceGenerator(root_key=key_handle, manifest_hash=sha256_of_manifest)
    nonce_0 = gen.generate(frame_counter=0)
    nonce_1 = gen.generate(frame_counter=1)
    # nonce_0 != nonce_1 guaranteed by construction

See also: docs/PROTOCOL.md §2, docs/SECURITY_INVARIANTS.md INV-003.
"""

import struct
import threading
from typing import Union

from .crypto_backend import get_default_backend, get_handle_backend

# Domain separator — MUST be unique to this module
NONCE_DOMAIN_INFO = b"aes-gcm-nonce-v1"

# Distinct domain for context-bound transfer nonces. Using a separate info
# string guarantees generate_for_transfer() outputs can NEVER collide with
# generate() outputs — even when additional_context is empty, where the salt
# would otherwise be byte-identical (which would be catastrophic GCM nonce
# reuse under the same key).
NONCE_TRANSFER_DOMAIN_INFO = b"aes-gcm-nonce-transfer-v1"

# Maximum frame counter (u64)
MAX_FRAME_COUNTER = (1 << 64) - 1


class NonceGenerator:
    """Deterministic nonce generator for AES-256-GCM.

    Generates 12-byte nonces via HKDF-SHA-256 from a root key,
    frame counter, and transfer manifest hash.  Thread-safe.

    Args:
        root_key: 32-byte root key (bytes) or opaque Rust handle (int).
        manifest_hash: 32-byte SHA-256 of the transfer manifest.
            Binds nonces to a specific transfer session.

    Invariants:
        - generate() with different frame_counter values ALWAYS returns
          different nonces (HKDF collision resistance).
        - generate() is idempotent: same frame_counter → same nonce.
        - No mutable state except the monotonic high-water mark.
    """

    def __init__(self, root_key: Union[bytes, int], manifest_hash: bytes):
        if isinstance(manifest_hash, bytes) and len(manifest_hash) != 32:
            raise ValueError(f"manifest_hash must be 32 bytes, got {len(manifest_hash)}")
        self._root_key = root_key
        self._manifest_hash = manifest_hash
        self._lock = threading.Lock()
        self._high_water_mark = -1  # highest frame_counter seen
        # Reuse guard. Storing every counter ever seen grew without bound on
        # long streaming feeds (millions of frames). Instead we track a
        # contiguous "floor" (every counter in [0, floor] has been seen) plus a
        # set of out-of-order counters seen above the floor — a SACK-style
        # acknowledgement window. Reuse is still detected exactly
        # (c is reused iff c <= floor or c in seen_above), but for a monotonic
        # counter stream the floor advances each step and the set stays empty,
        # so memory is O(reordering distance), not O(stream length).
        self._counter_floor = -1
        self._counter_seen_above: set = set()
        # Same scheme per additional_context for generate_for_transfer():
        # context -> [floor, seen_above]. Distinct sub-streams may legitimately
        # reuse a frame_counter as long as their context differs.
        self._transfer_state: dict = {}

    def generate(self, frame_counter: int) -> bytes:
        """Generate a deterministic 12-byte nonce for a given frame.

        Args:
            frame_counter: Monotonic frame index (0-based, u64).
                MUST be unique per encryption under the same root key.

        Returns:
            12-byte nonce suitable for AES-256-GCM.

        Raises:
            ValueError: If frame_counter is negative or exceeds u64.
            RuntimeError: If frame_counter was already used (reuse guard).
        """
        if frame_counter < 0:
            raise ValueError(f"frame_counter must be non-negative, got {frame_counter}")
        if frame_counter > MAX_FRAME_COUNTER:
            raise ValueError(f"frame_counter exceeds u64 max ({MAX_FRAME_COUNTER})")

        with self._lock:
            # Reuse guard: reject duplicate frame counters (bounded SACK window).
            if frame_counter <= self._counter_floor or frame_counter in self._counter_seen_above:
                raise RuntimeError(
                    f"Nonce reuse detected: frame_counter={frame_counter} already used. "
                    "This is a CRITICAL error — AES-GCM nonce reuse breaks all security."
                )
            self._counter_seen_above.add(frame_counter)
            # Advance the contiguous floor, dropping now-contiguous entries so
            # the set collapses to empty for an in-order stream.
            while (self._counter_floor + 1) in self._counter_seen_above:
                self._counter_floor += 1
                self._counter_seen_above.discard(self._counter_floor)
            self._high_water_mark = max(self._high_water_mark, frame_counter)

        # Construct salt: frame_counter (u64 BE) || manifest_hash
        salt = struct.pack(">Q", frame_counter) + self._manifest_hash

        # Derive nonce via HKDF-SHA-256
        if isinstance(self._root_key, int):
            # Handle-based: nonce bytes are non-secret, safe to extract
            hb = get_handle_backend()
            nonce = hb.derive_key_hkdf_bytes(self._root_key, salt, NONCE_DOMAIN_INFO, 12)
        else:
            # Bytes-based (test/legacy path)
            backend = get_default_backend()
            nonce = backend.derive_key_hkdf(self._root_key, salt, NONCE_DOMAIN_INFO, 12)

        return nonce

    def generate_for_transfer(self, frame_counter: int, additional_context: bytes = b"") -> bytes:
        """Generate nonce with optional additional context binding.

        This variant allows binding extra context (e.g., sub-stream ID)
        into the nonce derivation, useful for Schrödinger mode where
        two independent sub-streams share a transfer session.

        Args:
            frame_counter: Monotonic frame index.
            additional_context: Extra bytes bound into derivation.

        Returns:
            12-byte nonce.
        """
        if frame_counter < 0:
            raise ValueError(f"frame_counter must be non-negative, got {frame_counter}")
        if frame_counter > MAX_FRAME_COUNTER:
            raise ValueError(f"frame_counter exceeds u64 max ({MAX_FRAME_COUNTER})")

        with self._lock:
            # Per-context bounded reuse guard. Distinct sub-streams may reuse a
            # frame_counter with a different context, but the SAME pair twice
            # would reuse a nonce under the same key. Each context keeps its own
            # SACK-style (floor, seen_above) window so a monotonic sub-stream
            # stays O(1) in memory.
            state = self._transfer_state.get(additional_context)
            if state is None:
                state = [-1, set()]
                self._transfer_state[additional_context] = state
            floor, seen_above = state
            if frame_counter <= floor or frame_counter in seen_above:
                raise RuntimeError(
                    f"Nonce reuse detected: frame_counter={frame_counter} with this "
                    "additional_context already used. AES-GCM nonce reuse breaks all security."
                )
            seen_above.add(frame_counter)
            while (state[0] + 1) in seen_above:
                state[0] += 1
                seen_above.discard(state[0])
            self._high_water_mark = max(self._high_water_mark, frame_counter)

        salt = struct.pack(">Q", frame_counter) + self._manifest_hash + additional_context

        # Use the transfer-specific domain so these nonces are guaranteed
        # disjoint from generate()'s, even when additional_context is empty.
        if isinstance(self._root_key, int):
            hb = get_handle_backend()
            nonce = hb.derive_key_hkdf_bytes(self._root_key, salt, NONCE_TRANSFER_DOMAIN_INFO, 12)
        else:
            backend = get_default_backend()
            nonce = backend.derive_key_hkdf(self._root_key, salt, NONCE_TRANSFER_DOMAIN_INFO, 12)

        return nonce

    @property
    def high_water_mark(self) -> int:
        """Return the highest frame_counter used so far."""
        return self._high_water_mark

    def reset(self) -> None:
        """Reset the generator state. USE WITH EXTREME CAUTION.

        Only valid when starting a completely new transfer session
        with a new root_key and manifest_hash.
        """
        with self._lock:
            self._high_water_mark = -1
            self._counter_floor = -1
            self._counter_seen_above.clear()
            self._transfer_state.clear()


def derive_transfer_nonce(
    root_key: Union[bytes, int],
    frame_counter: int,
    manifest_hash: bytes,
    additional_context: bytes = b"",
) -> bytes:
    """Stateless nonce derivation (for single-use contexts).

    Convenience function for callers that manage their own counter state.
    Does NOT enforce monotonicity or reuse detection — caller is responsible.

    Args:
        root_key: 32-byte key or Rust handle.
        frame_counter: Frame index (u64).
        manifest_hash: 32-byte transfer manifest hash.
        additional_context: Optional extra binding data.

    Returns:
        12-byte deterministic nonce.
    """
    salt = struct.pack(">Q", frame_counter) + manifest_hash + additional_context

    if isinstance(root_key, int):
        hb = get_handle_backend()
        return hb.derive_key_hkdf_bytes(root_key, salt, NONCE_DOMAIN_INFO, 12)
    else:
        backend = get_default_backend()
        return backend.derive_key_hkdf(root_key, salt, NONCE_DOMAIN_INFO, 12)
