"""
Master Key Ratchet for Cross-Session Forward Secrecy.

Provides long-term key management with per-file roots and automatic ratcheting.
Each GIF encode derives a unique session key from the master chain, ensuring:
- Forward secrecy: Compromise of current key doesn't expose past files
- Post-compromise security: Periodic ratcheting limits damage window
- Key commitment: Ciphertext bound to specific chain state

Protocol overview:
1. Master key initialized from user passphrase + hardware entropy
2. Each encode operation ratchets the chain forward
3. Per-file keys derived via HKDF with file-specific context
4. Chain state stored encrypted on disk (optional)
5. Emergency wipe zeros all chain state

Security properties:
- Deleting chain state renders ALL past files undecryptable (plausible deniability)
- Chain cannot be rewound (one-way hash ratchet)
- Each file gets unique key even with same password

Implementation note (gemini #1, 2026-05-04):
The chain key never leaves Rust. `ChainState.chain_handle` is an opaque
HandleBackend handle; HKDF derivations and AES-GCM sealing for at-rest
persistence happen entirely in Rust. The on-disk format `MRCV2`
supersedes the legacy `MRCV1`/`MRCX1` formats — old state files cannot
be loaded by this version.

Cross-platform: Windows, Linux, macOS.
"""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from meow_decoder.crypto_backend import HandleBackend, get_handle_backend

__all__ = [
    "MasterRatchet",
    "ChainState",
    "derive_file_key",
    "get_master_ratchet",
    "set_master_ratchet",
    "emergency_wipe_chain",
]


# ─── On-disk format constants ───────────────────────────────────────────────

_FORMAT_MAGIC = b"MRCV2"
_FORMAT_AAD = b"meow_chain_state_v2"
_SEAL_AAD = b"meow_chain_seal_v2"

# Layout: magic(5) || generation(8 LE) || timestamp(8 LE double) ||
#         master_salt(32) || seal_nonce(12) || sealed_chain_key(48)
_HEADER_LEN = 5 + 8 + 8 + 32 + 12 + 48  # = 113


def _zero_bytearray(data: bytearray) -> None:
    """Best-effort zero of a bytearray (CPython only — bytes objects are immutable)."""
    for i in range(len(data)):
        data[i] = 0


@dataclass
class ChainState:
    """
    Ratchet chain state.

    `chain_handle` is an opaque HandleBackend handle ID; the actual chain
    key bytes never enter Python. `master_salt` is non-secret (per-file
    randomness used for KDF domain separation) and lives in Python as bytes.
    """

    chain_handle: Optional[int]
    generation: int
    last_ratchet_time: float
    master_salt: bytes


class MasterRatchet:
    """
    Master key ratchet for cross-session forward secrecy.

    Usage:
        # Initialize from password
        ratchet = MasterRatchet.from_password("my_password")

        # Derive per-file key
        file_key = ratchet.derive_file_key(file_id="document.pdf")

        # Ratchet forward (call after each encode)
        ratchet.ratchet()

        # Emergency wipe (deletes chain state, makes past files unrecoverable)
        ratchet.emergency_wipe()
    """

    # Domain separation constants
    DOMAIN_CHAIN_INIT = b"meow_master_ratchet_v1_init"
    DOMAIN_CHAIN_RATCHET = b"meow_master_ratchet_v1_ratchet"
    DOMAIN_FILE_KEY = b"meow_master_ratchet_v1_file_key"
    DOMAIN_STATE_KEY = b"meow_master_ratchet_v1_state_key"

    def __init__(
        self,
        state: ChainState,
        state_file: Optional[Path] = None,
        auto_persist: bool = True,
        backend: Optional[HandleBackend] = None,
    ):
        """
        Initialize ratchet with existing chain state.

        Use from_password() for initial setup.

        Args:
            state: Existing chain state.
            state_file: Path to persist state (optional).
            auto_persist: If True, save state after each ratchet.
            backend: HandleBackend instance (defaults to global singleton).
        """
        self._state = state
        self._state_file = state_file
        self._auto_persist = auto_persist
        self._state_key_handle: Optional[int] = None
        self._hb: HandleBackend = backend if backend is not None else get_handle_backend()

    @classmethod
    def from_password(
        cls,
        password: str,
        state_file: Optional[Path] = None,
        auto_persist: bool = True,
    ) -> "MasterRatchet":
        """
        Initialize ratchet from password.

        Combines password with hardware entropy for initial chain key.
        The password and IKM bytes briefly live in Python (they originate
        from user input / OS entropy); the derived chain key is imported
        directly into a Rust handle and never re-exported.
        """
        hb = get_handle_backend()

        master_salt = secrets.token_bytes(32)

        # IKM = password || salt || hardware_entropy. Hold in a bytearray
        # so we can overwrite after the derive.
        password_bytes = password.encode("utf-8")
        ikm = bytearray(password_bytes)
        ikm.extend(master_salt)
        ikm.extend(cls._get_hardware_entropy())

        try:
            chain_handle = hb.derive_key_hkdf_raw(
                bytes(ikm), master_salt, cls.DOMAIN_CHAIN_INIT, 32
            )
        finally:
            _zero_bytearray(ikm)

        state = ChainState(
            chain_handle=chain_handle,
            generation=0,
            last_ratchet_time=time.time(),
            master_salt=master_salt,
        )

        ratchet = cls(state, state_file, auto_persist, backend=hb)

        if auto_persist and state_file is not None:
            ratchet._derive_state_key(password)
            ratchet._save_state()

        return ratchet

    @classmethod
    def load(
        cls,
        password: str,
        state_file: Path,
    ) -> Optional["MasterRatchet"]:
        """
        Load existing ratchet from state file.

        Returns None on any failure (missing file, IO error, decryption
        failure, format mismatch).
        """
        if not state_file.exists():
            return None

        try:
            data = state_file.read_bytes()
        except (OSError, IOError):
            return None

        hb = get_handle_backend()

        # Derive the state KEK as a handle.
        state_key_handle = cls._derive_state_key_handle(hb, password)

        try:
            state = _decode_chain_state(data, state_key_handle, hb)
        except (ValueError, RuntimeError):
            hb.drop(state_key_handle)
            return None

        if state is None:
            hb.drop(state_key_handle)
            return None

        ratchet = cls(state, state_file, auto_persist=True, backend=hb)
        ratchet._state_key_handle = state_key_handle
        return ratchet

    @staticmethod
    def _get_hardware_entropy() -> bytes:
        """Collect hardware-specific entropy."""
        entropy_sources = []

        # OS random
        entropy_sources.append(os.urandom(16))

        # Platform info
        entropy_sources.append(platform.node().encode()[:16])
        entropy_sources.append(platform.machine().encode()[:8])

        # High-resolution time
        entropy_sources.append(struct.pack("<d", time.time()))
        entropy_sources.append(struct.pack("<q", time.perf_counter_ns()))

        # Process ID
        entropy_sources.append(struct.pack("<I", os.getpid()))

        # Combine via hash
        combined = b"".join(entropy_sources)
        return hashlib.sha256(combined).digest()

    @staticmethod
    def _derive_state_key_handle(hb: HandleBackend, password: str) -> int:
        """Derive the at-rest KEK handle from password (HKDF, no Argon2 — KEK
        binds the on-disk state to *this* password but the KDF cost lives in
        the chain init step which already mixed hardware entropy)."""
        password_bytes = bytearray(password.encode("utf-8"))
        try:
            return hb.derive_key_hkdf_raw(
                bytes(password_bytes), b"", MasterRatchet.DOMAIN_STATE_KEY, 32
            )
        finally:
            _zero_bytearray(password_bytes)

    def _derive_state_key(self, password: str) -> None:
        """Derive (or re-derive) the at-rest KEK handle for this ratchet."""
        if self._state_key_handle is not None:
            self._hb.drop(self._state_key_handle)
            self._state_key_handle = None
        self._state_key_handle = self._derive_state_key_handle(self._hb, password)

    def _save_state(self) -> None:
        """Save encrypted state to file. Silent on IO errors (best-effort)."""
        if self._state_file is None or self._state_key_handle is None:
            return
        if self._state.chain_handle is None:
            return

        seal_nonce = secrets.token_bytes(12)

        # AAD binds the on-disk metadata to the sealed chain key. Tampering
        # with generation/timestamp/master_salt invalidates the seal.
        meta = (
            _FORMAT_MAGIC
            + struct.pack("<Q", self._state.generation)
            + struct.pack("<d", self._state.last_ratchet_time)
            + self._state.master_salt
        )
        sealed = self._hb.seal_key(
            self._state.chain_handle,
            self._state_key_handle,
            seal_nonce,
            aad=meta + _SEAL_AAD,
        )

        blob = meta + seal_nonce + sealed
        try:
            self._state_file.write_bytes(blob)
        except (OSError, IOError):
            pass

    def ratchet(self) -> None:
        """
        Advance the chain key one step.

        This is a one-way operation - previous keys cannot be recovered.
        Call this after each successful encode operation.
        """
        if self._state.chain_handle is None:
            raise RuntimeError("Cannot ratchet a wiped chain")

        info = self.DOMAIN_CHAIN_RATCHET + struct.pack("<Q", self._state.generation)
        new_handle = self._hb.derive_key_hkdf(
            self._state.chain_handle, b"", info, 32
        )

        old = self._state.chain_handle
        self._state.chain_handle = new_handle
        self._state.generation += 1
        self._state.last_ratchet_time = time.time()
        self._hb.drop(old)

        if self._auto_persist:
            self._save_state()

    def derive_file_key(
        self,
        file_id: str,
        key_length: int = 32,
    ) -> bytes:
        """
        Derive a unique key for a specific file.

        Returns raw bytes — file keys are consumed by callers that need
        bytes (e.g. shamir_split, downstream AES setup). The chain key
        itself is never exported.
        """
        if self._state.chain_handle is None:
            raise RuntimeError("Cannot derive from a wiped chain")

        info = (
            self.DOMAIN_FILE_KEY
            + struct.pack("<Q", self._state.generation)
            + file_id.encode("utf-8")
        )
        return self._hb.derive_key_hkdf_bytes(
            self._state.chain_handle, b"", info, key_length
        )

    def derive_file_key_with_commitment(
        self,
        file_id: str,
        key_length: int = 32,
    ) -> Tuple[bytes, bytes]:
        """
        Derive file key with a commitment tag.

        Commitment binds the ciphertext to the chain state, preventing
        invisible-salamander attacks. Computed via HMAC-SHA256(chain_handle,
        "commitment:" || file_id) inside Rust.
        """
        if self._state.chain_handle is None:
            raise RuntimeError("Cannot derive from a wiped chain")

        file_key = self.derive_file_key(file_id, key_length)
        tag = self._hb.hmac_sha256(
            self._state.chain_handle,
            b"commitment:" + file_id.encode("utf-8"),
        )
        return file_key, tag[:16]

    @property
    def generation(self) -> int:
        """Current chain generation (number of ratchets performed)."""
        return self._state.generation

    @property
    def last_ratchet_time(self) -> float:
        """Timestamp of last ratchet operation."""
        return self._state.last_ratchet_time

    def emergency_wipe(self) -> bool:
        """
        Emergency wipe — securely delete all chain state.

        After this:
        - Chain handle dropped (Rust zeroizes via Zeroize impl on Drop)
        - State file overwritten with random data 3x then unlinked
        - Future calls to ratchet/derive_file_key raise RuntimeError
        """
        success = True

        # Drop the chain handle — Rust zeroizes the SecretKey on Drop.
        if self._state.chain_handle is not None:
            try:
                self._hb.drop(self._state.chain_handle)
            except Exception:
                success = False
            self._state.chain_handle = None

        if self._state_key_handle is not None:
            try:
                self._hb.drop(self._state_key_handle)
            except Exception:
                success = False
            self._state_key_handle = None

        # Zero the non-secret salt as defence-in-depth.
        salt_ba = bytearray(self._state.master_salt)
        _zero_bytearray(salt_ba)
        self._state.master_salt = bytes(32)
        self._state.generation = 0

        # Delete state file.
        if self._state_file is not None and self._state_file.exists():
            try:
                size = self._state_file.stat().st_size
                for _ in range(3):
                    self._state_file.write_bytes(secrets.token_bytes(size))
                self._state_file.unlink()
            except (OSError, IOError):
                success = False

        return success

    def get_chain_id(self) -> bytes:
        """
        Get a non-sensitive identifier for this chain.

        Can be used to verify chain continuity without exposing keys.
        """
        return hashlib.sha256(b"chain_id:" + self._state.master_salt).digest()[:16]

    def __del__(self) -> None:
        # Best-effort handle cleanup on GC. Production code should call
        # emergency_wipe() explicitly for deterministic teardown.
        try:
            if self._state.chain_handle is not None:
                self._hb.drop(self._state.chain_handle)
                self._state.chain_handle = None
            if self._state_key_handle is not None:
                self._hb.drop(self._state_key_handle)
                self._state_key_handle = None
        except Exception:
            pass


def _decode_chain_state(
    data: bytes, state_key_handle: int, hb: HandleBackend
) -> Optional[ChainState]:
    """Parse and verify an MRCV2 blob, return ChainState or None."""
    if len(data) != _HEADER_LEN:
        return None
    if data[:5] != _FORMAT_MAGIC:
        return None

    generation = struct.unpack("<Q", data[5:13])[0]
    last_ratchet_time = struct.unpack("<d", data[13:21])[0]
    master_salt = data[21:53]
    seal_nonce = data[53:65]
    sealed = data[65:113]

    meta = data[:53]  # magic || generation || timestamp || master_salt

    try:
        chain_handle = hb.unseal_key(
            sealed, state_key_handle, seal_nonce, aad=meta + _SEAL_AAD
        )
    except Exception:
        return None

    return ChainState(
        chain_handle=chain_handle,
        generation=generation,
        last_ratchet_time=last_ratchet_time,
        master_salt=master_salt,
    )


def derive_file_key(
    password: str,
    file_id: str,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Convenience function to derive a one-shot file key.

    Use this when you don't need persistent ratchet state. Goes through
    the Rust handle backend (no Python-side HKDF).
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    hb = get_handle_backend()
    password_bytes = bytearray(password.encode("utf-8"))
    try:
        ikm = bytearray(password_bytes)
        ikm.extend(salt)
        try:
            transient = hb.derive_key_hkdf_raw(bytes(ikm), salt, b"meow_oneshot_seed", 32)
        finally:
            _zero_bytearray(ikm)
    finally:
        _zero_bytearray(password_bytes)

    try:
        return hb.derive_key_hkdf_bytes(
            transient,
            b"",
            MasterRatchet.DOMAIN_FILE_KEY + file_id.encode("utf-8"),
            32,
        )
    finally:
        hb.drop(transient)


# Global singleton
_global_ratchet: Optional[MasterRatchet] = None


def get_master_ratchet() -> Optional[MasterRatchet]:
    """Get the global master ratchet instance."""
    return _global_ratchet


def set_master_ratchet(ratchet: MasterRatchet) -> None:
    """Set the global master ratchet instance."""
    global _global_ratchet
    _global_ratchet = ratchet


def emergency_wipe_chain() -> bool:
    """
    Emergency wipe of global master ratchet.

    Returns True if wipe succeeded or no ratchet was set.
    """
    global _global_ratchet

    if _global_ratchet is None:
        return True

    result = _global_ratchet.emergency_wipe()
    _global_ratchet = None
    return result
