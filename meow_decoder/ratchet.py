"""
Per-Frame Symmetric Ratchet for Post-Compromise Security

Implements a Signal-inspired symmetric hash ratchet that provides per-frame
forward secrecy for fountain-coded QR/GIF air-gap file transfer.

═══════════════════════════════════════════════════════════════════════════════
PROTOCOL OVERVIEW: MEOW Symmetric Ratchet (MSR v1)
═══════════════════════════════════════════════════════════════════════════════

Key Hierarchy:

    root_key (from Argon2id / X25519 / PQ hybrid)
         │
         │  HKDF(root_key, salt, "meow_ratchet_root_v1")
         ▼
    chain_key[0]
         │
         ├──── HKDF(ck[0], salt, "meow_ratchet_msg_v1")  ──► message_key[0]
         │                                                         │
         │  HKDF(ck[0], salt, "meow_ratchet_step_v1")     ┌───────┼───────┐
         ▼                                                 │       │       │
    chain_key[1]                                      enc_key  nonce    mac_key
         │                                            (32B)   (12B)    (32B)
         ├──── message_key[1]
         │
         ▼
    chain_key[2]  ...

Security Properties:
    1. Per-frame forward secrecy: chain_key[i] → chain_key[i+1] is one-way
       (HKDF-SHA256). Compromising frame N reveals nothing about frames 0..N-1.
    2. Key deletion: Each chain_key and message_key is zeroized immediately
       after deriving its successor/subkeys.
    3. Subkey independence: enc_key, nonce, mac_key derived via domain-separated
       HKDF from message_key — compromise of one subkey doesn't reveal others.
    4. Replay prevention: Frame index is bound in AES-GCM AAD, preventing
       frame reordering attacks.
    5. Fountain compatibility: Frame index is explicit in frame header,
       enabling out-of-order reception for fountain code decoding.

Limitations (documented honestly):
    - No DH ratchet: Air-gap is unidirectional, so no asymmetric re-keying.
      If chain_key[N] is compromised, all subsequent keys are derivable.
      This is inherent to ANY unidirectional protocol.
    - Mitigation: Chain keys exist only during encode/decode session (not at
      rest). The primary threat model is post-capture forensic analysis.

Comparison with Signal Double Ratchet:
    ┌──────────────────────┬─────────────────┬────────────────────┐
    │ Property             │ Signal          │ MEOW (MSR v1)      │
    ├──────────────────────┼─────────────────┼────────────────────┤
    │ Symmetric ratchet    │ ✓ per-message   │ ✓ per-frame        │
    │ DH ratchet           │ ✓ per-reply     │ ✗ (unidirectional) │
    │ Forward secrecy      │ ✓ per-message   │ ✓ per-frame        │
    │ Post-compromise sec. │ ✓ (via DH)      │ ✗ (no back-chan)   │
    │ Out-of-order support │ Bounded window  │ Full (fountain)    │
    │ Key zeroization      │ ✓               │ ✓                  │
    │ Header encryption    │ ✓               │ ✗ (idx plaintext)  │
    └──────────────────────┴─────────────────┴────────────────────┘

See docs/RATCHET_PROTOCOL.md for formal specification.
"""

import os
import struct
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ── Domain Separation Constants ──────────────────────────────────────────────
# Each HKDF derivation uses a unique info string to ensure cryptographic
# independence between derived keys. Never reuse these across modules.

RATCHET_ROOT_INFO = b"meow_ratchet_root_v1"
RATCHET_STEP_INFO = b"meow_ratchet_step_v1"
RATCHET_MSG_INFO = b"meow_ratchet_msg_v1"
FRAME_ENC_INFO = b"meow_ratchet_frame_enc_v1"
FRAME_NONCE_INFO = b"meow_ratchet_frame_nonce_v1"
FRAME_MAC_INFO = b"meow_ratchet_frame_mac_v1"

# Frame header size: 4 bytes (frame index, big-endian uint32)
FRAME_INDEX_SIZE = 4

# AES-GCM tag size
GCM_TAG_SIZE = 16

# AAD domain prefix for ratchet-encrypted frames
RATCHET_AAD_PREFIX = b"MEOW_RATCHET_V1"

# Maximum frame index (2^32 - 1)
MAX_FRAME_INDEX = 0xFFFFFFFF

# Maximum number of skipped message keys to cache (DoS bound for decoder)
MAX_SKIP_KEYS = 2000

# ── Rekey Beacon Constants ───────────────────────────────────────────────────
# Sender rekey beacons inject fresh entropy at periodic intervals.
# Two modes:
#   1. KEM mode (MEOW3/4): X25519 ephemeral → receiver. Attacker with chain_key
#      + GIF but NOT receiver_private_key cannot derive enhanced message keys.
#   2. Plaintext mode (MEOW2): Random beacon in frame header. Protects against
#      memory-only compromise (attacker has chain_key but NOT the GIF).

REKEY_BEACON_INFO = b"meow_ratchet_rekey_v1"
REKEY_BEACON_KEM_INFO = b"meow_ratchet_kem_v1"
REKEY_BEACON_SIZE = 32  # X25519 public key or random entropy
DEFAULT_REKEY_INTERVAL = 0  # 0 = disabled; recommended: 32


# ── Secure Memory Helpers ────────────────────────────────────────────────────


def _secure_zero(buf: bytearray) -> None:
    """Best-effort zeroization of a mutable buffer."""
    try:
        from .crypto_backend import get_default_backend

        get_default_backend().secure_zero(buf)
    except Exception:
        # Fallback: manual zeroing
        for i in range(len(buf)):
            buf[i] = 0


def _hkdf_derive(key_material: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 key derivation with domain separation."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)


def _mix_beacon(message_key: bytes, beacon_secret: bytes, salt: bytes) -> bytes:
    """Mix rekey beacon entropy into a message key.

    Combines the ratchet-derived message key with fresh beacon entropy
    using HKDF. The resulting key requires knowledge of BOTH the chain
    state AND the beacon secret (which may be KEM-derived).
    """
    combined = message_key + beacon_secret
    return _hkdf_derive(combined, salt, REKEY_BEACON_INFO, 32)


def _generate_kem_beacon(receiver_public_key: bytes) -> Tuple[bytes, bytes]:
    """Generate X25519 KEM rekey beacon.

    Returns:
        (shared_secret, ephemeral_public_bytes) — shared_secret is mixed
        into the message key; ephemeral_public is embedded in the frame.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    receiver_pub = X25519PublicKey.from_public_bytes(receiver_public_key)
    raw_shared = ephemeral_private.exchange(receiver_pub)

    shared_secret = _hkdf_derive(raw_shared, b"", REKEY_BEACON_KEM_INFO, 32)

    ephemeral_public_bytes = ephemeral_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return shared_secret, ephemeral_public_bytes


def _recover_kem_beacon(ephemeral_public_bytes: bytes, receiver_private_key: bytes) -> bytes:
    """Recover shared secret from X25519 KEM rekey beacon.

    Args:
        ephemeral_public_bytes: 32-byte ephemeral public key from frame header
        receiver_private_key: Receiver's X25519 private key

    Returns:
        32-byte shared secret to mix into message key
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    eph_pub = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    priv = X25519PrivateKey.from_private_bytes(receiver_private_key)
    raw_shared = priv.exchange(eph_pub)

    shared_secret = _hkdf_derive(raw_shared, b"", REKEY_BEACON_KEM_INFO, 32)
    return shared_secret


# ── Data Structures ──────────────────────────────────────────────────────────


@dataclass
class FrameKeys:
    """Per-frame derived subkeys. All fields are mutable bytearrays for zeroization."""

    enc_key: bytearray  # 32 bytes: AES-256 encryption key
    nonce: bytearray  # 12 bytes: AES-GCM nonce
    mac_key: bytearray  # 32 bytes: Frame authentication key

    def zeroize(self) -> None:
        """Securely zero all subkeys."""
        _secure_zero(self.enc_key)
        _secure_zero(self.nonce)
        _secure_zero(self.mac_key)


@dataclass
class RatchetState:
    """
    Mutable ratchet chain state.

    The chain_key advances forward with each ratchet_step().
    Previous chain_keys are irrecoverable after zeroization.
    """

    chain_key: bytearray  # 32 bytes: current chain key (mutable for zeroization)
    salt: bytes  # 16 bytes: session salt (immutable, from manifest)
    position: int = 0  # Current chain position (frame index)

    def zeroize(self) -> None:
        """Securely zero the chain key. Call when ratchet is no longer needed."""
        _secure_zero(self.chain_key)
        self.position = -1  # Sentinel: state is dead


# ── Core Ratchet Operations ──────────────────────────────────────────────────


def init_ratchet(root_key: bytes, salt: bytes) -> RatchetState:
    """
    Initialize a ratchet chain from root key material.

    Args:
        root_key: 32-byte root key (from Argon2id / X25519 / PQ hybrid)
        salt: 16-byte random salt (from manifest)

    Returns:
        RatchetState at position 0

    Security:
        - HKDF domain separation from encryption/HMAC keys
        - root_key is NOT stored in the ratchet state
        - chain_key[0] is cryptographically independent of root_key's
          other derivations (encryption key, HMAC key, frame MAC key)
    """
    chain_key_0 = _hkdf_derive(root_key, salt, RATCHET_ROOT_INFO, 32)
    return RatchetState(
        chain_key=bytearray(chain_key_0),
        salt=salt,
        position=0,
    )


def ratchet_step(state: RatchetState) -> Tuple[bytes, RatchetState]:
    """
    Advance the ratchet by one step, producing a message key.

    This is the core forward-secrecy primitive:
        message_key[i] = HKDF(chain_key[i], salt, "meow_ratchet_msg_v1")
        chain_key[i+1] = HKDF(chain_key[i], salt, "meow_ratchet_step_v1")
        ZEROIZE(chain_key[i])

    After this call, chain_key[i] is irrecoverable. An attacker who
    compromises chain_key[i+1] cannot derive chain_key[i] or message_key[i]
    (HKDF-SHA256 one-wayness).

    Args:
        state: Current ratchet state (CONSUMED — chain_key will be zeroized)

    Returns:
        (message_key, new_state) — message_key is 32 bytes

    Raises:
        ValueError: If state is dead (already zeroized) or at max position
    """
    if state.position < 0:
        raise ValueError("Ratchet state is dead (already zeroized)")
    if state.position > MAX_FRAME_INDEX:
        raise ValueError(f"Ratchet position overflow: {state.position} > {MAX_FRAME_INDEX}")

    current_key = bytes(state.chain_key)

    # Derive message key (for this frame)
    message_key = _hkdf_derive(current_key, state.salt, RATCHET_MSG_INFO, 32)

    # Derive next chain key (irreversible forward step)
    next_chain_key = _hkdf_derive(current_key, state.salt, RATCHET_STEP_INFO, 32)

    # CRITICAL: Zeroize the current chain key before replacing
    _secure_zero(state.chain_key)

    # Create new state with advanced position
    new_state = RatchetState(
        chain_key=bytearray(next_chain_key),
        salt=state.salt,
        position=state.position + 1,
    )

    return message_key, new_state


def derive_frame_keys(message_key: bytes, salt: bytes) -> FrameKeys:
    """
    Derive per-frame subkeys from a message key.

    Subkey derivation uses domain-separated HKDF to ensure independence:
        enc_key  = HKDF(message_key, salt, "meow_ratchet_frame_enc_v1")[:32]
        nonce    = HKDF(message_key, salt, "meow_ratchet_frame_nonce_v1")[:12]
        mac_key  = HKDF(message_key, salt, "meow_ratchet_frame_mac_v1")[:32]

    Args:
        message_key: 32-byte message key from ratchet_step()
        salt: 16-byte session salt

    Returns:
        FrameKeys with all subkeys as mutable bytearrays
    """
    enc_key = _hkdf_derive(message_key, salt, FRAME_ENC_INFO, 32)
    nonce = _hkdf_derive(message_key, salt, FRAME_NONCE_INFO, 12)
    mac_key = _hkdf_derive(message_key, salt, FRAME_MAC_INFO, 32)

    return FrameKeys(
        enc_key=bytearray(enc_key),
        nonce=bytearray(nonce),
        mac_key=bytearray(mac_key),
    )


def build_frame_aad(
    frame_index: int, salt: bytes, k_blocks: int, block_size: int, total_frames: int
) -> bytes:
    """
    Build Additional Authenticated Data for per-frame AES-GCM encryption.

    Layout:
        RATCHET_AAD_PREFIX || frame_index(4 LE) || k_blocks(2 LE) ||
        block_size(2 LE) || total_frames(4 LE) || salt(16)

    The frame_index binding prevents frame reordering attacks.
    The salt binding prevents cross-session replay.
    k_blocks/block_size/total_frames bind the frame to its encoding context.

    Args:
        frame_index: 0-based frame index
        salt: 16-byte session salt
        k_blocks: Number of fountain source blocks
        block_size: Fountain block size in bytes
        total_frames: Total number of frames (manifest + droplets)

    Returns:
        Deterministic AAD bytestring
    """
    return (
        RATCHET_AAD_PREFIX
        + struct.pack("<I", frame_index)
        + struct.pack("<H", k_blocks)
        + struct.pack("<H", block_size)
        + struct.pack("<I", total_frames)
        + salt
    )


# ── Per-Frame Encryption/Decryption ─────────────────────────────────────────


def encrypt_frame(
    frame_data: bytes,
    message_key: bytes,
    frame_index: int,
    salt: bytes,
    k_blocks: int,
    block_size: int,
    total_frames: int,
) -> bytes:
    """
    Encrypt a single frame (droplet) using ratcheted keys.

    Output format:
        frame_index(4 BE) || AES-GCM-ciphertext(len(frame_data) + 16)

    The frame_index is transmitted in plaintext (needed for key derivation
    by the decoder). It is authenticated via AES-GCM AAD.

    Args:
        frame_data: Raw droplet bytes to encrypt
        message_key: 32-byte message key from ratchet_step()
        frame_index: 0-based frame index
        salt: 16-byte session salt
        k_blocks: Fountain source block count
        block_size: Fountain block size
        total_frames: Total frame count

    Returns:
        Encrypted frame bytes (frame_index || ciphertext || tag)

    Security:
        - Each frame uses a unique key+nonce pair (from domain-separated HKDF)
        - AAD binds frame_index, salt, and encoding parameters
        - AES-GCM provides authenticated encryption (confidentiality + integrity)
        - All subkeys are zeroized after encryption
    """
    from .crypto_backend import get_default_backend

    backend = get_default_backend()

    # Derive per-frame subkeys
    keys = derive_frame_keys(message_key, salt)

    # Build AAD
    aad = build_frame_aad(frame_index, salt, k_blocks, block_size, total_frames)

    try:
        # Encrypt with AES-256-GCM
        ciphertext = backend.aes_gcm_encrypt(
            key=bytes(keys.enc_key),
            nonce=bytes(keys.nonce),
            plaintext=frame_data,
            aad=aad,
        )

        # Pack: frame_index(4 BE) || ciphertext (includes 16-byte GCM tag)
        return struct.pack(">I", frame_index) + ciphertext

    finally:
        # CRITICAL: Zeroize all subkeys regardless of success/failure
        keys.zeroize()


def decrypt_frame(
    encrypted_frame: bytes,
    message_key: bytes,
    expected_index: int,
    salt: bytes,
    k_blocks: int,
    block_size: int,
    total_frames: int,
) -> bytes:
    """
    Decrypt a single ratchet-encrypted frame.

    Args:
        encrypted_frame: Frame bytes (frame_index || ciphertext || tag)
        message_key: 32-byte message key for this frame's ratchet position
        expected_index: Expected frame index (for validation)
        salt: 16-byte session salt
        k_blocks: Fountain source block count
        block_size: Fountain block size
        total_frames: Total frame count

    Returns:
        Decrypted frame data (raw droplet bytes)

    Raises:
        ValueError: If frame_index doesn't match expected, or GCM auth fails

    Security:
        - Frame index is validated against expected_index
        - AES-GCM authentication prevents tampering
        - All subkeys are zeroized after decryption
    """
    from .crypto_backend import get_default_backend

    backend = get_default_backend()

    if len(encrypted_frame) < FRAME_INDEX_SIZE + GCM_TAG_SIZE:
        raise ValueError(
            f"Encrypted frame too short: {len(encrypted_frame)} bytes "
            f"(minimum {FRAME_INDEX_SIZE + GCM_TAG_SIZE})"
        )

    # Parse frame index from header
    frame_index = struct.unpack(">I", encrypted_frame[:FRAME_INDEX_SIZE])[0]

    if frame_index != expected_index:
        raise ValueError(f"Frame index mismatch: got {frame_index}, expected {expected_index}")

    ciphertext = encrypted_frame[FRAME_INDEX_SIZE:]

    # Derive per-frame subkeys
    keys = derive_frame_keys(message_key, salt)

    # Build AAD (must match encoder's AAD exactly)
    aad = build_frame_aad(frame_index, salt, k_blocks, block_size, total_frames)

    try:
        # Decrypt with AES-256-GCM (authenticates ciphertext + AAD)
        plaintext = backend.aes_gcm_decrypt(
            key=bytes(keys.enc_key),
            nonce=bytes(keys.nonce),
            ciphertext=ciphertext,
            aad=aad,
        )
        return plaintext

    finally:
        # CRITICAL: Zeroize all subkeys regardless of success/failure
        keys.zeroize()


# ── Encoder Ratchet ──────────────────────────────────────────────────────────


class EncoderRatchet:
    """
    Ratchet state machine for the encoder (frame generator).

    State machine:
        INIT ──(first frame)──► ENCODING ──(all frames done)──► FINALIZED
                                    │                               │
                                    └── frame i encrypted ──────────┘
                                        chain_key[i] zeroized

    Usage:
        ratchet = EncoderRatchet(root_key, salt, k_blocks, block_size, total_frames)
        for i in range(total_frames):
            encrypted = ratchet.encrypt_next(frame_data[i])
        ratchet.finalize()  # Zeroizes all remaining state
    """

    def __init__(
        self,
        root_key: bytes,
        salt: bytes,
        k_blocks: int,
        block_size: int,
        total_frames: int,
        rekey_interval: int = 0,
        receiver_public_key: Optional[bytes] = None,
    ):
        """
        Initialize encoder ratchet.

        Args:
            root_key: 32-byte root key (from main key derivation)
            salt: 16-byte session salt
            k_blocks: Number of fountain source blocks
            block_size: Fountain block size in bytes
            total_frames: Total number of frames to encrypt
            rekey_interval: Frames between rekey beacons (0 = disabled)
            receiver_public_key: X25519 public key for KEM beacons (optional)
        """
        self._state = init_ratchet(root_key, salt)
        self._salt = salt
        self._k_blocks = k_blocks
        self._block_size = block_size
        self._total_frames = total_frames
        self._frames_encrypted = 0
        self._finalized = False
        self._rekey_interval = rekey_interval
        self._receiver_public_key = receiver_public_key

    def _is_rekey_frame(self, frame_index: int) -> bool:
        """Check if this frame index is a rekey beacon point."""
        return (
            self._rekey_interval > 0 and frame_index > 0 and frame_index % self._rekey_interval == 0
        )

    @property
    def position(self) -> int:
        """Current ratchet position (number of frames encrypted so far)."""
        return self._frames_encrypted

    def encrypt_next(self, frame_data: bytes) -> bytes:
        """
        Encrypt the next frame in sequence using the ratchet.

        Args:
            frame_data: Raw frame data (manifest or droplet bytes)

        Returns:
            Encrypted frame bytes

        Raises:
            RuntimeError: If ratchet is finalized or all frames already encrypted
        """
        if self._finalized:
            raise RuntimeError("Encoder ratchet is finalized — no more frames")
        if self._frames_encrypted >= self._total_frames:
            raise RuntimeError(f"All {self._total_frames} frames already encrypted")

        frame_index = self._frames_encrypted

        # Ratchet step: derive message key, advance chain
        message_key_bytes, self._state = ratchet_step(self._state)
        message_key_buf = bytearray(message_key_bytes)

        # Rekey beacon: inject fresh entropy at periodic intervals
        beacon_header = b""
        if self._is_rekey_frame(frame_index):
            if self._receiver_public_key is not None:
                # KEM beacon: attacker needs receiver_private_key to recover
                beacon_secret, eph_pub = _generate_kem_beacon(self._receiver_public_key)
                beacon_header = eph_pub
            else:
                # Plaintext beacon: protects against memory-only compromise
                beacon_secret = os.urandom(REKEY_BEACON_SIZE)
                beacon_header = beacon_secret
            enhanced_key = _mix_beacon(bytes(message_key_buf), beacon_secret, self._salt)
            _secure_zero(message_key_buf)
            message_key_buf = bytearray(enhanced_key)

        try:
            # Encrypt frame with (potentially beacon-enhanced) key
            encrypted = encrypt_frame(
                frame_data=frame_data,
                message_key=bytes(message_key_buf),
                frame_index=frame_index,
                salt=self._salt,
                k_blocks=self._k_blocks,
                block_size=self._block_size,
                total_frames=self._total_frames,
            )

            # Insert beacon after frame_index header if present
            if beacon_header:
                encrypted = (
                    encrypted[:FRAME_INDEX_SIZE] + beacon_header + encrypted[FRAME_INDEX_SIZE:]
                )

            self._frames_encrypted += 1
            return encrypted
        finally:
            # Zeroize message key
            _secure_zero(message_key_buf)

    def finalize(self) -> None:
        """
        Finalize the ratchet, zeroizing all remaining state.

        Must be called when encoding is complete (or on error cleanup).
        After finalize(), no more frames can be encrypted.
        """
        if not self._finalized:
            self._state.zeroize()
            self._finalized = True

    def __del__(self):
        """Safety net: ensure keys are zeroized on garbage collection."""
        if not self._finalized:
            try:
                self.finalize()
            except Exception:
                pass


# ── Decoder Ratchet ──────────────────────────────────────────────────────────


class DecoderRatchet:
    """
    Ratchet state machine for the decoder (frame receiver).

    Handles out-of-order frame reception for fountain code compatibility:
    - Frames arriving in order: chain advances naturally
    - Frames arriving out of order: chain fast-forwards, caching skipped keys
    - Previously skipped keys are consumed from cache

    State machine:
        INIT ──(first frame)──► DECODING ──(complete)──► FINALIZED
                                    │                        │
                                    ├── frame i < pos: use cache
                                    ├── frame i == pos: use current
                                    └── frame i > pos: fast-forward, cache skipped

    Bounded key cache (MAX_SKIP_KEYS) prevents DoS from adversarial
    frame index inflation.

    Usage:
        ratchet = DecoderRatchet(root_key, salt, k_blocks, block_size, total_frames)
        for frame in received_frames:
            data = ratchet.decrypt(frame)
        ratchet.finalize()
    """

    def __init__(
        self,
        root_key: bytes,
        salt: bytes,
        k_blocks: int,
        block_size: int,
        total_frames: int,
        rekey_interval: int = 0,
        receiver_private_key: Optional[bytes] = None,
    ):
        """
        Initialize decoder ratchet.

        Args:
            root_key: 32-byte root key (same derivation as encoder)
            salt: 16-byte session salt
            k_blocks: Number of fountain source blocks
            block_size: Fountain block size in bytes
            total_frames: Total number of expected frames
            rekey_interval: Frames between rekey beacons (0 = disabled)
            receiver_private_key: X25519 private key for KEM beacons (optional)
        """
        self._state = init_ratchet(root_key, salt)
        self._salt = salt
        self._k_blocks = k_blocks
        self._block_size = block_size
        self._total_frames = total_frames
        self._skipped_keys: Dict[int, bytearray] = {}  # frame_index → message_key
        self._consumed_indices: set = set()  # Track consumed frame indices
        self._finalized = False
        self._rekey_interval = rekey_interval
        self._receiver_private_key = receiver_private_key

    def _is_rekey_frame(self, frame_index: int) -> bool:
        """Check if this frame index is a rekey beacon point."""
        return (
            self._rekey_interval > 0 and frame_index > 0 and frame_index % self._rekey_interval == 0
        )

    @property
    def position(self) -> int:
        """Current chain position (next frame index to derive from chain)."""
        return self._state.position

    def _advance_to(self, target_index: int) -> bytes:
        """
        Advance the chain to target_index, caching skipped message keys.

        Args:
            target_index: The frame index we need to derive a key for

        Returns:
            message_key for target_index

        Raises:
            ValueError: If too many keys would need to be cached (DoS protection)
        """
        skip_count = target_index - self._state.position
        if skip_count < 0:
            raise ValueError(
                f"Cannot reverse ratchet: current={self._state.position}, " f"target={target_index}"
            )

        if len(self._skipped_keys) + skip_count > MAX_SKIP_KEYS:
            raise ValueError(
                f"Too many skipped keys ({len(self._skipped_keys) + skip_count} > "
                f"{MAX_SKIP_KEYS}). Possible DoS attack via frame index inflation."
            )

        # Fast-forward, caching each skipped message key
        for _ in range(skip_count):
            msg_key, self._state = ratchet_step(self._state)
            # Cache the skipped key for later out-of-order reception
            skipped_idx = self._state.position - 1
            self._skipped_keys[skipped_idx] = bytearray(msg_key)

        # Now derive the target message key
        msg_key, self._state = ratchet_step(self._state)
        return msg_key

    def decrypt(self, encrypted_frame: bytes) -> bytes:
        """
        Decrypt a ratchet-encrypted frame, handling out-of-order reception.

        Args:
            encrypted_frame: Encrypted frame bytes (frame_index || ciphertext || tag)

        Returns:
            Decrypted frame data (raw droplet bytes)

        Raises:
            ValueError: On authentication failure, index out of range, or replay
            RuntimeError: If ratchet is finalized
        """
        if self._finalized:
            raise RuntimeError("Decoder ratchet is finalized — no more frames")

        if len(encrypted_frame) < FRAME_INDEX_SIZE:
            raise ValueError(f"Frame too short: {len(encrypted_frame)} bytes")

        # Parse frame index from header
        frame_index = struct.unpack(">I", encrypted_frame[:FRAME_INDEX_SIZE])[0]

        # Replay detection
        if frame_index in self._consumed_indices:
            raise ValueError(f"Replay detected: frame {frame_index} already consumed")

        if frame_index >= self._total_frames:
            raise ValueError(f"Frame index {frame_index} exceeds total frames {self._total_frames}")

        # Get the message key for this frame
        message_key_buf: Optional[bytearray] = None

        try:
            if frame_index in self._skipped_keys:
                # Case 1: This frame was skipped earlier — use cached key
                message_key_buf = self._skipped_keys.pop(frame_index)
            elif frame_index >= self._state.position:
                # Case 2: Frame is at or ahead of current position — advance chain
                msg_key = self._advance_to(frame_index)
                message_key_buf = bytearray(msg_key)
            else:
                # Case 3: Frame is behind current position and NOT in cache
                # This means we already advanced past it without caching.
                # This should not happen if the decoder processes frames correctly.
                raise ValueError(
                    f"Frame {frame_index} is behind chain position "
                    f"{self._state.position} and not in skip cache. "
                    f"Key is irrecoverable (forward secrecy)."
                )

            # Handle rekey beacon: extract beacon and enhance message key
            actual_frame = encrypted_frame
            if self._is_rekey_frame(frame_index):
                if len(encrypted_frame) < FRAME_INDEX_SIZE + REKEY_BEACON_SIZE + GCM_TAG_SIZE:
                    raise ValueError(f"Beacon frame too short: {len(encrypted_frame)} bytes")
                beacon_data = encrypted_frame[
                    FRAME_INDEX_SIZE : FRAME_INDEX_SIZE + REKEY_BEACON_SIZE
                ]
                # Reconstruct frame without beacon for decrypt_frame
                actual_frame = (
                    encrypted_frame[:FRAME_INDEX_SIZE]
                    + encrypted_frame[FRAME_INDEX_SIZE + REKEY_BEACON_SIZE :]
                )
                # Derive beacon secret
                if self._receiver_private_key is not None:
                    beacon_secret = _recover_kem_beacon(beacon_data, self._receiver_private_key)
                else:
                    beacon_secret = beacon_data
                # Mix beacon into message key
                enhanced_key = _mix_beacon(bytes(message_key_buf), beacon_secret, self._salt)
                _secure_zero(message_key_buf)
                message_key_buf = bytearray(enhanced_key)

            # Decrypt the frame
            plaintext = decrypt_frame(
                encrypted_frame=actual_frame,
                message_key=bytes(message_key_buf),
                expected_index=frame_index,
                salt=self._salt,
                k_blocks=self._k_blocks,
                block_size=self._block_size,
                total_frames=self._total_frames,
            )

            # Mark as consumed (replay prevention)
            self._consumed_indices.add(frame_index)
            return plaintext

        finally:
            # Zeroize the message key after use
            if message_key_buf is not None:
                _secure_zero(message_key_buf)

    def finalize(self) -> None:
        """
        Finalize the ratchet, zeroizing all remaining state.

        Zeroizes:
        - Current chain key
        - All cached skipped message keys
        """
        if not self._finalized:
            self._state.zeroize()
            for idx, key_buf in self._skipped_keys.items():
                _secure_zero(key_buf)
            self._skipped_keys.clear()
            self._consumed_indices.clear()
            self._finalized = True

    def __del__(self):
        """Safety net: ensure keys are zeroized on garbage collection."""
        if not self._finalized:
            try:
                self.finalize()
            except Exception:
                pass


# ── Key Deletion Report ──────────────────────────────────────────────────────


@dataclass
class KeyDeletionReport:
    """
    Tracks key lifecycle events for audit logging.

    Each entry records when a key was derived and when it was zeroized.
    This is NOT used in production — it's for testing and verification only.
    """

    events: List[dict] = field(default_factory=list)

    def record_derive(self, key_type: str, index: int) -> None:
        """Record a key derivation event."""
        self.events.append(
            {
                "action": "derive",
                "key_type": key_type,
                "index": index,
            }
        )

    def record_zeroize(self, key_type: str, index: int) -> None:
        """Record a key zeroization event."""
        self.events.append(
            {
                "action": "zeroize",
                "key_type": key_type,
                "index": index,
            }
        )

    def verify_all_zeroized(self) -> bool:
        """Verify that every derived key was eventually zeroized."""
        derived = set()
        zeroized = set()
        for event in self.events:
            key_id = (event["key_type"], event["index"])
            if event["action"] == "derive":
                derived.add(key_id)
            elif event["action"] == "zeroize":
                zeroized.add(key_id)
        return derived == zeroized


# ── Tasteful Meow API Layer ─────────────────────────────────────────────────
# Cat-themed public aliases for the wrapper/demo layer.
# Core crypto internals remain serious. The edge gets the cat. 🐱

# Type aliases
PawState = RatchetState
WhiskerKeys = FrameKeys

# Function aliases
bury_in_litter = _secure_zero
knead_subkey = derive_frame_keys


def prime_cat(password_key: bytes, salt: bytes) -> "PawState":
    """Initialize a ratchet from the Prime Cat (root key).

    This is the tasteful meow alias for init_ratchet().
    Use this at the wrapper/demo layer. Core crypto uses init_ratchet().
    """
    return init_ratchet(password_key, salt)
