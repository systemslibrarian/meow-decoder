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
    ┌──────────────────────┬─────────────────┬────────────────────────┐
    │ Property             │ Signal          │ MEOW (MSR v1.2)        │
    ├──────────────────────┼─────────────────┼────────────────────────┤
    │ Symmetric ratchet    │ ✓ per-message   │ ✓ per-frame            │
    │ DH ratchet           │ ✓ per-reply     │ ✗ (unidirectional)     │
    │ Forward secrecy      │ ✓ per-message   │ ✓ per-frame            │
    │ Post-compromise sec. │ ✓ (via DH)      │ ⚡ KEM rekey beacons   │
    │ Out-of-order support │ Bounded window  │ Full (fountain)        │
    │ Key zeroization      │ ✓               │ ✓                      │
    │ Header encryption    │ ✓               │ ✓ (HKDF-XOR mask)      │
    │ Key commitment       │ Implicit (HMAC) │ ✓ (HMAC-SHA256 tag)    │
    │ AEAD                 │ CBC + HMAC      │ AES-256-GCM + commit   │
    └──────────────────────┴─────────────────┴────────────────────────┘

See docs/RATCHET_PROTOCOL.md for formal specification.
"""

import os
import struct
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .crypto_backend import get_default_backend

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

# ── Header Encryption Constants (Signal parity) ─────────────────────────────
# Signal encrypts message headers to prevent traffic analysis.
# MEOW encrypts frame indices with HKDF-derived XOR masks so observers
# cannot determine frame ordering, count consumed frames, or correlate
# frames across sessions.
HEADER_ENC_INFO = b"meow_ratchet_header_v1"
HEADER_MASK_INFO = b"meow_header_mask_v1"

# ── Asymmetric Entropy Reinjection Constants (MSR v2.0) ─────────────────────
# Signal-grade post-compromise security via periodic X25519 root key rotation.
# Every rekey_interval frames, the sender generates a fresh X25519 keypair,
# performs ECDH with the receiver's long-term public key, and rotates the root
# key.  Compromise of chain_key[N] CANNOT yield keys after the next rekey,
# because the new root depends on an ECDH shared secret that requires the
# receiver's long-term private key (NOT present in the ratchet state).
#
# State machine:
#   root_key[e] ─── HKDF(ECDH(eph[e+1], receiver), salt=root_key[e]) ──► root_key[e+1]
#                                                                              │
#               HKDF(root_key[e+1], salt, ASYM_REKEY_CHAIN_INFO)               │
#                                                                              ▼
#                                                                        chain_key[e+1][0]
#
# Comparison with MSR v1.2 KEM beacons:
#   v1.2: beacon entropy mixed into individual message_key (no root rotation)
#   v2.0: ECDH entropy rotates root_key, deriving entirely new chain
#   v2.0 strictly dominates v1.2 for PCS when receiver_public_key is available.

ASYM_REKEY_ROOT_INFO = b"meow_asym_rekey_root_v1"
ASYM_REKEY_CHAIN_INFO = b"meow_asym_rekey_chain_v1"
ASYM_REKEY_KEM_INFO = b"meow_asym_rekey_kem_v1"
ASYM_REKEY_ROOT_INIT_INFO = b"meow_ratchet_root_store_v1"

# ── Key Commitment Constants ────────────────────────────────────────────────
# AES-GCM is NOT key-committing: an adversary can find two different keys
# that both successfully decrypt the same ciphertext to different plaintexts
# ("invisible salamanders" attack, Grubbs et al. 2017).
# Fix: Append HMAC-SHA256(mac_key, frame_body) to each frame. Since mac_key
# is deterministically derived from message_key, a valid commitment tag
# proves the decryptor holds the ONLY key that could have produced it.
COMMIT_TAG_SIZE = 16  # Truncated HMAC-SHA256 (128-bit collision resistance)


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
    backend = get_default_backend()
    return backend.derive_key_hkdf(key_material, salt, info, length)


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
    backend = get_default_backend()
    ephemeral_private_bytes, ephemeral_public_bytes = backend.x25519_generate_keypair()

    raw_shared = backend.x25519_exchange(ephemeral_private_bytes, receiver_public_key)

    shared_secret = _hkdf_derive(raw_shared, b"", REKEY_BEACON_KEM_INFO, 32)

    return shared_secret, ephemeral_public_bytes


def _recover_kem_beacon(ephemeral_public_bytes: bytes, receiver_private_key: bytes) -> bytes:
    """Recover shared secret from X25519 KEM rekey beacon.

    Args:
        ephemeral_public_bytes: 32-byte ephemeral public key from frame header
        receiver_private_key: Receiver's X25519 private key

    Returns:
        32-byte shared secret to mix into message key
    """
    backend = get_default_backend()
    raw_shared = backend.x25519_exchange(receiver_private_key, ephemeral_public_bytes)

    shared_secret = _hkdf_derive(raw_shared, b"", REKEY_BEACON_KEM_INFO, 32)
    return shared_secret


# ── Asymmetric Entropy Reinjection (MSR v2.0) ───────────────────────────────
#
# Signal-grade post-compromise security for unidirectional air-gap channels.
#
# Protocol:
#   At each rekey frame (every K frames), the sender:
#     1. Generates fresh ephemeral X25519 keypair
#     2. ECDH(ephemeral_private, receiver_public) → raw_shared
#     3. shared = HKDF(raw_shared, salt="", info=ASYM_REKEY_KEM_INFO)
#     4. new_root = HKDF(IKM=shared, salt=old_root, info=ASYM_REKEY_ROOT_INFO||epoch)
#     5. new_chain = HKDF(new_root, salt, ASYM_REKEY_CHAIN_INFO)
#     6. ZEROIZE(old_root, old_chain, ephemeral_private)
#     7. Continue ratchet_step() from new_chain
#     8. Embed ephemeral_public (32 bytes) in frame header
#
# Attack surface analysis:
#   Attacker compromises chain_key[N] and root_key[epoch_E]:
#     - Can derive ALL message keys from frame N to next rekey boundary
#     - At rekey: new_root = HKDF(ECDH_shared, salt=root_key[E])
#       Attacker has root_key[E] but NOT the ECDH shared secret
#       (requires receiver_private_key, which is NOT in ratchet state)
#     - Therefore: frames after rekey are UNRECOVERABLE by attacker
#
#   If attacker compromises state REPEATEDLY (between every rekey):
#     - Each compromise window is bounded to rekey_interval frames
#     - Each rekey creates an independent healing point
#     - With interval=32 and total=150: max 32 frames exposed per compromise
#
# Comparison with Signal Double Ratchet:
#   ┌─────────────────────┬───────────────────┬──────────────────────────┐
#   │ Property            │ Signal            │ MEOW (MSR v2.0)          │
#   ├─────────────────────┼───────────────────┼──────────────────────────┤
#   │ DH ratchet trigger  │ Per reply          │ Every K frames (config)  │
#   │ DH ratchet latency  │ 1 round-trip      │ K frames (unidirectional)│
#   │ PCS healing speed   │ Immediate (reply) │ ≤K frames               │
#   │ Root key rotation   │ ✓ per DH step     │ ✓ per rekey             │
#   │ Chain key isolation  │ ✓ per chain       │ ✓ per epoch             │
#   │ Air-gap compatible  │ ✗ (needs channel) │ ✓                       │
#   │ Passive observer    │ Cannot forge DH   │ Cannot forge DH         │
#   └─────────────────────┴───────────────────┴──────────────────────────┘
#
# The only property weaker than Signal is PCS healing latency: Signal heals
# on the next message from the other party (1 round-trip); MEOW heals at
# the next rekey boundary (≤K frames, unidirectional). This is inherent
# to unidirectional protocols and cannot be improved without a back-channel.


def _generate_asym_rekey(
    receiver_public_key: bytes,
) -> Tuple[bytes, bytes]:
    """Generate X25519 ephemeral keypair and ECDH for asymmetric root rekey.

    This is the sender-side operation: generate an ephemeral keypair,
    perform ECDH with the receiver's long-term public key, and return
    the shared secret + ephemeral public key for embedding in the frame.

    Args:
        receiver_public_key: Receiver's long-term X25519 public key (32 bytes)

    Returns:
        (shared_secret, ephemeral_public_bytes):
            shared_secret: 32-byte ECDH-derived secret for root rotation
            ephemeral_public_bytes: 32-byte ephemeral public key for frame header

    Security:
        - Ephemeral private key exists only in this function's scope
        - HKDF domain separation (ASYM_REKEY_KEM_INFO) prevents cross-use
        - shared_secret requires receiver_private_key to reconstruct
    """
    backend = get_default_backend()
    ephemeral_private_bytes, ephemeral_public_bytes = backend.x25519_generate_keypair()

    raw_shared = backend.x25519_exchange(ephemeral_private_bytes, receiver_public_key)

    # Domain-separated KDF — distinct from beacon KEM and FS derivation
    shared_secret = _hkdf_derive(raw_shared, b"", ASYM_REKEY_KEM_INFO, 32)

    # NOTE: ephemeral_private_bytes goes out of scope here and is not stored.
    # The Rust backend's zeroize crate handles the actual X25519 scalar cleanup.
    return shared_secret, ephemeral_public_bytes


def _recover_asym_rekey(
    ephemeral_public_bytes: bytes,
    receiver_private_key: bytes,
) -> bytes:
    """Recover ECDH shared secret for asymmetric root rekey (decoder side).

    Args:
        ephemeral_public_bytes: 32-byte ephemeral public key from frame header
        receiver_private_key: Receiver's long-term X25519 private key (32 bytes)

    Returns:
        32-byte ECDH-derived secret (must match sender's _generate_asym_rekey output)
    """
    backend = get_default_backend()
    raw_shared = backend.x25519_exchange(receiver_private_key, ephemeral_public_bytes)

    # Same domain separator as sender — MUST match _generate_asym_rekey
    shared_secret = _hkdf_derive(raw_shared, b"", ASYM_REKEY_KEM_INFO, 32)
    return shared_secret


def _asymmetric_root_rekey(
    root_key: bytes,
    shared_secret: bytes,
    salt: bytes,
    epoch: int,
) -> Tuple[bytes, bytes]:
    """Rotate root key with asymmetric entropy and derive new chain key.

    This is the core of Signal-grade post-compromise security:
        new_root  = HKDF(IKM=shared_secret, salt=old_root_key,
                         info=ASYM_REKEY_ROOT_INFO || epoch)
        new_chain = HKDF(new_root, salt, ASYM_REKEY_CHAIN_INFO)

    The new root requires BOTH:
        1. The old root key (which authenticated prior state)
        2. The ECDH shared secret (which requires receiver's private key)

    An attacker who has old_root but NOT receiver_private_key cannot
    compute the new root. This is the PCS guarantee.

    Args:
        root_key: Current root key (32 bytes, used as HKDF salt)
        shared_secret: ECDH-derived secret (32 bytes, used as HKDF IKM)
        salt: Session salt (16 bytes, used for chain derivation)
        epoch: Epoch counter (bound into info to prevent cross-epoch confusion)

    Returns:
        (new_root_key, new_chain_key): Both 32 bytes

    Security:
        - Epoch binding: info includes epoch counter, preventing replay of
          old ephemeral keys across epochs
        - One-way: HKDF(SHA-256) ensures old_root is irrecoverable from new_root
        - Domain separation: ASYM_REKEY_ROOT_INFO ≠ ASYM_REKEY_CHAIN_INFO
    """
    # Bind epoch into derivation to prevent cross-epoch attacks
    epoch_info = ASYM_REKEY_ROOT_INFO + struct.pack(">I", epoch)

    # Signal-style root rotation: HKDF(IKM=ECDH_shared, salt=old_root, info=...)
    new_root = _hkdf_derive(
        key_material=shared_secret,
        salt=root_key,
        info=epoch_info,
        length=32,
    )

    # Derive new chain from new root
    new_chain = _hkdf_derive(
        key_material=new_root,
        salt=salt,
        info=ASYM_REKEY_CHAIN_INFO,
        length=32,
    )

    return new_root, new_chain


# ── Header Encryption Helpers ────────────────────────────────────────────────


def _derive_header_key(root_key: bytes, salt: bytes) -> bytes:
    """Derive header encryption key for frame index obfuscation.

    The header key is used to XOR-mask frame indices in the output,
    preventing observers from determining frame ordering or performing
    traffic analysis on in-flight frames.

    This mirrors Signal's header encryption where message headers
    (containing chain position) are encrypted before transmission.
    """
    return _hkdf_derive(root_key, salt, HEADER_ENC_INFO, 32)


def _header_mask(header_key: bytes, frame_index: int) -> bytes:
    """Compute 4-byte XOR mask for a specific frame index.

    Each frame gets a unique pseudorandom mask derived from the header
    key and its index. The mask is applied as XOR to the frame index
    before transmission, making the encrypted index appear random.

    Args:
        header_key: 32-byte header encryption key
        frame_index: The plaintext frame index to mask

    Returns:
        4-byte XOR mask for this frame index
    """
    return _hkdf_derive(header_key, struct.pack(">I", frame_index), HEADER_MASK_INFO, 4)


def _encrypt_index(header_key: bytes, frame_index: int) -> bytes:
    """Encrypt a frame index for header encryption.

    Returns 4 bytes of pseudorandom data that hides the true frame index.
    The same header_key and frame_index always produce the same output
    (deterministic encryption).
    """
    mask = _header_mask(header_key, frame_index)
    plaintext = struct.pack(">I", frame_index)
    return bytes(a ^ b for a, b in zip(plaintext, mask))


def _build_header_lookup(header_key: bytes, total_frames: int) -> Dict[bytes, int]:
    """Precompute encrypted-index → real-index lookup table for decoder.

    Called once during decoder initialization. O(total_frames) HKDF calls,
    then O(1) lookup per received frame.

    Args:
        header_key: 32-byte header encryption key (same as encoder)
        total_frames: Total expected frame count

    Returns:
        Dict mapping encrypted 4-byte index → plaintext frame index
    """
    lookup: Dict[bytes, int] = {}
    for i in range(total_frames):
        enc_idx = _encrypt_index(header_key, i)
        lookup[enc_idx] = i
    return lookup


# ── Key Commitment Helpers ───────────────────────────────────────────────────


def _compute_commitment(mac_key: bytes, frame_body: bytes) -> bytes:
    """Compute key commitment tag over frame body.

    Prevents key commitment attacks ("invisible salamanders") where an
    adversary finds two different keys that both produce valid AES-GCM
    tags for the same ciphertext, but yield different plaintexts.

    The commitment is HMAC-SHA256(mac_key, frame_body) truncated to 16
    bytes. Since mac_key is deterministically derived from message_key
    via domain-separated HKDF, a valid commitment proves the decryptor
    holds the ONLY key that could have produced it.

    Args:
        mac_key: 32-byte MAC key from derive_frame_keys()
        frame_body: Frame body bytes (beacon + ciphertext, or just ciphertext)

    Returns:
        16-byte commitment tag (truncated HMAC-SHA256)
    """
    backend = get_default_backend()
    return backend.hmac_sha256(mac_key, frame_body)[:COMMIT_TAG_SIZE]


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

    MSR v2.0 additions:
        root_key: Stored for asymmetric rekey operations. When a rekey
                  occurs, HKDF(ECDH_shared, salt=root_key, info=...) produces
                  a new root_key and chain_key. This trades storing the root
                  (which an attacker with memory access could read) for
                  post-compromise security: after the next rekey, the attacker
                  loses access because the new root depends on an ECDH shared
                  secret requiring the receiver's long-term private key.
        epoch:    Tracks how many asymmetric rekeys have occurred. Bound into
                  the HKDF info to prevent cross-epoch confusion.
    """

    chain_key: bytearray  # 32 bytes: current chain key (mutable for zeroization)
    salt: bytes  # 16 bytes: session salt (immutable, from manifest)
    position: int = 0  # Current chain position (frame index)
    root_key: Optional[bytearray] = None  # 32 bytes: root key for asymmetric rekey (MSR v2.0)
    epoch: int = 0  # Current asymmetric rekey epoch (MSR v2.0)

    def zeroize(self) -> None:
        """Securely zero all keys. Call when ratchet is no longer needed."""
        _secure_zero(self.chain_key)
        if self.root_key is not None:
            _secure_zero(self.root_key)
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
        - chain_key[0] is cryptographically independent of root_key's
          other derivations (encryption key, HMAC key, frame MAC key)
        - MSR v2.0: A domain-separated ratchet_root is stored for future
          asymmetric rekey operations. This enables post-compromise security
          at the cost of keeping root material in memory during the session.
          The trade-off is net-positive: without storing the root, there is
          NO post-compromise security at all.
    """
    chain_key_0 = _hkdf_derive(root_key, salt, RATCHET_ROOT_INFO, 32)
    # MSR v2.0: Derive a separate ratchet root for asymmetric rekey operations.
    # Domain-separated from chain_key_0 so compromise of one ≠ compromise of other.
    ratchet_root = _hkdf_derive(root_key, salt, ASYM_REKEY_ROOT_INIT_INFO, 32)
    return RatchetState(
        chain_key=bytearray(chain_key_0),
        salt=salt,
        position=0,
        root_key=bytearray(ratchet_root),
        epoch=0,
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
    # MSR v2.0: Preserve root_key and epoch across ratchet steps
    new_state = RatchetState(
        chain_key=bytearray(next_chain_key),
        salt=state.salt,
        position=state.position + 1,
        root_key=state.root_key,  # Shared reference (old state is consumed)
        epoch=state.epoch,
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
        # Header encryption key (Signal parity: encrypted message headers)
        self._header_key = _derive_header_key(root_key, salt)

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

        Output format (MSR v1.2 hardened):
            [encrypted_index(4)] [commitment_tag(16)] [beacon?(32)] [ciphertext + GCM_TAG(16)]

        Security properties:
            - Header encryption: Frame index is XOR-masked with HKDF-derived
              pseudorandom mask (prevents traffic analysis)
            - Key commitment: HMAC-SHA256(mac_key, body) prevents invisible
              salamanders attack on AES-GCM
            - Beacon support: Optional KEM/plaintext entropy injection

        Args:
            frame_data: Raw frame data (manifest or droplet bytes)

        Returns:
            Encrypted frame bytes with header encryption + key commitment

        Raises:
            RuntimeError: If ratchet is finalized or all frames already encrypted
        """
        if self._finalized:
            raise RuntimeError("Encoder ratchet is finalized — no more frames")
        if self._frames_encrypted >= self._total_frames:
            raise RuntimeError(f"All {self._total_frames} frames already encrypted")

        frame_index = self._frames_encrypted

        # ─── MSR v2.0: Asymmetric root key rotation (before ratchet step) ───
        # When receiver_public_key is available, perform Signal-style root
        # rotation at rekey boundaries. This provides post-compromise security:
        # compromise of chain_key[N] cannot yield keys after the next rekey.
        beacon_header = b""
        if self._is_rekey_frame(frame_index) and self._receiver_public_key is not None:
            # Generate fresh X25519 ephemeral, ECDH with receiver → shared_secret
            shared_secret, eph_pub = _generate_asym_rekey(self._receiver_public_key)
            beacon_header = eph_pub  # 32 bytes in header (same size as v1.2 beacon)

            # Rotate root key with asymmetric entropy (epoch binding prevents replay)
            self._state.epoch += 1
            new_root, new_chain = _asymmetric_root_rekey(
                root_key=bytes(self._state.root_key),
                shared_secret=shared_secret,
                salt=self._salt,
                epoch=self._state.epoch,
            )

            # Zeroize old root + chain (forward secrecy within epoch)
            _secure_zero(self._state.root_key)
            _secure_zero(self._state.chain_key)

            # Install new root and chain — next ratchet_step derives from new chain
            self._state.root_key = bytearray(new_root)
            self._state.chain_key = bytearray(new_chain)

        # Ratchet step: derive message key from current chain
        # (may be the newly rotated chain if asymmetric rekey just occurred)
        message_key_bytes, self._state = ratchet_step(self._state)
        message_key_buf = bytearray(message_key_bytes)

        # Plaintext beacon fallback (no receiver key → no PCS, memory-only protection)
        if self._is_rekey_frame(frame_index) and self._receiver_public_key is None:
            beacon_secret = os.urandom(REKEY_BEACON_SIZE)
            beacon_header = beacon_secret
            enhanced_key = _mix_beacon(bytes(message_key_buf), beacon_secret, self._salt)
            _secure_zero(message_key_buf)
            message_key_buf = bytearray(enhanced_key)

        commit_keys = None
        try:
            # Derive commitment keys (mac_key for key commitment tag)
            commit_keys = derive_frame_keys(bytes(message_key_buf), self._salt)

            # Encrypt frame (produces [frame_index(4 BE)] [ciphertext+tag])
            encrypted = encrypt_frame(
                frame_data=frame_data,
                message_key=bytes(message_key_buf),
                frame_index=frame_index,
                salt=self._salt,
                k_blocks=self._k_blocks,
                block_size=self._block_size,
                total_frames=self._total_frames,
            )

            # Extract ciphertext (strip plaintext frame_index header)
            raw_ciphertext = encrypted[FRAME_INDEX_SIZE:]

            # Insert beacon before ciphertext if present
            if beacon_header:
                frame_body = beacon_header + raw_ciphertext
            else:
                frame_body = raw_ciphertext

            # Key commitment: HMAC(mac_key, frame_body) truncated to 16 bytes
            commitment = _compute_commitment(bytes(commit_keys.mac_key), frame_body)

            # Header encryption: mask the frame index
            enc_idx = _encrypt_index(self._header_key, frame_index)

            # Assemble hardened frame:
            # [encrypted_index(4)] [commitment(16)] [beacon?(32)] [ciphertext+tag]
            result = enc_idx + commitment + frame_body

            self._frames_encrypted += 1
            return result
        finally:
            # Zeroize all sensitive material
            _secure_zero(message_key_buf)
            if commit_keys is not None:
                commit_keys.zeroize()

    def finalize(self) -> None:
        """
        Finalize the ratchet, zeroizing all remaining state.

        Must be called when encoding is complete (or on error cleanup).
        After finalize(), no more frames can be encrypted.
        """
        if not self._finalized:
            self._state.zeroize()
            # Zeroize header key (best-effort for immutable bytes)
            self._header_key = b"\x00" * 32
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
        # MSR v2.0: Asymmetric rekey material storage for epoch advancement
        # Maps epoch_number → ephemeral_public_key (32 bytes) extracted from
        # rekey frames. Populated during decrypt() BEFORE _advance_to() so
        # the chain can cross epoch boundaries during fast-forward.
        self._received_rekey_material: Dict[int, bytes] = {}
        # Header encryption: precompute encrypted-index → real-index lookup
        self._header_key = _derive_header_key(root_key, salt)
        self._header_lookup = _build_header_lookup(self._header_key, total_frames)

    def _is_rekey_frame(self, frame_index: int) -> bool:
        """Check if this frame index is a rekey beacon point."""
        return (
            self._rekey_interval > 0 and frame_index > 0 and frame_index % self._rekey_interval == 0
        )

    def _frame_epoch(self, frame_index: int) -> int:
        """Determine which asymmetric rekey epoch a frame belongs to.

        Epoch 0: frames [0, rekey_interval)
        Epoch 1: frames [rekey_interval, 2*rekey_interval)
        ...
        """
        if self._rekey_interval <= 0:
            return 0
        return frame_index // self._rekey_interval

    def _execute_rekey(self, epoch: int) -> None:
        """Execute asymmetric root key rotation for the given epoch.

        Consumes the stored ephemeral public key for this epoch,
        performs ECDH with the receiver's private key, and rotates
        the root key + chain key.

        Args:
            epoch: The epoch number to rotate into

        Security:
            - Shared secret requires receiver_private_key (NOT in ratchet state)
            - Old root + chain are zeroized (forward secrecy)
            - Epoch is bound into HKDF info (prevents cross-epoch replay)
        """
        eph_pub = self._received_rekey_material.pop(epoch)
        shared_secret = _recover_asym_rekey(eph_pub, self._receiver_private_key)

        new_root, new_chain = _asymmetric_root_rekey(
            root_key=bytes(self._state.root_key),
            shared_secret=shared_secret,
            salt=self._salt,
            epoch=epoch,
        )

        # Zeroize old keys
        _secure_zero(self._state.root_key)
        _secure_zero(self._state.chain_key)

        # Install new root and chain
        self._state.root_key = bytearray(new_root)
        self._state.chain_key = bytearray(new_chain)
        self._state.epoch = epoch

    @property
    def position(self) -> int:
        """Current chain position (next frame index to derive from chain)."""
        return self._state.position

    def _advance_to(self, target_index: int) -> bytes:
        """
        Advance the chain to target_index, caching skipped message keys.

        MSR v2.0: Handles asymmetric root key rotation at epoch boundaries.
        When the chain crosses a rekey frame during fast-forward, the root
        key is rotated using stored ephemeral key material (from a previously
        received rekey frame). If the rekey material for an intermediate epoch
        hasn't been received yet, ValueError is raised (the frame is treated
        as lost by fountain codes).

        Args:
            target_index: The frame index we need to derive a key for

        Returns:
            message_key for target_index

        Raises:
            ValueError: If too many keys would need to be cached (DoS protection)
                        or if rekey material for an intermediate epoch is missing
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

        # Fast-forward through positions, handling asymmetric rekeys at boundaries
        while self._state.position < target_index:
            current_pos = self._state.position

            # MSR v2.0: Check for asymmetric rekey at this position
            if (
                self._is_rekey_frame(current_pos)
                and self._receiver_private_key is not None
                and self._state.root_key is not None
            ):
                epoch = self._frame_epoch(current_pos)
                if epoch not in self._received_rekey_material:
                    raise ValueError(
                        f"Cannot advance past rekey boundary at frame {current_pos}: "
                        f"rekey material for epoch {epoch} not yet received. "
                        f"Frame will be recoverable after the rekey frame arrives."
                    )
                self._execute_rekey(epoch)

            msg_key, self._state = ratchet_step(self._state)
            # Cache the skipped key for later out-of-order reception
            skipped_idx = self._state.position - 1
            self._skipped_keys[skipped_idx] = bytearray(msg_key)

        # Handle rekey at the target position itself
        if (
            self._is_rekey_frame(target_index)
            and self._receiver_private_key is not None
            and self._state.root_key is not None
        ):
            epoch = self._frame_epoch(target_index)
            if epoch not in self._received_rekey_material:
                raise ValueError(
                    f"Cannot derive key at rekey frame {target_index}: "
                    f"rekey material for epoch {epoch} not yet received."
                )
            self._execute_rekey(epoch)

        # Final ratchet step for the target position
        msg_key, self._state = ratchet_step(self._state)
        return msg_key

    def decrypt(self, encrypted_frame: bytes) -> bytes:
        """
        Decrypt a hardened ratchet-encrypted frame with header decryption
        and key commitment verification.

        Input format (MSR v1.2):
            [encrypted_index(4)] [commitment_tag(16)] [beacon?(32)] [ciphertext + GCM_TAG(16)]

        Verification order (fail-closed):
            1. Header decryption: Look up encrypted index in precomputed table
            2. Replay detection: Reject already-consumed frame indices
            3. Ratchet key derivation: Get message key for this position
            4. Beacon mixing: If rekey frame, extract and mix beacon entropy
            5. Key commitment: HMAC(mac_key, frame_body) must match commitment tag
            6. AES-GCM decryption: Decrypt ciphertext with authenticated AAD

        Args:
            encrypted_frame: Encrypted frame bytes (hardened format)

        Returns:
            Decrypted frame data (raw droplet bytes)

        Raises:
            ValueError: On authentication failure, index out of range, replay,
                       or key commitment verification failure
            RuntimeError: If ratchet is finalized
        """
        if self._finalized:
            raise RuntimeError("Decoder ratchet is finalized — no more frames")

        min_frame_size = FRAME_INDEX_SIZE + COMMIT_TAG_SIZE + GCM_TAG_SIZE
        if len(encrypted_frame) < min_frame_size:
            raise ValueError(
                f"Frame too short: {len(encrypted_frame)} bytes " f"(minimum {min_frame_size})"
            )

        # Step 1: Header decryption — look up encrypted index
        enc_idx = encrypted_frame[:FRAME_INDEX_SIZE]
        if enc_idx not in self._header_lookup:
            raise ValueError(
                "Header decryption failed: unknown encrypted frame index. "
                "Frame may be corrupted or from a different session."
            )
        frame_index = self._header_lookup[enc_idx]

        # Step 2: Extract commitment tag
        commitment_tag = encrypted_frame[FRAME_INDEX_SIZE : FRAME_INDEX_SIZE + COMMIT_TAG_SIZE]

        # Frame body = everything after index + commitment
        frame_body = encrypted_frame[FRAME_INDEX_SIZE + COMMIT_TAG_SIZE :]

        # Step 3: Replay detection
        if frame_index in self._consumed_indices:
            raise ValueError(f"Replay detected: frame {frame_index} already consumed")

        if frame_index >= self._total_frames:
            raise ValueError(f"Frame index {frame_index} exceeds total frames {self._total_frames}")

        # MSR v2.0: Determine rekey mode for this frame
        # Asymmetric rekey: receiver_private_key + root_key available → root rotation
        # Plaintext beacon: no receiver key → mix random entropy into message key
        is_asym_rekey = (
            self._is_rekey_frame(frame_index)
            and self._receiver_private_key is not None
            and self._state.root_key is not None
        )

        # CRITICAL: For asymmetric rekey frames, extract and store the ephemeral
        # key BEFORE _advance_to(). This ensures the chain can cross the rekey
        # boundary during fast-forward. Without this, _advance_to() would fail
        # with "rekey material not yet received" when it hits the boundary.
        if is_asym_rekey:
            if len(frame_body) < REKEY_BEACON_SIZE + GCM_TAG_SIZE:
                raise ValueError(f"Asymmetric rekey frame body too short: {len(frame_body)} bytes")
            eph_pub = bytes(frame_body[:REKEY_BEACON_SIZE])
            epoch = self._frame_epoch(frame_index)
            self._received_rekey_material[epoch] = eph_pub

        # Get the message key for this frame
        message_key_buf: Optional[bytearray] = None
        commit_keys = None

        try:
            if frame_index in self._skipped_keys:
                # Case 1: This frame was skipped earlier — use cached key
                message_key_buf = self._skipped_keys.pop(frame_index)
            elif frame_index >= self._state.position:
                # Case 2: Frame is at or ahead of current position — advance chain
                # (may trigger asymmetric root rotation at epoch boundaries)
                msg_key = self._advance_to(frame_index)
                message_key_buf = bytearray(msg_key)
            else:
                # Case 3: Frame is behind current position and NOT in cache
                raise ValueError(
                    f"Frame {frame_index} is behind chain position "
                    f"{self._state.position} and not in skip cache. "
                    f"Key is irrecoverable (forward secrecy)."
                )

            # Step 4: Handle rekey frame body (strip beacon/rekey header)
            ciphertext_body = frame_body
            if self._is_rekey_frame(frame_index):
                if len(frame_body) < REKEY_BEACON_SIZE + GCM_TAG_SIZE:
                    raise ValueError(f"Beacon frame body too short: {len(frame_body)} bytes")
                ciphertext_body = frame_body[REKEY_BEACON_SIZE:]

                if not is_asym_rekey:
                    # Plaintext beacon fallback (MSR v1.x):
                    # Mix beacon entropy into message key
                    beacon_data = frame_body[:REKEY_BEACON_SIZE]
                    beacon_secret = beacon_data
                    enhanced_key = _mix_beacon(bytes(message_key_buf), beacon_secret, self._salt)
                    _secure_zero(message_key_buf)
                    message_key_buf = bytearray(enhanced_key)
                # For is_asym_rekey: root rotation was already performed during
                # _advance_to() → _execute_rekey(). The message key comes from
                # the post-rotation chain. No additional mixing needed.

            # Step 5: Key commitment verification (BEFORE decryption!)
            commit_keys = derive_frame_keys(bytes(message_key_buf), self._salt)
            expected_commitment = _compute_commitment(bytes(commit_keys.mac_key), frame_body)
            if not secrets.compare_digest(commitment_tag, expected_commitment):
                raise ValueError(
                    f"Key commitment verification failed for frame {frame_index}. "
                    "Possible key commitment attack or corrupted frame."
                )

            # Step 6: AES-GCM decryption
            # Reconstruct standard frame for decrypt_frame:
            # [plaintext_index(4 BE)] [ciphertext+tag]
            reconstructed = struct.pack(">I", frame_index) + ciphertext_body

            plaintext = decrypt_frame(
                encrypted_frame=reconstructed,
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
            # Zeroize all sensitive material
            if message_key_buf is not None:
                _secure_zero(message_key_buf)
            if commit_keys is not None:
                commit_keys.zeroize()

    def finalize(self) -> None:
        """
        Finalize the ratchet, zeroizing all remaining state.

        Zeroizes:
        - Current chain key and root key
        - All cached skipped message keys
        - Header encryption key
        - Header lookup table
        - Received rekey material (ephemeral public keys)
        """
        if not self._finalized:
            self._state.zeroize()
            for idx, key_buf in self._skipped_keys.items():
                _secure_zero(key_buf)
            self._skipped_keys.clear()
            self._consumed_indices.clear()
            self._received_rekey_material.clear()
            # Zeroize header key and lookup table
            self._header_key = b"\x00" * 32
            self._header_lookup.clear()
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
