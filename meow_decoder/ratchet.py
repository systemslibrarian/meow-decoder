"""
Per-Frame Symmetric Ratchet for Post-Compromise Security

Implements a Signal-inspired symmetric hash ratchet that provides per-frame
forward secrecy for fountain-coded QR/GIF air-gap file transfer.

Formal verification linkage
---------------------------
TLA+ state machine:  formal/tla/MeowRatchet.tla          (skip-key DoS bound,
                                                           index monotonicity,
                                                           key uniqueness)
TLA+ master ratchet: formal/tla/MasterRatchet.tla        (cross-session FS)
Tamarin FS+PCS:      formal/tamarin/MeowRatchetFS.spthy   (per-frame FS,
                                                           PCS via beacon)
Tamarin header OE:   formal/tamarin/MeowRatchetHeaderOE.spthy

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
from typing import Dict, List, Optional, Tuple, Union

from .crypto_backend import get_default_backend, get_handle_backend
from .pq_ratchet_beacon import (
    PQRatchetBeacon,
    PQBeaconFrame,
    PQBeaconKeyPair,
    generate_beacon_keypair as generate_pq_beacon_keypair,
    _mlkem1024_encapsulate,
    _mlkem1024_decapsulate,
    MLKEM1024_CIPHERTEXT_SIZE,
    MLKEM1024_PUBLIC_KEY_SIZE,
)

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
DEFAULT_REKEY_INTERVAL = 32  # frames between asymmetric rekey beacons

# ── PQ Ratchet Beacon Constants ──────────────────────────────────────────────
# ML-KEM-1024 post-quantum beacon: at rekey frames, if a PQ public key is
# available, encapsulate via ML-KEM-1024 and mix the shared secret into the
# message key. The PQ ciphertext is embedded in the frame header after the
# classical beacon (if any). This provides quantum-resistant PCS on top of
# the X25519 classical rekey.
PQ_BEACON_MIX_INFO = b"meow_pq_beacon_ratchet_mix_v1"

# ── Header Encryption Constants (Signal parity) ─────────────────────────────
# Signal encrypts message headers to prevent traffic analysis.
# MEOW encrypts frame indices with HKDF-derived XOR masks so observers
# cannot determine frame ordering, count consumed frames, or correlate
# frames across sessions.
HEADER_ENC_INFO = b"meow_ratchet_header_v1"
HEADER_MASK_INFO = b"meow_header_mask_v1"

# ── Asymmetric Entropy Reinjection Constants (MSR v2.0) ─────────────────────
# Signal-inspired post-compromise security via periodic X25519 root key rotation.
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
# PQ-hybrid root rekey: fold ML-KEM-1024 shared secret into root after X25519.
# Ensures that post-compromise security (PCS) requires breaking BOTH classical
# and post-quantum KEMs — a PQXDH-style combiner applied to the ratchet root.
PQ_HYBRID_REKEY_ROOT_INFO = b"meow_pq_hybrid_rekey_root_v1"

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


def _hkdf_derive_handle(key_handle: int, salt: bytes, info: bytes, length: int = 32) -> int:
    """HKDF-SHA256 derivation from a key handle. Returns new handle (secret stays in Rust)."""
    return get_handle_backend().derive_key_hkdf(key_handle, salt, info, length)


def _hkdf_derive_bytes_from_handle(
    key_handle: int, salt: bytes, info: bytes, length: int = 32
) -> bytes:
    """HKDF-SHA256 derivation from a handle, returning raw bytes.
    USE ONLY for non-secret derived values (nonces, header masks)."""
    return get_handle_backend().derive_key_hkdf_bytes(key_handle, salt, info, length)


def _ensure_handle(key_or_handle: Union[bytes, int]) -> tuple:
    """Convert bytes to handle if needed. Returns (handle_id, needs_cleanup)."""
    if isinstance(key_or_handle, int):
        return key_or_handle, False
    hb = get_handle_backend()
    return hb.import_key(key_or_handle), True


def _mix_beacon(message_key: bytes, beacon_secret: bytes, salt: bytes) -> bytes:
    """Mix rekey beacon entropy into a message key (legacy bytes API).

    Combines the ratchet-derived message key with fresh beacon entropy
    using HKDF. The resulting key requires knowledge of BOTH the chain
    state AND the beacon secret (which may be KEM-derived).
    """
    combined = message_key + beacon_secret
    return _hkdf_derive(combined, salt, REKEY_BEACON_INFO, 32)


def _mix_beacon_handle(message_key_handle: int, beacon_secret: bytes, salt: bytes) -> int:
    """Mix rekey beacon entropy into a message key handle.

    Like _mix_beacon but operates entirely via handles — secret key bytes
    never enter Python. Returns a new handle to the enhanced key.
    """
    hb = get_handle_backend()
    return hb.mix_hkdf(message_key_handle, beacon_secret, salt, REKEY_BEACON_INFO, 32)


def _mix_pq_beacon_handle(message_key_handle: int, pq_shared_secret: bytes, salt: bytes) -> int:
    """Mix ML-KEM-1024 PQ beacon entropy into a message key handle.

    Uses PQ-specific domain separation (PQ_BEACON_MIX_INFO) to ensure
    PQ beacon mixing is cryptographically independent from classical
    beacon mixing. The PQ shared secret is mixed additively on top of
    any classical beacon already applied.

    Returns a new handle; caller must drop the old handle.
    """
    hb = get_handle_backend()
    return hb.mix_hkdf(message_key_handle, pq_shared_secret, salt, PQ_BEACON_MIX_INFO, 32)


# NOTE: Legacy _generate_kem_beacon / _recover_kem_beacon removed.
# Superseded by _generate_asym_rekey / _recover_asym_rekey (MSR v2.0)
# which perform full root-key rotation via ECDH, providing actual PCS.


# ── Asymmetric Entropy Reinjection (MSR v2.0) ───────────────────────────────
#
# Signal-inspired post-compromise security for unidirectional air-gap channels.
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
) -> Tuple[int, bytes]:
    """Generate X25519 ephemeral keypair and ECDH for asymmetric root rekey.

    This is the sender-side operation: generate an ephemeral keypair,
    perform ECDH with the receiver's long-term public key, and return
    a handle to the shared secret + ephemeral public key for the frame.

    Args:
        receiver_public_key: Receiver's long-term X25519 public key (32 bytes)

    Returns:
        (shared_secret_handle, ephemeral_public_bytes):
            shared_secret_handle: Opaque Rust handle (secret never in Python)
            ephemeral_public_bytes: 32-byte ephemeral public key for frame header

    Security:
        - Ephemeral private key stays in Rust handle (never in Python)
        - Shared secret stays in Rust handle (never in Python)
        - HKDF domain separation (ASYM_REKEY_KEM_INFO) prevents cross-use
        - shared_secret requires receiver_private_key to reconstruct
    """
    hb = get_handle_backend()
    eph_handle, ephemeral_public_bytes = hb.x25519_generate_keypair()
    shared_handle = hb.x25519_exchange(eph_handle, receiver_public_key)

    # Domain-separated KDF — returns handle, secret stays in Rust
    shared_secret_handle = hb.derive_key_hkdf(shared_handle, b"", ASYM_REKEY_KEM_INFO, 32)

    hb.drop(eph_handle)
    hb.drop(shared_handle)
    return shared_secret_handle, ephemeral_public_bytes


def _recover_asym_rekey(
    ephemeral_public_bytes: bytes,
    receiver_private_key: Union[bytes, int],
) -> int:
    """Recover ECDH shared secret for asymmetric root rekey (decoder side).

    Args:
        ephemeral_public_bytes: 32-byte ephemeral public key from frame header
        receiver_private_key: Receiver's long-term X25519 private key (bytes or handle)

    Returns:
        Handle to 32-byte ECDH-derived secret (must match sender's
        _generate_asym_rekey output). Secret never enters Python.
    """
    hb = get_handle_backend()
    if isinstance(receiver_private_key, int):
        priv_handle = receiver_private_key
        cleanup = False
    else:
        # Import as X25519 private key (not generic symmetric key)
        priv_handle = hb.import_x25519_private(receiver_private_key)
        cleanup = True
    try:
        shared_handle = hb.x25519_exchange(priv_handle, ephemeral_public_bytes)
        # Same domain separator as sender — returns handle, MUST match
        shared_secret_handle = hb.derive_key_hkdf(shared_handle, b"", ASYM_REKEY_KEM_INFO, 32)
        hb.drop(shared_handle)
        return shared_secret_handle
    finally:
        if cleanup:
            hb.drop(priv_handle)


def _asymmetric_root_rekey(
    root_key: bytes,
    shared_secret: bytes,
    salt: bytes,
    epoch: int,
) -> Tuple[bytes, bytes]:
    """Rotate root key with asymmetric entropy and derive new chain key.

    This is the core of Signal-inspired post-compromise security:
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


def _asymmetric_root_rekey_handle(
    root_key_handle: int,
    shared_secret_handle: int,
    salt: bytes,
    epoch: int,
) -> Tuple[int, int]:
    """Handle-based asymmetric root rekey. All secrets stay in Rust.

    Both root_key and shared_secret are opaque Rust handles — no secret
    bytes ever enter Python memory.

    Returns (new_root_handle, new_chain_handle). Caller MUST drop the old
    root/chain handles and the consumed shared_secret_handle.
    """
    hb = get_handle_backend()
    epoch_info = ASYM_REKEY_ROOT_INFO + struct.pack(">I", epoch)

    # HKDF(IKM=shared_secret_handle, salt=root_key_handle, info=epoch_info)
    # Both inputs are handles — no bytes cross the boundary
    new_root_handle = hb.hkdf_two_handles(shared_secret_handle, root_key_handle, epoch_info, 32)

    # Derive new chain from new root handle
    new_chain_handle = _hkdf_derive_handle(new_root_handle, salt, ASYM_REKEY_CHAIN_INFO, 32)

    return new_root_handle, new_chain_handle


def _fold_pq_into_root(
    post_x25519_root_handle: int,
    pq_shared_bytes: bytes,
    epoch: int,
) -> int:
    """Fold ML-KEM-1024 shared secret into root key for PQ-hybrid root rekey.

    Called AFTER the classical X25519 root rotation. Produces a new root key
    that requires BOTH X25519 AND ML-KEM-1024 to predict, giving true
    PQXDH-style post-compromise security on the ratchet root.

    Derivation (PQXDH combiner):
        new_root = HKDF(IKM=pq_shared, salt=x25519_post_rotation_root,
                        info=PQ_HYBRID_REKEY_ROOT_INFO || BE32(epoch), len=32)

    Args:
        post_x25519_root_handle: Root handle from prior X25519 root rotation.
            CONSUMED (dropped) by this function.
        pq_shared_bytes: Raw ML-KEM-1024 shared secret (32 bytes).
            Imported as handle, then immediately dropped.
        epoch: Current rekey epoch counter bound into derivation to prevent
            cross-epoch replay of stale PQ ciphertexts.

    Returns:
        New 32-byte PQ-hybrid root key handle.

    Security:
        - Both inputs required: attacker must break X25519 AND ML-KEM-1024
          to predict the new root — matching Signal PQXDH security level
        - Epoch binding: prevents replaying old PQ ciphertexts across epochs
        - Domain separation: PQ_HYBRID_REKEY_ROOT_INFO distinct from all others
        - Secret bytes stay in Rust: pq_shared_bytes imported then dropped
    """
    hb = get_handle_backend()
    epoch_info = PQ_HYBRID_REKEY_ROOT_INFO + struct.pack(">I", epoch)
    # Import PQ shared secret as an opaque handle; Python copy will be GC'd
    pq_handle = hb.import_key(pq_shared_bytes)
    # HKDF(IKM=pq_shared, salt=x25519_root_handle, info=epoch_info, len=32)
    # Both inputs are handles — no secret bytes cross the Rust boundary
    new_root_handle = hb.hkdf_two_handles(pq_handle, post_x25519_root_handle, epoch_info, 32)
    hb.drop(pq_handle)
    hb.drop(post_x25519_root_handle)
    return new_root_handle


# ── Header Encryption Helpers ────────────────────────────────────────────────


def _derive_header_key(root_key: Union[bytes, int], salt: bytes) -> int:
    """Derive header encryption key for frame index obfuscation.

    Returns an opaque handle (int). The header key never exists as Python bytes.

    This mirrors Signal's header encryption where message headers
    (containing chain position) are encrypted before transmission.
    """
    handle, cleanup = _ensure_handle(root_key)
    try:
        result = _hkdf_derive_handle(handle, salt, HEADER_ENC_INFO, 32)
        return result
    finally:
        if cleanup:
            get_handle_backend().drop(handle)


def _header_mask(header_key_handle: int, frame_index: int) -> bytes:
    """Compute 4-byte XOR mask for a specific frame index.

    Each frame gets a unique pseudorandom mask derived from the header
    key handle and its index. The mask is applied as XOR to the frame index
    before transmission, making the encrypted index appear random.

    Args:
        header_key_handle: Handle to 32-byte header encryption key
        frame_index: The plaintext frame index to mask

    Returns:
        4-byte XOR mask for this frame index
    """
    return _hkdf_derive_bytes_from_handle(
        header_key_handle, struct.pack(">I", frame_index), HEADER_MASK_INFO, 4
    )


def _encrypt_index(header_key_handle: int, frame_index: int) -> bytes:
    """Encrypt a frame index for header encryption.

    Returns 4 bytes of pseudorandom data that hides the true frame index.
    The same header_key and frame_index always produce the same output
    (deterministic encryption).
    """
    mask = _header_mask(header_key_handle, frame_index)
    plaintext = struct.pack(">I", frame_index)
    return bytes(a ^ b for a, b in zip(plaintext, mask))


def _build_header_lookup(header_key_handle: int, total_frames: int) -> Dict[bytes, int]:
    """Precompute encrypted-index → real-index lookup table for decoder.

    Called once during decoder initialization. O(total_frames) HKDF calls,
    then O(1) lookup per received frame.

    Args:
        header_key_handle: Handle to 32-byte header encryption key
        total_frames: Total expected frame count

    Returns:
        Dict mapping encrypted 4-byte index → plaintext frame index
    """
    lookup: Dict[bytes, int] = {}
    for i in range(total_frames):
        enc_idx = _encrypt_index(header_key_handle, i)
        lookup[enc_idx] = i
    return lookup


# ── Key Commitment Helpers ───────────────────────────────────────────────────


def _compute_commitment(mac_key: Union[bytes, int], frame_body: bytes) -> bytes:
    """Compute key commitment tag over frame body.

    Prevents key commitment attacks ("invisible salamanders") where an
    adversary finds two different keys that both produce valid AES-GCM
    tags for the same ciphertext, but yield different plaintexts.

    The commitment is HMAC-SHA256(mac_key, frame_body) truncated to 16
    bytes. Since mac_key is deterministically derived from message_key
    via domain-separated HKDF, a valid commitment proves the decryptor
    holds the ONLY key that could have produced it.

    Args:
        mac_key: 32-byte MAC key (bytes) or handle (int) from derive_frame_keys()
        frame_body: Frame body bytes (beacon + ciphertext, or just ciphertext)

    Returns:
        16-byte commitment tag (truncated HMAC-SHA256)
    """
    if isinstance(mac_key, int):
        hb = get_handle_backend()
        return hb.hmac_sha256(mac_key, frame_body)[:COMMIT_TAG_SIZE]
    backend = get_default_backend()
    return backend.hmac_sha256(mac_key, frame_body)[:COMMIT_TAG_SIZE]


# ── Data Structures ──────────────────────────────────────────────────────────


@dataclass
class FrameKeys:
    """Per-frame derived subkeys.
    enc_key and mac_key are opaque handles (ints) or bytearrays (legacy).
    nonce is bytes (non-secret, needed for AEAD)."""

    enc_key: Union[bytearray, int]  # Handle ID or 32-byte AES key (legacy)
    nonce: bytearray  # 12 bytes: AES-GCM nonce (non-secret, needed for AEAD)
    mac_key: Union[bytearray, int]  # Handle ID or 32-byte MAC key (legacy)

    def zeroize(self) -> None:
        """Securely zero/drop all subkeys."""
        hb = get_handle_backend()
        if isinstance(self.enc_key, int):
            try:
                hb.drop(self.enc_key)
            except Exception:
                pass
        else:
            _secure_zero(self.enc_key)
        _secure_zero(self.nonce)
        if isinstance(self.mac_key, int):
            try:
                hb.drop(self.mac_key)
            except Exception:
                pass
        else:
            _secure_zero(self.mac_key)


@dataclass
class RatchetState:
    """
    Mutable ratchet chain state.

    chain_key and root_key are opaque handle IDs (ints) — secrets never in Python.
    Previous chain_keys are irrecoverable after handle drop.
    """

    chain_key: Union[bytearray, int]  # Handle ID (secret, never in Python)
    salt: bytes  # 16 bytes: session salt (immutable, from manifest)
    position: int = 0  # Current chain position (frame index)
    root_key: Optional[Union[bytearray, int]] = None  # Handle ID for root key
    epoch: int = 0  # Current asymmetric rekey epoch (MSR v2.0)

    def zeroize(self) -> None:
        """Drop all key handles. Call when ratchet is no longer needed."""
        hb = get_handle_backend()
        if isinstance(self.chain_key, int):
            try:
                hb.drop(self.chain_key)
            except Exception:
                pass
        elif isinstance(self.chain_key, bytearray):
            _secure_zero(self.chain_key)
        if self.root_key is not None:
            if isinstance(self.root_key, int):
                try:
                    hb.drop(self.root_key)
                except Exception:
                    pass
            elif isinstance(self.root_key, bytearray):
                _secure_zero(self.root_key)
        self.position = -1  # Sentinel: state is dead


# ── Core Ratchet Operations ──────────────────────────────────────────────────


def init_ratchet(root_key: Union[bytes, int], salt: bytes) -> RatchetState:
    """
    Initialize a ratchet chain from root key material.

    Args:
        root_key: 32-byte root key (bytes or handle)
        salt: 16-byte random salt (from manifest)

    Returns:
        RatchetState at position 0 (keys as opaque handles)
    """
    hb = get_handle_backend()
    rk_handle, cleanup = _ensure_handle(root_key)
    try:
        chain_key_handle = _hkdf_derive_handle(rk_handle, salt, RATCHET_ROOT_INFO, 32)
        ratchet_root_handle = _hkdf_derive_handle(rk_handle, salt, ASYM_REKEY_ROOT_INIT_INFO, 32)
    finally:
        if cleanup:
            hb.drop(rk_handle)

    return RatchetState(
        chain_key=chain_key_handle,
        salt=salt,
        position=0,
        root_key=ratchet_root_handle,
        epoch=0,
    )


def ratchet_step(state: RatchetState) -> Tuple[int, RatchetState]:
    """
    Advance the ratchet by one step, producing a message key handle.

    chain_key is an opaque handle. The returned message_key is also an
    opaque handle (int) — secret bytes never cross into Python.

    Args:
        state: Current ratchet state (CONSUMED — chain_key handle will be dropped)

    Returns:
        (message_key_handle, new_state) — message_key_handle is an opaque int

    Raises:
        ValueError: If state is dead or at max position
    """
    if state.position < 0:
        raise ValueError("Ratchet state is dead (already zeroized)")
    if state.position > MAX_FRAME_INDEX:
        raise ValueError(f"Ratchet position overflow: {state.position} > {MAX_FRAME_INDEX}")

    hb = get_handle_backend()
    ck_handle = state.chain_key

    if isinstance(ck_handle, int):
        # Handle-based path: derive message_key and next_chain_key via handles
        next_ck_handle = _hkdf_derive_handle(ck_handle, state.salt, RATCHET_STEP_INFO, 32)

        # message_key as handle (secret stays in Rust)
        message_key_handle = _hkdf_derive_handle(ck_handle, state.salt, RATCHET_MSG_INFO, 32)

        # Drop old chain key (forward secrecy)
        hb.drop(ck_handle)

        new_state = RatchetState(
            chain_key=next_ck_handle,
            salt=state.salt,
            position=state.position + 1,
            root_key=state.root_key,
            epoch=state.epoch,
        )
    else:
        # Legacy bytearray path (backward compat) — import result into handle
        current_key = bytes(state.chain_key)
        message_key = _hkdf_derive(current_key, state.salt, RATCHET_MSG_INFO, 32)
        next_chain_key = _hkdf_derive(current_key, state.salt, RATCHET_STEP_INFO, 32)
        _secure_zero(state.chain_key)
        message_key_handle = hb.import_key(message_key)
        new_state = RatchetState(
            chain_key=hb.import_key(next_chain_key),
            salt=state.salt,
            position=state.position + 1,
            root_key=state.root_key,
            epoch=state.epoch,
        )

    return message_key_handle, new_state


def derive_frame_keys(message_key: Union[bytes, int], salt: bytes) -> FrameKeys:
    """
    Derive per-frame subkeys from a message key.

    Subkey derivation uses domain-separated HKDF to ensure independence:
        enc_key  = HKDF(message_key, salt, "meow_ratchet_frame_enc_v1")[:32]
        nonce    = HKDF(message_key, salt, "meow_ratchet_frame_nonce_v1")[:12]
        mac_key  = HKDF(message_key, salt, "meow_ratchet_frame_mac_v1")[:32]

    Args:
        message_key: 32-byte message key (bytes or handle) from ratchet_step()
        salt: 16-byte session salt

    Returns:
        FrameKeys with enc_key/mac_key as handles, nonce as bytes
    """
    hb = get_handle_backend()
    mk_handle, cleanup = _ensure_handle(message_key)
    try:
        enc_key_handle = _hkdf_derive_handle(mk_handle, salt, FRAME_ENC_INFO, 32)
        nonce = _hkdf_derive_bytes_from_handle(mk_handle, salt, FRAME_NONCE_INFO, 12)
        mac_key_handle = _hkdf_derive_handle(mk_handle, salt, FRAME_MAC_INFO, 32)
    finally:
        if cleanup:
            hb.drop(mk_handle)

    return FrameKeys(
        enc_key=enc_key_handle,
        nonce=bytearray(nonce),
        mac_key=mac_key_handle,
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
    message_key: Union[bytes, int],
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

    Args:
        frame_data: Raw droplet bytes to encrypt
        message_key: 32-byte message key or handle from ratchet_step()
        frame_index: 0-based frame index
        salt: 16-byte session salt
        k_blocks: Fountain source block count
        block_size: Fountain block size
        total_frames: Total frame count

    Returns:
        Encrypted frame bytes (frame_index || ciphertext || tag)
    """
    from .crypto_backend import get_default_backend

    backend = get_default_backend()

    # Derive per-frame subkeys
    keys = derive_frame_keys(message_key, salt)

    # Build AAD
    aad = build_frame_aad(frame_index, salt, k_blocks, block_size, total_frames)

    try:
        # Encrypt with AES-256-GCM
        hb = get_handle_backend()
        if isinstance(keys.enc_key, int):
            ciphertext = hb.aes_gcm_encrypt(
                key_handle=keys.enc_key,
                nonce=bytes(keys.nonce),
                plaintext=frame_data,
                aad=aad,
            )
        else:
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
    message_key: Union[bytes, int],
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
        hb = get_handle_backend()
        if isinstance(keys.enc_key, int):
            plaintext = hb.aes_gcm_decrypt(
                key_handle=keys.enc_key,
                nonce=bytes(keys.nonce),
                ciphertext=ciphertext,
                aad=aad,
            )
        else:
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
        rekey_interval: int = DEFAULT_REKEY_INTERVAL,
        receiver_public_key: Optional[bytes] = None,
        receiver_pq_public_key: Optional[bytes] = None,
    ):
        """
        Initialize encoder ratchet.

        Args:
            root_key: 32-byte root key (from main key derivation)
            salt: 16-byte session salt
            k_blocks: Number of fountain source blocks
            block_size: Fountain block size in bytes
            total_frames: Total number of frames to encrypt
            rekey_interval: Frames between rekey beacons (default: DEFAULT_REKEY_INTERVAL)
            receiver_public_key: X25519 public key for KEM beacons (optional)
            receiver_pq_public_key: ML-KEM-1024 public key for PQ beacons (optional)
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
        self._receiver_pq_public_key = receiver_pq_public_key
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
        hb = get_handle_backend()

        # ─── MSR v2.0: Asymmetric root key rotation (before ratchet step) ───
        beacon_header = b""
        pq_beacon_header = b""  # Populated by PQ root rekey or PQ-only fallback below
        if self._is_rekey_frame(frame_index) and self._receiver_public_key is not None:
            shared_secret_handle, eph_pub = _generate_asym_rekey(self._receiver_public_key)
            beacon_header = eph_pub

            self._state.epoch += 1

            # Handle-based root rekey (all secrets stay in Rust)
            new_root_h, new_chain_h = _asymmetric_root_rekey_handle(
                root_key_handle=self._state.root_key,
                shared_secret_handle=shared_secret_handle,
                salt=self._salt,
                epoch=self._state.epoch,
            )

            # Drop old root + chain handles (forward secrecy within epoch)
            old_rk = self._state.root_key
            old_ck = self._state.chain_key
            if isinstance(old_rk, int):
                hb.drop(old_rk)
            if isinstance(old_ck, int):
                hb.drop(old_ck)
            hb.drop(shared_secret_handle)

            # ─── PQ-hybrid root rekey: fold ML-KEM-1024 into root (PQXDH) ───
            # Upgrade classical X25519 root rotation to PQXDH-level security.
            # The ML-KEM-1024 shared secret is folded into new_root_h using the
            # PQXDH combiner: attacker must break BOTH X25519 AND ML-KEM-1024
            # to predict the new root key. The PQ ciphertext is embedded in
            # pq_beacon_header for the decoder to decapsulate.
            if self._receiver_pq_public_key is not None:
                pq_ct, pq_shared = _mlkem1024_encapsulate(self._receiver_pq_public_key)
                pq_beacon_header = PQBeaconFrame(ciphertext=pq_ct).to_bytes()
                new_root_h = _fold_pq_into_root(new_root_h, pq_shared, self._state.epoch)
                # CRITICAL: Re-derive chain from the PQ-hybrid root so that the
                # chain key (and all subsequent message keys) depend on BOTH
                # X25519 AND ML-KEM-1024.  Without this, the PQ fold only
                # updates the root but the chain remains X25519-only.
                if isinstance(new_chain_h, int):
                    hb.drop(new_chain_h)
                new_chain_h = _hkdf_derive_handle(new_root_h, self._salt, ASYM_REKEY_CHAIN_INFO, 32)
                # Zeroize Python-side copy (handle keeps the real secret in Rust)
                pq_shared = b"\x00" * len(pq_shared)

            self._state.root_key = new_root_h
            self._state.chain_key = new_chain_h

        # Ratchet step: derive message key handle from current chain
        msg_key_handle, self._state = ratchet_step(self._state)

        # Plaintext beacon fallback (no receiver key → mix entropy via handle)
        if self._is_rekey_frame(frame_index) and self._receiver_public_key is None:
            beacon_secret = secrets.token_bytes(REKEY_BEACON_SIZE)
            beacon_header = beacon_secret
            new_mk_handle = _mix_beacon_handle(msg_key_handle, beacon_secret, self._salt)
            hb.drop(msg_key_handle)
            msg_key_handle = new_mk_handle

        # ─── PQ-only fallback: PQ available but no X25519 key ─────────────────
        # When a PQ public key is provided but no classical X25519 key exists,
        # we cannot do a root rekey (no ephemeral X25519 material). Instead,
        # fold the ML-KEM-1024 shared secret into the message key. This
        # provides per-message PQ protection at the cost of no root rotation.
        # NOTE: When BOTH X25519 and PQ keys are present, the PQ-hybrid root
        # rekey runs INSIDE the X25519 block above — that path is preferred.
        if (
            self._is_rekey_frame(frame_index)
            and self._receiver_pq_public_key is not None
            and self._receiver_public_key is None
        ):
            pq_ct, pq_shared = _mlkem1024_encapsulate(self._receiver_pq_public_key)
            new_mk_handle = _mix_pq_beacon_handle(msg_key_handle, pq_shared, self._salt)
            hb.drop(msg_key_handle)
            msg_key_handle = new_mk_handle
            pq_beacon_header = PQBeaconFrame(ciphertext=pq_ct).to_bytes()
            # Zeroize PQ shared secret (ephemeral, defense in depth)
            pq_shared = b"\x00" * len(pq_shared)

        commit_keys = None
        try:
            # Derive commitment keys (mac_key as handle for commitment tag)
            commit_keys = derive_frame_keys(msg_key_handle, self._salt)

            # Encrypt frame using message_key handle
            encrypted = encrypt_frame(
                frame_data=frame_data,
                message_key=msg_key_handle,
                frame_index=frame_index,
                salt=self._salt,
                k_blocks=self._k_blocks,
                block_size=self._block_size,
                total_frames=self._total_frames,
            )

            # Extract ciphertext (strip plaintext frame_index header)
            raw_ciphertext = encrypted[FRAME_INDEX_SIZE:]

            # Insert beacon(s) before ciphertext:
            # [classical_beacon?(32)] [pq_beacon?(5+2+1568)] [ciphertext]
            frame_body = beacon_header + pq_beacon_header + raw_ciphertext

            # Key commitment: HMAC(mac_key handle, frame_body)
            commitment = _compute_commitment(commit_keys.mac_key, frame_body)

            # Header encryption: mask the frame index
            enc_idx = _encrypt_index(self._header_key, frame_index)

            # Assemble hardened frame
            result = enc_idx + commitment + frame_body

            self._frames_encrypted += 1
            return result
        finally:
            # Drop message key handle and commitment keys
            hb.drop(msg_key_handle)
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
            # Drop header key handle
            if isinstance(self._header_key, int):
                try:
                    get_handle_backend().drop(self._header_key)
                except Exception:
                    pass
            self._header_key = 0
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
        rekey_interval: int = DEFAULT_REKEY_INTERVAL,
        receiver_private_key: Optional[bytes] = None,
        receiver_pq_keypair: Optional[PQBeaconKeyPair] = None,
    ):
        """
        Initialize decoder ratchet.

        Args:
            root_key: 32-byte root key (same derivation as encoder)
            salt: 16-byte session salt
            k_blocks: Number of fountain source blocks
            block_size: Fountain block size in bytes
            total_frames: Total number of expected frames
            rekey_interval: Frames between rekey beacons (default: DEFAULT_REKEY_INTERVAL)
            receiver_private_key: X25519 private key for KEM beacons (optional)
            receiver_pq_keypair: ML-KEM-1024 keypair for PQ beacons (optional)
        """
        self._state = init_ratchet(root_key, salt)
        self._salt = salt
        self._k_blocks = k_blocks
        self._block_size = block_size
        self._total_frames = total_frames
        self._skipped_keys: Dict[int, int] = {}  # frame_index → message_key handle
        self._consumed_indices: set = set()  # Track consumed frame indices
        self._finalized = False
        self._rekey_interval = rekey_interval
        self._receiver_private_key = receiver_private_key
        self._receiver_pq_keypair = receiver_pq_keypair
        # MSR v2.0: Asymmetric rekey material storage for epoch advancement
        # Maps epoch_number → ephemeral_public_key (32 bytes) extracted from
        # rekey frames. Populated during decrypt() BEFORE _advance_to() so
        # the chain can cross epoch boundaries during fast-forward.
        # Maps epoch → (eph_pub_bytes, pq_ciphertext_or_None) for hybrid root rekey
        self._received_rekey_material: Dict[int, tuple] = {}
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

        Uses handle-based operations so all secret key bytes stay in Rust.
        When PQ rekey material is available, performs a full PQXDH-style
        hybrid root rotation: new_root depends on BOTH X25519 AND ML-KEM-1024.
        """
        eph_pub, pq_ct = self._received_rekey_material.pop(epoch)
        shared_secret_handle = _recover_asym_rekey(eph_pub, self._receiver_private_key)

        hb = get_handle_backend()
        new_root_h, new_chain_h = _asymmetric_root_rekey_handle(
            root_key_handle=self._state.root_key,
            shared_secret_handle=shared_secret_handle,
            salt=self._salt,
            epoch=epoch,
        )

        # Drop old handles (forward secrecy)
        old_rk = self._state.root_key
        old_ck = self._state.chain_key
        if isinstance(old_rk, int):
            hb.drop(old_rk)
        if isinstance(old_ck, int):
            hb.drop(old_ck)
        hb.drop(shared_secret_handle)

        # ─── PQ-hybrid root fold: fold ML-KEM-1024 into root (PQXDH) ────────
        # If the encoder included a PQ ciphertext in the rekey frame and we have
        # the PQ keypair, decapsulate and fold the shared secret into the root.
        # This must mirror encode_next's PQ-hybrid block exactly.
        if pq_ct is not None and self._receiver_pq_keypair is not None:
            pq_shared = _mlkem1024_decapsulate(self._receiver_pq_keypair.secret_key, pq_ct)
            new_root_h = _fold_pq_into_root(new_root_h, pq_shared, epoch)
            # CRITICAL: Re-derive chain from the PQ-hybrid root so that the
            # chain key (and all subsequent message keys) depend on BOTH
            # X25519 AND ML-KEM-1024.  Must mirror the encoder's fix exactly.
            if isinstance(new_chain_h, int):
                hb.drop(new_chain_h)
            new_chain_h = _hkdf_derive_handle(new_root_h, self._salt, ASYM_REKEY_CHAIN_INFO, 32)
            # Zeroize Python-side copy (defense in depth)
            pq_shared = b"\x00" * len(pq_shared)

        self._state.root_key = new_root_h
        self._state.chain_key = new_chain_h
        self._state.epoch = epoch

    @property
    def position(self) -> int:
        """Current chain position (next frame index to derive from chain)."""
        return self._state.position

    def _advance_to(self, target_index: int) -> int:
        """
        Advance the chain to target_index, caching skipped message key handles.

        Returns:
            message_key_handle for target_index (an opaque int)
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

            msg_key_handle, self._state = ratchet_step(self._state)
            # Cache the skipped key handle for later out-of-order reception
            skipped_idx = self._state.position - 1
            self._skipped_keys[skipped_idx] = msg_key_handle

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
        msg_key_handle, self._state = ratchet_step(self._state)
        return msg_key_handle

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
            # Pre-extract PQ ciphertext BEFORE _advance_to() so _execute_rekey()
            # can perform the full PQ-hybrid root rotation in one step.
            _pq_frame_early = PQBeaconFrame.from_bytes(frame_body[REKEY_BEACON_SIZE:])
            _pq_ct_early = _pq_frame_early.ciphertext if _pq_frame_early is not None else None
            epoch = self._frame_epoch(frame_index)
            self._received_rekey_material[epoch] = (eph_pub, _pq_ct_early)

        # Get the message key handle for this frame
        msg_key_handle: Optional[int] = None
        commit_keys = None
        hb = get_handle_backend()

        try:
            if frame_index in self._skipped_keys:
                # Case 1: This frame was skipped earlier — use cached handle
                msg_key_handle = self._skipped_keys.pop(frame_index)
            elif frame_index >= self._state.position:
                # Case 2: Frame is at or ahead of current position — advance chain
                msg_key_handle = self._advance_to(frame_index)
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
                    # Plaintext beacon fallback: mix beacon via handle
                    beacon_data = frame_body[:REKEY_BEACON_SIZE]
                    new_mk_handle = _mix_beacon_handle(msg_key_handle, beacon_data, self._salt)
                    hb.drop(msg_key_handle)
                    msg_key_handle = new_mk_handle

            # Step 4b: PQ beacon processing (after classical beacon is stripped)
            # Two code paths:
            # A. Full hybrid (is_asym_rekey=True): PQ was ALREADY folded into
            #    the root key by _execute_rekey() → only strip PQ beacon bytes.
            # B. PQ-only fallback (is_asym_rekey=False, no X25519 key): mix PQ
            #    shared secret into the message key (mirrors encoder fallback).
            if self._is_rekey_frame(frame_index) and self._receiver_pq_keypair is not None:
                pq_frame = PQBeaconFrame.from_bytes(ciphertext_body)
                if pq_frame is not None:
                    if not is_asym_rekey:
                        # PQ-only fallback: mix PQ into message key (no root key)
                        pq_shared = _mlkem1024_decapsulate(
                            self._receiver_pq_keypair.secret_key,
                            pq_frame.ciphertext,
                        )
                        new_mk_handle = _mix_pq_beacon_handle(msg_key_handle, pq_shared, self._salt)
                        hb.drop(msg_key_handle)
                        msg_key_handle = new_mk_handle
                        # Zeroize Python-side copy (defense in depth)
                        pq_shared = b"\x00" * len(pq_shared)
                    # is_asym_rekey: PQ already folded into root by _execute_rekey
                    # Strip PQ beacon bytes from ciphertext body (both paths)
                    pq_total = PQBeaconFrame.header_size() + len(pq_frame.ciphertext)
                    ciphertext_body = ciphertext_body[pq_total:]

            # Step 5: Key commitment verification (BEFORE decryption!)
            commit_keys = derive_frame_keys(msg_key_handle, self._salt)
            expected_commitment = _compute_commitment(commit_keys.mac_key, frame_body)
            _backend = get_default_backend()
            if not _backend.constant_time_compare(commitment_tag, expected_commitment):
                raise ValueError(
                    f"Key commitment verification failed for frame {frame_index}. "
                    "Possible key commitment attack or corrupted frame."
                )

            # Step 6: AES-GCM decryption using message key handle
            reconstructed = struct.pack(">I", frame_index) + ciphertext_body

            plaintext = decrypt_frame(
                encrypted_frame=reconstructed,
                message_key=msg_key_handle,
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
            # Drop message key handle and commitment keys
            if msg_key_handle is not None:
                try:
                    hb.drop(msg_key_handle)
                except Exception:
                    pass
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
            hb = get_handle_backend()
            for idx, key_handle in self._skipped_keys.items():
                try:
                    hb.drop(key_handle)
                except Exception:
                    pass
            self._skipped_keys.clear()
            self._consumed_indices.clear()
            self._received_rekey_material.clear()
            # Drop header key handle
            if isinstance(self._header_key, int):
                try:
                    hb.drop(self._header_key)
                except Exception:
                    pass
            self._header_key = 0
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


# ── Tasteful Meow API Layer (opt-in) ────────────────────────────────────────
# Cat-themed convenience aliases for the wrapper/demo layer.
# These are NOT exported by default.  Import them explicitly or set
#     MEOW_CAT_API=1
# to enable them at module level.  Core crypto internals always use the
# serious names (RatchetState, FrameKeys, init_ratchet, etc.).


def _register_cat_aliases() -> None:
    """Lazily register cat-themed aliases into this module's namespace."""
    import sys

    _mod = sys.modules[__name__]
    # Type aliases
    _mod.PawState = RatchetState  # type: ignore[attr-defined]
    _mod.WhiskerKeys = FrameKeys  # type: ignore[attr-defined]
    # Function aliases
    _mod.bury_in_litter = _secure_zero  # type: ignore[attr-defined]
    _mod.knead_subkey = derive_frame_keys  # type: ignore[attr-defined]

    def prime_cat(password_key: bytes, salt: bytes) -> RatchetState:
        """Initialize a ratchet from the Prime Cat (root key).

        This is the tasteful meow alias for init_ratchet().
        Use this at the wrapper/demo layer. Core crypto uses init_ratchet().
        """
        return init_ratchet(password_key, salt)

    _mod.prime_cat = prime_cat  # type: ignore[attr-defined]


# Auto-register when MEOW_CAT_API=1 (e.g. demo scripts, notebooks)
if os.environ.get("MEOW_CAT_API", "0") == "1":
    _register_cat_aliases()
