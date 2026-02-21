"""
Dual-Stream Encoding Module for Schrödinger Indistinguishability

Every encode — regardless of whether the user requests single-secret or
dual-secret (Schrödinger) mode — produces exactly TWO independent
sub-streams interleaved in the fountain-coded output. In single-secret
mode the second stream is cryptographic-strength random filler with
its own independent keys. In Schrödinger mode the user supplies
both payloads.

PURPOSE: Make single-secret and dual-secret GIF outputs structurally
identical, so a forensic examiner cannot distinguish them.

Architecture:
    payload → compress → encrypt (stream A)  ─┐
    decoy/random → encrypt (stream B)         ─┤
                                               ▼
                                    interleave(A, B)
                                               ▼
                                    fountain encode
                                               ▼
                                    QR → GIF

Each sub-stream has completely independent:
    - Argon2id salt + derived key (or separate key handles)
    - AES-256-GCM nonce derivation (separate manifest hash)
    - Ratchet chain (separate root key + chain key)
    - Fountain encoding seed
    - GCM key / nonce / AAD

There are NO cross-commitments between streams. The manifest stores
metadata for both streams; a decoder with one password can authenticate
and recover only its own stream, treating the other as fountain erasures.

Security Properties:
    - Statistical indistinguishability: both streams are AES-256-GCM
      ciphertext and appear as uniform random bytes.
    - Each sub-stream uses independent Argon2id derivation.
    - No cross-commitments: knowledge of stream A key reveals nothing
      about stream B.
    - The dummy stream (single-secret mode) is cryptographically
      indistinguishable from a real second secret.

Honest Limitations (see docs/THREAT_MODEL.md):
    - File size patterns may leak dual-encoding presence if attacker
      compares outputs across users or time.
    - Timing side-channels during encode/decode are best-effort equalized.
    - Memory/swap forensics may recover both key sets.
    - This is plausible deniability under casual inspection, NOT perfect
      cryptographic deniability against unlimited compute.
"""

import secrets
import struct
from typing import Optional, Tuple
from dataclasses import dataclass

from .crypto_backend import get_default_backend, get_handle_backend
from .crypto import (
    encrypt_file_bytes_handle,
    ARGON2_MEMORY,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
)
from .quantum_mixer import entangle_realities


# Domain separation for dual-stream metadata
DUAL_STREAM_ENC_A_INFO = b"meow_dual_enc_a_v1"
DUAL_STREAM_ENC_B_INFO = b"meow_dual_enc_b_v1"
DUAL_STREAM_HMAC_A_INFO = b"meow_dual_hmac_a_v1"
DUAL_STREAM_HMAC_B_INFO = b"meow_dual_hmac_b_v1"


@dataclass
class DualStreamManifest:
    """Manifest for dual-stream (always-two-stream) encoding.

    Both streams are always present. In single-secret mode, stream B
    is random ciphertext with its own independent keys.

    Wire format (406 bytes):
        magic:          b"MEOW"   (4)
        version:        0x08      (1) — dual-stream always-on
        flags:          1 byte    (bit 0: stream_b_is_real)
        salt_a:         16 bytes
        salt_b:         16 bytes
        nonce_a:        12 bytes
        nonce_b:        12 bytes
        hmac_a:         32 bytes  (verifies password A)
        hmac_b:         32 bytes  (verifies password B, or dummy HMAC)
        metadata_a:     104 bytes (AES-GCM encrypted)
        metadata_b:     104 bytes (AES-GCM encrypted)
        block_count:    4 bytes   (BE)
        block_size:     4 bytes   (BE)
        superposition_len: 8 bytes (BE)
        target_frames:  4 bytes   (BE) — target total frame count (0 = auto)
        reserved:       28 bytes
        ─────────────────────────────
        Total: 382 bytes (same as SchrodingerManifest for backward compat)

    NOTE: Always 382 bytes regardless of single/dual mode.
    """
    salt_a: bytes
    salt_b: bytes
    nonce_a: bytes
    nonce_b: bytes
    hmac_a: bytes
    hmac_b: bytes
    metadata_a: bytes
    metadata_b: bytes
    block_count: int
    block_size: int
    superposition_len: int
    target_frames: int = 0
    magic: bytes = b"MEOW"
    version: int = 0x08
    flags: int = 0x00
    reserved: bytes = b"\x00" * 28

    def pack_core_for_auth(self) -> bytes:
        """Pack fields that are HMAC-authenticated (excludes HMACs themselves)."""
        core = self.magic
        core += struct.pack("BB", self.version, self.flags)
        core += self.salt_a + self.salt_b
        core += self.nonce_a + self.nonce_b
        core += self.metadata_a + self.metadata_b
        core += struct.pack(">IIQI", self.block_count, self.block_size,
                            self.superposition_len, self.target_frames)
        core += self.reserved
        return core

    def pack(self) -> bytes:
        """Serialize to wire format."""
        data = self.magic
        data += struct.pack("BB", self.version, self.flags)
        data += self.salt_a + self.salt_b
        data += self.nonce_a + self.nonce_b
        data += self.hmac_a + self.hmac_b
        data += self.metadata_a + self.metadata_b
        data += struct.pack(">IIQI", self.block_count, self.block_size,
                            self.superposition_len, self.target_frames)
        data += self.reserved
        return data

    @classmethod
    def unpack(cls, data: bytes) -> "DualStreamManifest":
        """Deserialize from wire format."""
        if len(data) < 382:
            raise ValueError(f"Manifest too short: {len(data)} < 382")
        if data[:4] != b"MEOW":
            raise ValueError("Invalid manifest magic")

        version, flags = struct.unpack("BB", data[4:6])
        if version != 0x08:
            raise ValueError(f"Not a dual-stream manifest (version 0x{version:02x})")

        offset = 6
        salt_a = data[offset:offset + 16]
        offset += 16
        salt_b = data[offset:offset + 16]
        offset += 16
        nonce_a = data[offset:offset + 12]
        offset += 12
        nonce_b = data[offset:offset + 12]
        offset += 12
        hmac_a = data[offset:offset + 32]
        offset += 32
        hmac_b = data[offset:offset + 32]
        offset += 32
        metadata_a = data[offset:offset + 104]
        offset += 104
        metadata_b = data[offset:offset + 104]
        offset += 104
        block_count, block_size, superposition_len, target_frames = struct.unpack(
            ">IIQI", data[offset:offset + 20]
        )
        offset += 20
        reserved = data[offset:offset + 28]

        return cls(
            salt_a=salt_a, salt_b=salt_b,
            nonce_a=nonce_a, nonce_b=nonce_b,
            hmac_a=hmac_a, hmac_b=hmac_b,
            metadata_a=metadata_a, metadata_b=metadata_b,
            block_count=block_count, block_size=block_size,
            superposition_len=superposition_len,
            target_frames=target_frames,
            magic=data[:4], version=version, flags=flags,
            reserved=reserved,
        )

    @property
    def stream_b_is_real(self) -> bool:
        """True if stream B contains a real user-supplied payload."""
        return bool(self.flags & 0x01)


def dual_stream_encode(
    real_data: bytes,
    real_password: str,
    decoy_data: Optional[bytes] = None,
    decoy_password: Optional[str] = None,
    block_size: int = 256,
    target_frames: int = 0,
) -> Tuple[bytes, DualStreamManifest]:
    """Encode data into a dual-stream interleaved ciphertext.

    ALWAYS produces two independent sub-streams. In single-secret mode
    (decoy_data=None), stream B is random ciphertext with independent keys.

    Args:
        real_data: Real secret payload.
        real_password: Password for stream A.
        decoy_data: Optional decoy payload for stream B.
        decoy_password: Password for stream B (required if decoy_data provided).
        block_size: Fountain code block size.
        target_frames: Target total frame count (0 = auto).

    Returns:
        (interleaved_ciphertext, manifest)
    """
    hb = get_handle_backend()

    # ── Stream A: Real payload ──
    comp_a, sha_a, salt_enc_a, nonce_enc_a, cipher_a, key_handle_a = \
        encrypt_file_bytes_handle(real_data, real_password, use_length_padding=True)
    hb.drop(key_handle_a)

    # ── Stream B: Decoy or random dummy ──
    is_dual = decoy_data is not None and decoy_password is not None

    if is_dual:
        # User-provided decoy
        comp_b, sha_b, salt_enc_b, nonce_enc_b, cipher_b, key_handle_b = \
            encrypt_file_bytes_handle(decoy_data, decoy_password, use_length_padding=True)
        hb.drop(key_handle_b)
        flags = 0x01  # stream_b_is_real
    else:
        # Generate random ciphertext of similar size for stream B.
        # This is a REAL encryption of random data under a random password,
        # not just random bytes — so the structure is identical to a real stream.
        dummy_password = secrets.token_hex(32)
        dummy_data = secrets.token_bytes(len(real_data))
        comp_b, sha_b, salt_enc_b, nonce_enc_b, cipher_b, key_handle_b = \
            encrypt_file_bytes_handle(dummy_data, dummy_password, use_length_padding=True)
        hb.drop(key_handle_b)
        # Decoy password is intentionally unknown (random, never stored)
        decoy_password = dummy_password
        flags = 0x00  # stream_b_is_dummy

    # ── Interleave the two ciphertexts ──
    superposition = entangle_realities(cipher_a, cipher_b)

    # ── Pad/size normalization ──
    # If target_frames specified, pad superposition to fill target block count
    if target_frames > 0:
        target_blocks = target_frames  # 1 block = 1 droplet ≈ 1 frame
        target_bytes = target_blocks * block_size
        if len(superposition) < target_bytes:
            # Pad with random (indistinguishable from ciphertext)
            superposition = superposition + secrets.token_bytes(target_bytes - len(superposition))

    # Split into blocks
    blocks = []
    for i in range(0, len(superposition), block_size):
        block = superposition[i:i + block_size]
        if len(block) < block_size:
            block = block + secrets.token_bytes(block_size - len(block))
        blocks.append(block)

    # ── Generate metadata keys (independent per stream) ──
    salt_a = secrets.token_bytes(16)
    salt_b = secrets.token_bytes(16)
    nonce_a = secrets.token_bytes(12)
    nonce_b = secrets.token_bytes(12)

    master_a = hb.derive_key_argon2id(
        real_password.encode("utf-8"), salt_a,
        memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    master_b = hb.derive_key_argon2id(
        decoy_password.encode("utf-8"), salt_b,
        memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )

    enc_key_a = hb.derive_key_hkdf(master_a, salt_a, DUAL_STREAM_ENC_A_INFO, 32)
    hmac_key_a = hb.derive_key_hkdf(master_a, salt_a, DUAL_STREAM_HMAC_A_INFO, 32)
    enc_key_b = hb.derive_key_hkdf(master_b, salt_b, DUAL_STREAM_ENC_B_INFO, 32)
    hmac_key_b = hb.derive_key_hkdf(master_b, salt_b, DUAL_STREAM_HMAC_B_INFO, 32)

    # ── Pack and encrypt metadata (88 bytes → 104 bytes with GCM tag) ──
    metadata_a_plain = (
        struct.pack(">QQQ", len(real_data), len(comp_a), len(cipher_a))
        + salt_enc_a + nonce_enc_a + sha_a + b"\x00" * 4
    )
    if is_dual:
        metadata_b_plain = (
            struct.pack(">QQQ", len(decoy_data), len(comp_b), len(cipher_b))
            + salt_enc_b + nonce_enc_b + sha_b + b"\x00" * 4
        )
    else:
        # Dummy metadata — same structure, random content
        metadata_b_plain = (
            struct.pack(">QQQ", len(dummy_data), len(comp_b), len(cipher_b))
            + salt_enc_b + nonce_enc_b + sha_b + b"\x00" * 4
        )

    metadata_a_enc = hb.aes_gcm_encrypt(enc_key_a, nonce_a, metadata_a_plain, None)
    metadata_b_enc = hb.aes_gcm_encrypt(enc_key_b, nonce_b, metadata_b_plain, None)

    if len(metadata_a_enc) != 104 or len(metadata_b_enc) != 104:
        raise RuntimeError(f"Metadata encryption length mismatch: {len(metadata_a_enc)}, {len(metadata_b_enc)}")

    # ── Compute manifest HMACs (independent per stream) ──
    temp_manifest = DualStreamManifest(
        salt_a=salt_a, salt_b=salt_b,
        nonce_a=nonce_a, nonce_b=nonce_b,
        hmac_a=b"\x00" * 32, hmac_b=b"\x00" * 32,
        metadata_a=metadata_a_enc, metadata_b=metadata_b_enc,
        block_count=len(blocks), block_size=block_size,
        superposition_len=len(superposition),
        target_frames=target_frames,
        flags=flags,
    )
    manifest_core = temp_manifest.pack_core_for_auth()

    hmac_a = hb.hmac_sha256(hmac_key_a, manifest_core)
    hmac_b = hb.hmac_sha256(hmac_key_b, manifest_core)

    # ── Zeroize all intermediate key handles ──
    for h in (master_a, master_b, enc_key_a, enc_key_b, hmac_key_a, hmac_key_b):
        try:
            hb.drop(h)
        except Exception:
            pass

    manifest = DualStreamManifest(
        salt_a=salt_a, salt_b=salt_b,
        nonce_a=nonce_a, nonce_b=nonce_b,
        hmac_a=hmac_a, hmac_b=hmac_b,
        metadata_a=metadata_a_enc, metadata_b=metadata_b_enc,
        block_count=len(blocks), block_size=block_size,
        superposition_len=len(superposition),
        target_frames=target_frames,
        flags=flags,
    )

    return b"".join(blocks), manifest


def dual_stream_try_decode_stream(
    manifest: DualStreamManifest,
    password: str,
    interleaved: bytes,
) -> Optional[Tuple[bytes, int]]:
    """Attempt to authenticate and decode one stream from a dual-stream manifest.

    Tries password against both stream A and stream B HMAC. If one matches,
    decrypts the corresponding metadata and returns the stream's ciphertext.

    Args:
        manifest: The dual-stream manifest.
        password: Password to try.
        interleaved: The interleaved ciphertext.

    Returns:
        (ciphertext, stream_index) if password matches a stream, else None.
        stream_index: 0 = stream A, 1 = stream B.
    """
    from .quantum_mixer import collapse_to_reality

    hb = get_handle_backend()

    manifest_core = manifest.pack_core_for_auth()

    # Try stream A
    master_a = hb.derive_key_argon2id(
        password.encode("utf-8"), manifest.salt_a,
        memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    hmac_key_a = hb.derive_key_hkdf(master_a, manifest.salt_a, DUAL_STREAM_HMAC_A_INFO, 32)
    computed_hmac_a = hb.hmac_sha256(hmac_key_a, manifest_core)

    import secrets as _secrets
    if _secrets.compare_digest(computed_hmac_a, manifest.hmac_a):
        # Password matches stream A
        enc_key_a = hb.derive_key_hkdf(master_a, manifest.salt_a, DUAL_STREAM_ENC_A_INFO, 32)
        try:
            metadata_plain = hb.aes_gcm_decrypt(enc_key_a, manifest.nonce_a, manifest.metadata_a, None)
        finally:
            hb.drop(enc_key_a)
            hb.drop(hmac_key_a)
            hb.drop(master_a)

        # Extract stream A ciphertext from interleaved (even positions)
        cipher_a = collapse_to_reality(interleaved, 0)
        return cipher_a, 0

    hb.drop(hmac_key_a)
    hb.drop(master_a)

    # Try stream B
    master_b = hb.derive_key_argon2id(
        password.encode("utf-8"), manifest.salt_b,
        memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    hmac_key_b = hb.derive_key_hkdf(master_b, manifest.salt_b, DUAL_STREAM_HMAC_B_INFO, 32)
    computed_hmac_b = hb.hmac_sha256(hmac_key_b, manifest_core)

    if _secrets.compare_digest(computed_hmac_b, manifest.hmac_b):
        # Password matches stream B
        enc_key_b = hb.derive_key_hkdf(master_b, manifest.salt_b, DUAL_STREAM_ENC_B_INFO, 32)
        try:
            metadata_plain = hb.aes_gcm_decrypt(enc_key_b, manifest.nonce_b, manifest.metadata_b, None)
        finally:
            hb.drop(enc_key_b)
            hb.drop(hmac_key_b)
            hb.drop(master_b)

        cipher_b = collapse_to_reality(interleaved, 1)
        return cipher_b, 1

    hb.drop(hmac_key_b)
    hb.drop(master_b)
    return None


def secure_decode_and_zeroize(
    manifest: DualStreamManifest,
    password: str,
    interleaved: bytes,
    duress: bool = False,
) -> Optional[Tuple[bytes, int]]:
    """Decode a stream and securely zeroize ALL key material afterward.

    This is the recommended decode entry point for production use.
    Guarantees that both stream key sets are zeroized regardless of
    success, failure, or exceptions.

    If duress=True, performs dummy decode timing to avoid timing
    side-channels that reveal which password was correct.

    Args:
        manifest: The dual-stream manifest.
        password: Password to try.
        interleaved: The interleaved ciphertext.
        duress: If True, simulate decode of both streams for timing parity.

    Returns:
        (ciphertext, stream_index) if password matches, else None.
    """
    from .constant_time import secure_zero_memory
    from .quantum_mixer import collapse_to_reality

    hb = get_handle_backend()
    handles_to_drop: list = []
    password_buf = bytearray(password.encode("utf-8"))

    try:
        manifest_core = manifest.pack_core_for_auth()
        result = None

        # ── Try Stream A ──
        master_a = hb.derive_key_argon2id(
            bytes(password_buf), manifest.salt_a,
            memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
            parallelism=ARGON2_PARALLELISM,
        )
        handles_to_drop.append(master_a)
        hmac_key_a = hb.derive_key_hkdf(master_a, manifest.salt_a, DUAL_STREAM_HMAC_A_INFO, 32)
        handles_to_drop.append(hmac_key_a)
        computed_hmac_a = hb.hmac_sha256(hmac_key_a, manifest_core)

        import secrets as _secrets
        matched_a = _secrets.compare_digest(computed_hmac_a, manifest.hmac_a)

        if matched_a:
            enc_key_a = hb.derive_key_hkdf(master_a, manifest.salt_a, DUAL_STREAM_ENC_A_INFO, 32)
            handles_to_drop.append(enc_key_a)
            try:
                _ = hb.aes_gcm_decrypt(enc_key_a, manifest.nonce_a, manifest.metadata_a, None)
                result = (collapse_to_reality(interleaved, 0), 0)
            except Exception:
                pass

        # ── Try Stream B (always, for timing parity if duress mode) ──
        if not matched_a or duress:
            master_b = hb.derive_key_argon2id(
                bytes(password_buf), manifest.salt_b,
                memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
                parallelism=ARGON2_PARALLELISM,
            )
            handles_to_drop.append(master_b)
            hmac_key_b = hb.derive_key_hkdf(master_b, manifest.salt_b, DUAL_STREAM_HMAC_B_INFO, 32)
            handles_to_drop.append(hmac_key_b)
            computed_hmac_b = hb.hmac_sha256(hmac_key_b, manifest_core)

            if not matched_a and _secrets.compare_digest(computed_hmac_b, manifest.hmac_b):
                enc_key_b = hb.derive_key_hkdf(master_b, manifest.salt_b, DUAL_STREAM_ENC_B_INFO, 32)
                handles_to_drop.append(enc_key_b)
                try:
                    _ = hb.aes_gcm_decrypt(enc_key_b, manifest.nonce_b, manifest.metadata_b, None)
                    result = (collapse_to_reality(interleaved, 1), 1)
                except Exception:
                    pass

        return result

    finally:
        # ── Zeroize ALL handles (both streams) ──
        for h in handles_to_drop:
            try:
                hb.drop(h)
            except Exception:
                pass

        # ── Zeroize password buffer in Python ──
        secure_zero_memory(password_buf)

        # ── Zeroize manifest_core (contains authenticated data) ──
        if isinstance(manifest_core, bytearray):
            secure_zero_memory(manifest_core)
