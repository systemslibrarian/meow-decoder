#!/usr/bin/env python3
"""
Schrödinger's Yarn Ball - Dual Reality Encoder v6.0.0

TRUE PLAUSIBLE DENIABILITY VIA QUANTUM SUPERPOSITION

Rewritten for the production Rust crypto backend (HandleBackend).
All secret key material stays inside opaque Rust handles — no raw
key bytes ever enter Python memory.

Architecture:
    1. Encrypt both files independently (AES-256-GCM + Argon2id via handles)
    2. Pad to same length (prevents size fingerprinting)
    3. Interleave encrypted blocks (even=A, odd=B)
    4. Fountain encode + QR + GIF

Security Properties:
    - All key derivation via Rust HandleBackend (constant-time, zeroize)
    - HKDF domain separation for enc vs HMAC keys
    - HMAC covers full manifest core (tamper-evident)
    - Independent decryption (each password works alone)
    - Plausible deniability (cannot prove second secret exists)
"""

import sys
import secrets
import struct
import argparse
from pathlib import Path
from getpass import getpass
from typing import Tuple, Optional
from dataclasses import dataclass

from .crypto import (
    encrypt_file_bytes_handle,
    ARGON2_MEMORY,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
)
from .crypto_backend import get_handle_backend, get_default_backend
from .fountain import FountainEncoder, pack_droplet
from .qr_code import QRCodeGenerator
from .gif_handler import GIFEncoder
from .config import EncodingConfig
from .frame_mac import pack_frame_with_mac
from .quantum_mixer import entangle_realities
from .decoy_generator import generate_convincing_decoy

# Current manifest version.  Bump when the binary layout changes.
#   0x07 = legacy (no frame_mac_seed, reserved=32 zeros)
#   0x08 = current (first 16 bytes of old-reserved repurposed as frame_mac_seed;
#                   remaining 16 bytes stay as reserved)
_MANIFEST_VERSION = 0x08

# Domain info used to derive the frame-MAC master key from the manifest seed.
# The seed itself is NOT secret (stored plaintext in the manifest), so derivation
# may run in Python.  Its only purpose is per-GIF key uniqueness for DoS-filter
# frame MACs; content authentication is provided by the Argon2id HMAC layer.
_FRAME_MAC_SEED_INFO = b"meow_schrodinger_frame_mac_seed_v2"


@dataclass
class SchrodingerManifest:
    """
    Manifest for Schrödinger mode v6.0.0  (binary version 0x08).

    Layout (382 bytes total, unchanged from v0x07):
        - magic:          b"MEOW" (4 bytes)
        - version:        0x08   (1 byte)
        - flags:          1 byte (reserved)
        - salt_a:         16 bytes
        - salt_b:         16 bytes
        - nonce_a:        12 bytes
        - nonce_b:        12 bytes
        - reality_a_hmac: 32 bytes  (Argon2id-based; verifies password A)
        - reality_b_hmac: 32 bytes  (Argon2id-based; verifies password B)
        - metadata_a:     104 bytes (AES-GCM encrypted per reality)
        - metadata_b:     104 bytes
        - block_count:    4 bytes
        - block_size:     4 bytes
        - superposition_len: 8 bytes
        - frame_mac_seed: 16 bytes  ← NEW in v0x08 (was first 16B of reserved)
        - reserved:       16 bytes  (remaining reserved bytes)
    Total: 382 bytes

    frame_mac_seed design
    ---------------------
    The seed is stored UNENCRYPTED.  It is NOT a secret — it provides only
    per-GIF key uniqueness for the DoS-filter frame MACs.  Content authentication
    is always provided by the Argon2id HMAC layer (reality_a/b_hmac + AES-GCM).

    Both reality-A and reality-B users derive the identical frame MAC master key:

        frame_mac_master = SHA-256(frame_mac_seed || _FRAME_MAC_SEED_INFO)

    This means EITHER password holder can verify frame MACs without learning
    anything about the other reality's password.  Frame MAC verification is a
    pure DoS filter; it does not authenticate content.
    """

    # Required fields
    salt_a: bytes
    salt_b: bytes
    nonce_a: bytes
    nonce_b: bytes
    reality_a_hmac: bytes
    reality_b_hmac: bytes
    metadata_a: bytes
    metadata_b: bytes
    block_count: int
    block_size: int
    superposition_len: int
    # Fields with defaults
    magic: bytes = b"MEOW"
    version: int = _MANIFEST_VERSION  # 0x08
    flags: int = 0x00
    # Security: public per-GIF nonce for frame-MAC key derivation (NOT secret).
    # See class docstring for full rationale.
    frame_mac_seed: bytes = b"\x00" * 16
    reserved: bytes = b"\x00" * 16  # 16 remaining reserved bytes (was 32)

    def pack_core_for_auth(self) -> bytes:
        """Pack all manifest fields that must be authenticated by HMAC.

        Excludes the HMACs themselves (they are what we're computing).
        Includes frame_mac_seed so the seed is bound by Argon2id HMAC —
        an attacker cannot substitute the seed without invalidating the HMAC.
        """
        core = self.magic
        core += struct.pack("BB", self.version, self.flags)
        core += self.salt_a
        core += self.salt_b
        core += self.nonce_a
        core += self.nonce_b
        core += self.metadata_a
        core += self.metadata_b
        core += struct.pack(">IIQ", self.block_count, self.block_size, self.superposition_len)
        core += self.frame_mac_seed  # bound in HMAC — seed cannot be swapped
        core += self.reserved
        return core

    def pack(self) -> bytes:
        """Pack manifest to bytes (382-byte wire format)."""
        data = self.magic
        data += struct.pack("BB", self.version, self.flags)
        data += self.salt_a
        data += self.salt_b
        data += self.nonce_a
        data += self.nonce_b
        data += self.reality_a_hmac
        data += self.reality_b_hmac
        data += self.metadata_a
        data += self.metadata_b
        data += struct.pack(">IIQ", self.block_count, self.block_size, self.superposition_len)
        data += self.frame_mac_seed  # 16 bytes (was first 16B of reserved)
        data += self.reserved  # 16 bytes (remaining reserved)
        return data

    @classmethod
    def unpack(cls, data: bytes) -> "SchrodingerManifest":
        """Unpack manifest from bytes.

        Supports both v0x07 (legacy, no frame_mac_seed) and
        v0x08 (current, has frame_mac_seed in first 16B of old-reserved).
        """
        if len(data) < 382:
            raise ValueError(f"Manifest too short: {len(data)} bytes (need 382)")
        if data[:4] != b"MEOW":
            raise ValueError("Invalid manifest magic")

        version, flags = struct.unpack("BB", data[4:6])
        if version not in (0x07, 0x08):
            raise ValueError(f"Not a Schrödinger manifest (version 0x{version:02x})")

        offset = 6
        salt_a = data[offset : offset + 16]
        offset += 16
        salt_b = data[offset : offset + 16]
        offset += 16
        nonce_a = data[offset : offset + 12]
        offset += 12
        nonce_b = data[offset : offset + 12]
        offset += 12
        reality_a_hmac = data[offset : offset + 32]
        offset += 32
        reality_b_hmac = data[offset : offset + 32]
        offset += 32
        metadata_a = data[offset : offset + 104]
        offset += 104
        metadata_b = data[offset : offset + 104]
        offset += 104
        block_count, block_size, superposition_len = struct.unpack(
            ">IIQ", data[offset : offset + 16]
        )
        offset += 16

        if version == 0x08:
            # v0x08: first 16 bytes of old-reserved = frame_mac_seed
            frame_mac_seed = data[offset : offset + 16]
            offset += 16
            reserved = data[offset : offset + 16]  # remaining 16 reserved bytes
        else:
            # v0x07 legacy: no explicit seed; use all-zeros placeholder
            # Frame MAC verification is unavailable for legacy GIFs.
            frame_mac_seed = b"\x00" * 16
            reserved = data[offset : offset + 32]

        return cls(
            magic=data[:4],
            version=version,
            flags=flags,
            salt_a=salt_a,
            salt_b=salt_b,
            nonce_a=nonce_a,
            nonce_b=nonce_b,
            reality_a_hmac=reality_a_hmac,
            reality_b_hmac=reality_b_hmac,
            metadata_a=metadata_a,
            metadata_b=metadata_b,
            block_count=block_count,
            block_size=block_size,
            superposition_len=superposition_len,
            frame_mac_seed=frame_mac_seed,
            reserved=reserved,
        )


def schrodinger_encode_data(
    real_data: bytes,
    decoy_data: bytes,
    real_password: str,
    decoy_password: str,
    block_size: int = 256,
) -> Tuple[bytes, SchrodingerManifest]:
    """
    Encode two secrets by interleaving their ciphertexts.

    All key material stays in opaque Rust handles — never enters Python.

    Args:
        real_data: Real secret bytes
        decoy_data: Decoy data bytes
        real_password: Password for real secret
        decoy_password: Password for decoy
        block_size: Block size for fountain coding

    Returns:
        (interleaved_ciphertext, manifest)
    """
    # Identical passwords break plausible deniability: the same key would
    # decrypt both realities, revealing that two secrets exist.
    if real_password == decoy_password:
        raise ValueError(
            "Real and decoy passwords must differ for Schrödinger mode "
            "to provide plausible deniability."
        )

    hb = get_handle_backend()

    # Generate salts, nonces, and frame MAC seed
    salt_a = secrets.token_bytes(16)
    salt_b = secrets.token_bytes(16)
    nonce_a = secrets.token_bytes(12)
    nonce_b = secrets.token_bytes(12)
    # Security: frame_mac_seed is a PUBLIC per-GIF nonce.  It is NOT a secret
    # and will be stored plaintext in the manifest.  Its sole purpose is to
    # make the frame-MAC master key unique per GIF so that frame MACs from one
    # session cannot be replayed into another.  Authentication is provided
    # by the Argon2id HMAC layer (reality_a/b_hmac), not by this seed.
    frame_mac_seed = secrets.token_bytes(16)

    # ── Encrypt both realities via handle-based API ──
    # Key NEVER enters Python memory.
    comp_a, sha_a, salt_enc_a, nonce_enc_a, cipher_a, key_handle_a = encrypt_file_bytes_handle(
        real_data, real_password, use_length_padding=True
    )

    comp_b, sha_b, salt_enc_b, nonce_enc_b, cipher_b, key_handle_b = encrypt_file_bytes_handle(
        decoy_data, decoy_password, use_length_padding=True
    )

    # Drop encryption key handles — we derive fresh metadata keys below
    hb.drop(key_handle_a)
    hb.drop(key_handle_b)

    # ── Interleave the two ciphertexts ──
    superposition = entangle_realities(cipher_a, cipher_b)

    # Split into blocks for fountain encoding
    blocks = [superposition[i : i + block_size] for i in range(0, len(superposition), block_size)]
    if blocks and len(blocks[-1]) < block_size:
        blocks[-1] += secrets.token_bytes(block_size - len(blocks[-1]))

    # ── Derive metadata keys via Argon2id → HKDF (all handle-based) ──
    master_meta_key_a = hb.derive_key_argon2id(
        real_password.encode("utf-8"),
        salt_a,
        memory_kib=ARGON2_MEMORY,
        iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    master_meta_key_b = hb.derive_key_argon2id(
        decoy_password.encode("utf-8"),
        salt_b,
        memory_kib=ARGON2_MEMORY,
        iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )

    # HKDF domain separation: separate enc and HMAC keys
    enc_key_a = hb.derive_key_hkdf(master_meta_key_a, salt_a, b"schrodinger_enc_key_v1", 32)
    hmac_key_a = hb.derive_key_hkdf(master_meta_key_a, salt_a, b"schrodinger_hmac_key_v1", 32)
    enc_key_b = hb.derive_key_hkdf(master_meta_key_b, salt_b, b"schrodinger_enc_key_v1", 32)
    hmac_key_b = hb.derive_key_hkdf(master_meta_key_b, salt_b, b"schrodinger_hmac_key_v1", 32)

    # ── Pack metadata payloads ──
    # Layout: orig_len(8) + comp_len(8) + cipher_len(8) + salt_enc(16) +
    #         nonce_enc(12) + sha256(32) + pad(4) = 88 bytes plaintext
    # AES-GCM adds 16-byte tag → 104 bytes ciphertext
    metadata_a_plain = (
        struct.pack(">QQQ", len(real_data), len(comp_a), len(cipher_a))
        + salt_enc_a
        + nonce_enc_a
        + sha_a
        + b"\x00" * 4
    )
    metadata_b_plain = (
        struct.pack(">QQQ", len(decoy_data), len(comp_b), len(cipher_b))
        + salt_enc_b
        + nonce_enc_b
        + sha_b
        + b"\x00" * 4
    )

    metadata_a_enc = hb.aes_gcm_encrypt(enc_key_a, nonce_a, metadata_a_plain, None)
    metadata_b_enc = hb.aes_gcm_encrypt(enc_key_b, nonce_b, metadata_b_plain, None)

    if len(metadata_a_enc) != 104 or len(metadata_b_enc) != 104:
        raise RuntimeError("Schrödinger metadata encryption produced unexpected length")

    # ── Compute manifest HMACs ──
    temp_manifest = SchrodingerManifest(
        salt_a=salt_a,
        salt_b=salt_b,
        nonce_a=nonce_a,
        nonce_b=nonce_b,
        reality_a_hmac=b"\x00" * 32,
        reality_b_hmac=b"\x00" * 32,
        metadata_a=metadata_a_enc,
        metadata_b=metadata_b_enc,
        block_count=len(blocks),
        block_size=block_size,
        superposition_len=len(superposition),
        frame_mac_seed=frame_mac_seed,
    )
    manifest_core = temp_manifest.pack_core_for_auth()

    hmac_a = hb.hmac_sha256(hmac_key_a, manifest_core)
    hmac_b = hb.hmac_sha256(hmac_key_b, manifest_core)

    # ── Drop all intermediate key handles (zeroize in Rust) ──
    for h in (master_meta_key_a, master_meta_key_b, enc_key_a, enc_key_b, hmac_key_a, hmac_key_b):
        try:
            hb.drop(h)
        except Exception:
            pass

    # ── Build final manifest ──
    manifest = SchrodingerManifest(
        salt_a=salt_a,
        salt_b=salt_b,
        nonce_a=nonce_a,
        nonce_b=nonce_b,
        reality_a_hmac=hmac_a,
        reality_b_hmac=hmac_b,
        metadata_a=metadata_a_enc,
        metadata_b=metadata_b_enc,
        block_count=len(blocks),
        block_size=block_size,
        superposition_len=len(superposition),
        frame_mac_seed=frame_mac_seed,
    )

    interleaved_ciphertext = b"".join(blocks)
    return interleaved_ciphertext, manifest


def schrodinger_encode_file(
    real_input: Path,
    decoy_input: Optional[Path],
    output: Path,
    real_password: str,
    decoy_password: str,
    config: Optional[EncodingConfig] = None,
    auto_generate_decoy: bool = True,
    verbose: bool = False,
) -> dict:
    """
    Encode files in Schrödinger mode.

    All cryptographic keys stay inside opaque Rust handles.

    Args:
        real_input: Path to the real secret file
        decoy_input: Path to the decoy file (or None for auto-generation)
        output: Path to write the output GIF
        real_password: Password for the real secret
        decoy_password: Password for the decoy
        config: Encoding configuration (optional)
        auto_generate_decoy: Generate a decoy if none provided
        verbose: Print progress to stdout

    Returns:
        dict with encoding statistics
    """
    if config is None:
        config = EncodingConfig()

    if verbose:
        print("🐱⚛️  Schrödinger's Yarn Ball - Quantum Encoder v6.0.0")
        print("=" * 60)
        print("  All keys stay in Rust handles — zero Python key exposure")
        print("=" * 60)

    # Load real file
    with open(real_input, "rb") as f:
        real_data = f.read()
    if verbose:
        print(f"\n📄 Reality A (Real): {len(real_data):,} bytes")

    # Load or generate decoy
    if decoy_input:
        with open(decoy_input, "rb") as f:
            decoy_data = f.read()
        if verbose:
            print(f"📄 Reality B (Decoy - provided): {len(decoy_data):,} bytes")
    elif auto_generate_decoy:
        target_size = len(real_data) + secrets.randbelow(20000) - 10000
        target_size = max(10000, target_size)
        decoy_data = generate_convincing_decoy(target_size)
        if verbose:
            print(f"📄 Reality B (Decoy - auto): {len(decoy_data):,} bytes")
    else:
        raise ValueError("Must provide decoy or enable auto_generate_decoy")

    # Encode
    if verbose:
        print("\n⚛️  Creating quantum superposition...")

    mixed, manifest = schrodinger_encode_data(
        real_data, decoy_data, real_password, decoy_password, config.block_size
    )

    if verbose:
        print(f"✅ Superposition created: {len(mixed):,} bytes")
        print(f"   Blocks: {manifest.block_count}")

    # Fountain encode
    if verbose:
        print("\n🌊 Fountain encoding...")

    k_blocks = manifest.block_count
    num_droplets = int(k_blocks * config.redundancy)

    if verbose:
        print(f"   k={k_blocks}, droplets={num_droplets}")

    fountain = FountainEncoder(mixed, k_blocks, config.block_size)
    droplets = fountain.generate_droplets(num_droplets)

    # ── Pack frames with frame MACs ──
    # Security: the frame-MAC master key is derived SOLELY from the public
    # frame_mac_seed stored in the manifest, NOT from either password.
    #
    # Rationale (fixes Bug 2 / Bug 6):
    #   - Old design used SHA-256(real_password) — tied MACs to one reality,
    #     allowing decoy users to be identified, and leaking secret bytes Python.
    #   - New design: seed is a random public nonce generated at encode time and
    #     stored plaintext in the manifest.  Anyone who can read the manifest
    #     (i.e. anyone who has the QR GIF) can verify frame MACs.
    #   - Frame MACs are DoS filters only; content authentication is provided
    #     by the Argon2id HMAC fields (reality_a_hmac / reality_b_hmac).
    #   - No secret material ever enters Python memory for this path.
    backend = get_default_backend()
    # frame_mac_seed is NOT secret — safe to have in Python bytes.
    frame_mac_master = backend.sha256(manifest.frame_mac_seed + _FRAME_MAC_SEED_INFO)
    # Import into handle purely to feed the existing handle-based pack_frame_with_mac API.
    # This is not a secret; the handle just avoids re-imports per frame.
    hb = get_handle_backend()
    master_key = hb.import_key(frame_mac_master)
    del frame_mac_master  # not secret but let's be tidy

    manifest_bytes = manifest.pack()
    manifest_with_mac = pack_frame_with_mac(manifest_bytes, master_key, 0, manifest.frame_mac_seed)

    qr_data_list = [manifest_with_mac]
    for i, droplet in enumerate(droplets, 1):
        droplet_bytes = pack_droplet(droplet)
        droplet_with_mac = pack_frame_with_mac(
            droplet_bytes, master_key, i, manifest.frame_mac_seed
        )
        qr_data_list.append(droplet_with_mac)

    hb.drop(master_key)

    if verbose:
        print(f"\n📱 Generating QR codes ({len(qr_data_list)} frames)...")

    # Generate QR
    qr_gen = QRCodeGenerator(
        error_correction=config.qr_error_correction,
        box_size=config.qr_box_size,
        border=config.qr_border,
    )
    qr_frames = qr_gen.generate_batch(qr_data_list)

    # Create GIF
    if verbose:
        print("\n🎬 Creating GIF...")

    gif_encoder = GIFEncoder(fps=config.fps)
    gif_size = gif_encoder.create_gif(qr_frames, output, optimize=False)

    if verbose:
        print(f"✅ GIF created: {gif_size:,} bytes")
        print(f"\n⚛️  QUANTUM SUPERPOSITION COMPLETE")
        print(f"   Both realities exist simultaneously")
        print(f"   Password observation will collapse to ONE")

    return {
        "real_size": len(real_data),
        "decoy_size": len(decoy_data),
        "mixed_size": len(mixed),
        "blocks": manifest.block_count,
        "qr_frames": len(qr_data_list),
        "gif_size": gif_size,
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="🐱⚛️ Schrödinger's Yarn Ball Encoder v6.0.0",
    )
    parser.add_argument("--real", required=True, help="Real secret file")
    parser.add_argument("--decoy", help="Decoy file (auto-generated if omitted)")
    parser.add_argument("-o", "--output", required=True, help="Output GIF")
    parser.add_argument("--real-password", help="Real password")
    parser.add_argument("--decoy-password", help="Decoy password")
    parser.add_argument("--block-size", type=int, default=256)
    parser.add_argument("--redundancy", type=float, default=1.5)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full traceback on error (avoid in coercion scenarios)",
    )

    args = parser.parse_args()

    real_pw = args.real_password or getpass("Real password: ")
    decoy_pw = args.decoy_password or getpass("Decoy password: ")

    config = EncodingConfig(block_size=args.block_size, redundancy=args.redundancy)

    try:
        stats = schrodinger_encode_file(
            Path(args.real),
            Path(args.decoy) if args.decoy else None,
            Path(args.output),
            real_pw,
            decoy_pw,
            config,
            auto_generate_decoy=True,
            verbose=args.verbose,
        )
        if not args.verbose:
            print(f"✅ Quantum superposition: {stats['gif_size']:,} bytes")
            print(f"   {stats['qr_frames']} frames | {stats['blocks']} blocks")
        return 0
    except Exception:
        # Security (Bug 7): never print full tracebacks by default.
        # Tracebacks expose file paths and internals; use --debug for diagnostics.
        print(f"\n\u274c Encoding failed: invalid input or internal error", file=sys.stderr)
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
