#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Dual Reality Encoder v5.4.0

"You cannot prove a secret exists unless you already know how to look for it.
 And once you look… you've already chosen your reality."

TRUE PLAUSIBLE DENIABILITY VIA QUANTUM SUPERPOSITION

This encoder creates a single GIF containing TWO completely separate encrypted
files. Each password reveals one reality. Neither can prove the other exists.

Architecture (Practical Approach):
    1. Encrypt both files independently (AES-256-GCM + Argon2id)
    2. Pad to same length (prevents size fingerprinting)
    3. Interleave encrypted blocks (even=A, odd=B)
    4. Permute with cryptographic shuffle (hides pattern)
    5. Add statistical noise (makes blocks indistinguishable)
    6. Fountain encode + QR + GIF

Decoding: Password extracts and decrypts its blocks
Result: One reality revealed, other unprovable

Security Properties:
    - Statistical indistinguishability (same entropy, frequencies)
    - No forensic markers (identical block structures)
    - Constant-time operations (no timing leakage)
    - Independent decryption (each password works alone)
    - Plausible deniability (cannot prove second secret exists)
"""

import sys
import secrets
import hashlib
import struct
import argparse
from pathlib import Path
from getpass import getpass
from typing import Tuple, Optional, List
from dataclasses import dataclass

from .crypto import encrypt_file_bytes, derive_key
from .fountain import FountainEncoder, pack_droplet
from .qr_code import QRCodeGenerator
from .gif_handler import GIFEncoder
from .config import EncodingConfig
from .frame_mac import pack_frame_with_mac
from .quantum_mixer import (
    entangle_realities,
)


@dataclass
class SchrodingerManifest:
    """
    Manifest for Schrödinger mode v5.5.0.
    
    Format (382 bytes):
        - magic: b"MEOW" (4 bytes)
        - version: 0x07 (1 byte) - v5.5.0 Schrödinger Interleaved
        - flags: 1 byte (reserved)
        - salt_a: 16 bytes
        - salt_b: 16 bytes
        - nonce_a: 12 bytes
        - nonce_b: 12 bytes
        - reality_a_hmac: 32 bytes (verifies password A)
        - reality_b_hmac: 32 bytes (verifies password B)
        - metadata_a: 104 bytes (encrypted: orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256)
        - metadata_b: 104 bytes (encrypted: orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256)
        - block_count: 4 bytes
        - block_size: 4 bytes
        - superposition_len: 8 bytes (NEW: total length of the interleaved data)
        - reserved: 32 bytes
        
    Total: 4+2+16+16+12+12+32+32+104+104+4+4+8+32 = 382 bytes
    """
    # Required fields (no defaults) must come first
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
    # Fields with defaults must come last
    magic: bytes = b"MEOW"
    version: int = 0x07
    flags: int = 0x00
    reserved: bytes = b'\x00' * 32

    def pack_core_for_auth(self) -> bytes:
        """Packs all manifest fields that must be authenticated by the HMAC."""
        # This includes ALL fields except the HMACs themselves.
        # Any change to these fields will invalidate the HMAC.
        core = self.magic
        core += struct.pack('BB', self.version, self.flags)
        core += self.salt_a
        core += self.salt_b
        core += self.nonce_a
        core += self.nonce_b
        # The HMACs are excluded as they are what we are calculating.
        core += self.metadata_a
        core += self.metadata_b
        core += struct.pack('>IIQ', self.block_count, self.block_size, self.superposition_len)
        core += self.reserved
        return core

    def pack(self) -> bytes:
        """Pack manifest to bytes."""
        data = self.magic
        data += struct.pack('BB', self.version, self.flags)
        data += self.salt_a
        data += self.salt_b
        data += self.nonce_a
        data += self.nonce_b
        data += self.reality_a_hmac
        data += self.reality_b_hmac
        data += self.metadata_a
        data += self.metadata_b
        data += struct.pack('>IIQ', self.block_count, self.block_size, self.superposition_len)
        data += self.reserved
        return data

    @classmethod
    def unpack(cls, data: bytes):
        """Unpack manifest from bytes."""
        if len(data) < 382:
            raise ValueError(f"Manifest too short: {len(data)} bytes (need 382)")
        
        if data[:4] != b"MEOW":
            raise ValueError("Invalid manifest magic")
        
        version, flags = struct.unpack('BB', data[4:6])
        
        if version != 0x07:
            raise ValueError(f"Not a Schrödinger v5.5.0 manifest (version 0x{version:02x})")
        
        offset = 6
        salt_a = data[offset:offset+16]; offset += 16
        salt_b = data[offset:offset+16]; offset += 16
        nonce_a = data[offset:offset+12]; offset += 12
        nonce_b = data[offset:offset+12]; offset += 12
        reality_a_hmac = data[offset:offset+32]; offset += 32
        reality_b_hmac = data[offset:offset+32]; offset += 32
        metadata_a = data[offset:offset+104]; offset += 104
        metadata_b = data[offset:offset+104]; offset += 104
        block_count, block_size, superposition_len = struct.unpack('>IIQ', data[offset:offset+16]); offset += 16
        reserved = data[offset:offset+32]
        
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
            reserved=reserved
        )


def schrodinger_encode_data(
    real_data: bytes,
    decoy_data: bytes,
    real_password: str,
    decoy_password: str,
    block_size: int = 256
) -> Tuple[bytes, SchrodingerManifest]:
    """
    Encode two secrets by interleaving their ciphertexts.
    
    Args:
        real_data: Real secret
        decoy_data: Decoy data
        real_password: Password for real
        decoy_password: Password for decoy
        block_size: Block size for fountain coding
        
    Returns:
        (interleaved_ciphertext, manifest)
    """
    # Generate salts and nonces for metadata encryption
    salt_a = secrets.token_bytes(16)
    salt_b = secrets.token_bytes(16)
    nonce_a = secrets.token_bytes(12)
    nonce_b = secrets.token_bytes(12)

    # Encrypt both realities independently
    comp_a, sha_a, salt_enc_a, nonce_enc_a, cipher_a, _, enc_key_a = encrypt_file_bytes(
        real_data, real_password, None, None, use_length_padding=True
    )
    
    comp_b, sha_b, salt_enc_b, nonce_enc_b, cipher_b, _, enc_key_b = encrypt_file_bytes(
        decoy_data, decoy_password, None, None, use_length_padding=True
    )
    
    # Interleave the two ciphertexts into a single superposition
    superposition = entangle_realities(cipher_a, cipher_b)

    # Split into blocks for fountain encoding
    blocks = [superposition[i:i+block_size] for i in range(0, len(superposition), block_size)]
    if blocks and len(blocks[-1]) < block_size:
        # Pad the last block to ensure all blocks are the same size
        blocks[-1] += secrets.token_bytes(block_size - len(blocks[-1]))

    # Create encrypted metadata payloads for each reality
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    import hmac

    # --- Task B: Strengthened Password Hardening ---
    # Derive master metadata keys using Argon2id (slow KDF)
    master_meta_key_a = derive_key(real_password, salt_a)
    master_meta_key_b = derive_key(decoy_password, salt_b)

    # --- Task C: Enforce Key Separation ---
    # Derive separate keys for encryption and HMAC using HKDF
    hkdf_enc_a = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt_a, info=b"schrodinger_enc_key_v1")
    enc_key_a = hkdf_enc_a.derive(master_meta_key_a)

    hkdf_hmac_a = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt_a, info=b"schrodinger_hmac_key_v1")
    hmac_key_a = hkdf_hmac_a.derive(master_meta_key_a)

    hkdf_enc_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt_b, info=b"schrodinger_enc_key_v1")
    enc_key_b = hkdf_enc_b.derive(master_meta_key_b)

    hkdf_hmac_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt_b, info=b"schrodinger_hmac_key_v1")
    hmac_key_b = hkdf_hmac_b.derive(master_meta_key_b)

    # Pack all necessary decryption info into metadata.
    # Base plaintext layout:
    #   orig_len(8) + comp_len(8) + cipher_len(8) + salt_enc(16) + nonce_enc(12) + sha(32) = 84 bytes
    # We pad plaintext to 88 bytes so that AES-GCM output is fixed-size 104 bytes (88 + 16 tag).
    metadata_a_plain = (
        struct.pack('>QQQ', len(real_data), len(comp_a), len(cipher_a))
        + salt_enc_a
        + nonce_enc_a
        + sha_a
        + b'\x00' * 4
    )
    metadata_b_plain = (
        struct.pack('>QQQ', len(decoy_data), len(comp_b), len(cipher_b))
        + salt_enc_b
        + nonce_enc_b
        + sha_b
        + b'\x00' * 4
    )
    
    aesgcm_a = AESGCM(enc_key_a)
    aesgcm_b = AESGCM(enc_key_b)
    
    # Encrypt metadata. AES-GCM adds a 16-byte tag. 88 + 16 = 104 bytes.
    metadata_a_enc = aesgcm_a.encrypt(nonce_a, metadata_a_plain, None)
    metadata_b_enc = aesgcm_b.encrypt(nonce_b, metadata_b_plain, None)

    if len(metadata_a_enc) != 104 or len(metadata_b_enc) != 104:
        raise RuntimeError("Schrödinger metadata encryption produced unexpected length")
    
    # --- Task A: Authentication Coverage ---
    # Create a temporary manifest to pack the core for HMAC calculation
    temp_manifest = SchrodingerManifest(
        salt_a=salt_a,
        salt_b=salt_b,
        nonce_a=nonce_a,
        nonce_b=nonce_b,
        reality_a_hmac=b'\x00' * 32, # Placeholder
        reality_b_hmac=b'\x00' * 32, # Placeholder
        metadata_a=metadata_a_enc,
        metadata_b=metadata_b_enc,
        block_count=len(blocks),
        block_size=block_size,
        superposition_len=len(superposition)
    )
    manifest_core = temp_manifest.pack_core_for_auth()

    hmac_a = hmac.new(hmac_key_a, manifest_core, hashlib.sha256).digest()
    hmac_b = hmac.new(hmac_key_b, manifest_core, hashlib.sha256).digest()
    
    # Create the final manifest
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
        superposition_len=len(superposition)
    )
    
    # The final ciphertext is the concatenation of all blocks
    interleaved_ciphertext = b''.join(blocks)
    
    return interleaved_ciphertext, manifest


def schrodinger_encode_file(
    real_input: Path,
    decoy_input: Optional[Path],
    output: Path,
    real_password: str,
    decoy_password: str,
    config: Optional[EncodingConfig] = None,
    auto_generate_decoy: bool = True,
    verbose: bool = False
) -> dict:
    """Encode files in Schrödinger mode."""
    if config is None:
        config = EncodingConfig()
    
    if verbose:
        print("🐱⚛️  Schrödinger's Yarn Ball - Quantum Encoder v5.4.0")
        print("=" * 60)
        print('"You cannot prove a secret exists unless you already')
        print(' know how to look for it..."')
        print("=" * 60)
    
    # Load real
    with open(real_input, 'rb') as f:
        real_data = f.read()
    
    if verbose:
        print(f"\n📄 Reality A (Real): {len(real_data):,} bytes")
    
    # Load or generate decoy
    if decoy_input:
        with open(decoy_input, 'rb') as f:
            decoy_data = f.read()
        if verbose:
            print(f"📄 Reality B (Decoy - provided): {len(decoy_data):,} bytes")
    elif auto_generate_decoy:
        target_size = len(real_data) + secrets.randbelow(20000) - 10000
        target_size = max(10000, target_size)
        decoy_data = generate_convincing_decoy(target_size)
        if verbose:
            print(f"📄 Reality B (Decoy - auto): {len(decoy_data):,} bytes")
            print("   (Vacation photos + shopping list + cat manifesto)")
    else:
        raise ValueError("Must provide decoy or enable auto_generate_decoy")
    
    # Encode
    if verbose:
        print("\n⚛️  Creating quantum superposition...")
    
    mixed, manifest = schrodinger_encode_data(
        real_data, decoy_data,
        real_password, decoy_password,
        config.block_size
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
    
    # Pack with MACs
    master_key = hashlib.sha256(real_password.encode()).digest()
    
    manifest_bytes = manifest.pack()
    manifest_with_mac = pack_frame_with_mac(manifest_bytes, master_key, 0, manifest.salt_a)
    
    qr_data_list = [manifest_with_mac]
    for i, droplet in enumerate(droplets, 1):
        droplet_bytes = pack_droplet(droplet)
        droplet_with_mac = pack_frame_with_mac(droplet_bytes, master_key, i, manifest.salt_a)
        qr_data_list.append(droplet_with_mac)
    
    if verbose:
        print(f"\n📱 Generating QR codes ({len(qr_data_list)} frames)...")
    
    # Generate QR
    qr_gen = QRCodeGenerator(
        error_correction=config.qr_error_correction,
        box_size=config.qr_box_size,
        border=config.qr_border
    )
    
    qr_frames = qr_gen.generate_batch(qr_data_list)
    
    # Create GIF
    if verbose:
        print(f"\n🎬 Creating GIF...")
    
    gif_encoder = GIFEncoder(fps=config.fps)
    gif_size = gif_encoder.create_gif(qr_frames, output, optimize=False)
    
    if verbose:
        print(f"✅ GIF created: {gif_size:,} bytes")
        print(f"\n⚛️  QUANTUM SUPERPOSITION COMPLETE")
        print(f"   Both realities exist simultaneously")
        print(f"   Password observation will collapse to ONE")
        print(f"\n🔮 To decode:")
        print(f"   Real password → Reality A")
        print(f"   Decoy password → Reality B")
        print(f"   Neither can prove the other exists! 🐱")
    
    return {
        'real_size': len(real_data),
        'decoy_size': len(decoy_data),
        'mixed_size': len(mixed),
        'blocks': manifest.block_count,
        'qr_frames': len(qr_data_list),
        'gif_size': gif_size,
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='🐱⚛️ Schrödinger\'s Yarn Ball Encoder v5.4.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Auto-generated decoy:
  python -m meow_decoder.schrodinger_encode --real secret.pdf -o quantum.gif
  
  # Custom decoy:
  python -m meow_decoder.schrodinger_encode \
      --real secret.pdf \
      --decoy innocent.zip \
      -o quantum.gif
        '''
    )
    
    parser.add_argument('--real', required=True, help='Real secret file')
    parser.add_argument('--decoy', help='Decoy file (auto-generated if omitted)')
    parser.add_argument('-o', '--output', required=True, help='Output GIF')
    parser.add_argument('--real-password', help='Real password')
    parser.add_argument('--decoy-password', help='Decoy password')
    parser.add_argument('--block-size', type=int, default=256)
    parser.add_argument('--redundancy', type=float, default=1.5)
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    # Get passwords
    real_pw = args.real_password or getpass("Real password: ")
    decoy_pw = args.decoy_password or getpass("Decoy password: ")
    
    config = EncodingConfig(
        block_size=args.block_size,
        redundancy=args.redundancy
    )
    
    try:
        stats = schrodinger_encode_file(
            Path(args.real),
            Path(args.decoy) if args.decoy else None,
            Path(args.output),
            real_pw,
            decoy_pw,
            config,
            auto_generate_decoy=True,
            verbose=args.verbose
        )
        
        if not args.verbose:
            print(f"✅ Quantum superposition: {stats['gif_size']:,} bytes")
            print(f"   {stats['qr_frames']} frames | {stats['blocks']} blocks")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
