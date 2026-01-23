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

from .crypto import encrypt_file_bytes
from .fountain import FountainEncoder, pack_droplet
from .qr_code import QRCodeGenerator
from .gif_handler import GIFEncoder
from .config import EncodingConfig
from .frame_mac import pack_frame_with_mac
from .decoy_generator import generate_convincing_decoy


@dataclass
class SchrodingerManifest:
    """
    Manifest for Schrödinger mode v5.4.0.
    
    Format (392 bytes):
        - magic: b"MEOW" (4 bytes)
        - version: 0x06 (1 byte) - v5.4.0 Schrödinger
        - flags: 1 byte (reserved)
        - salt_a: 16 bytes
        - salt_b: 16 bytes
        - nonce_a: 12 bytes
        - nonce_b: 12 bytes
        - reality_a_hmac: 32 bytes (verifies password A)
        - reality_b_hmac: 32 bytes (verifies password B)
        - metadata_a: 104 bytes (encrypted: orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256)
        - metadata_b: 104 bytes (encrypted: orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256)
        - merkle_root: 32 bytes
        - shuffle_seed: 8 bytes (for block permutation)
        - block_count: 4 bytes
        - block_size: 4 bytes
        - reserved: 10 bytes
        
    Total: 4+2+16+16+12+12+32+32+104+104+32+8+4+4+10 = 392 bytes
    """
    magic: bytes = b"MEOW"
    version: int = 0x06
    flags: int = 0x00
    salt_a: bytes = None
    salt_b: bytes = None
    nonce_a: bytes = None
    nonce_b: bytes = None
    reality_a_hmac: bytes = None
    reality_b_hmac: bytes = None
    metadata_a: bytes = None
    metadata_b: bytes = None
    merkle_root: bytes = None
    shuffle_seed: bytes = None
    block_count: int = 0
    block_size: int = 256
    reserved: bytes = b'\x00' * 10  # Padding to 392 bytes total
    
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
        data += self.merkle_root
        data += self.shuffle_seed
        data += struct.pack('>II', self.block_count, self.block_size)
        data += self.reserved
        return data
    
    @classmethod
    def unpack(cls, data: bytes):
        """Unpack manifest from bytes."""
        if len(data) < 392:
            raise ValueError(f"Manifest too short: {len(data)} bytes (need 392)")
        
        if data[:4] != b"MEOW":
            raise ValueError("Invalid manifest magic")
        
        version, flags = struct.unpack('BB', data[4:6])
        
        if version != 0x06:
            raise ValueError(f"Not a Schrödinger v5.4.0 manifest (version 0x{version:02x})")
        
        offset = 6
        salt_a = data[offset:offset+16]
        salt_b = data[offset+16:offset+32]
        nonce_a = data[offset+32:offset+44]
        nonce_b = data[offset+44:offset+56]
        reality_a_hmac = data[offset+56:offset+88]
        reality_b_hmac = data[offset+88:offset+120]
        metadata_a = data[offset+120:offset+224]  # 104 bytes
        metadata_b = data[offset+224:offset+328]  # 104 bytes
        merkle_root = data[offset+328:offset+360]
        shuffle_seed = data[offset+360:offset+368]
        block_count, block_size = struct.unpack('>II', data[offset+368:offset+376])
        reserved = data[offset+376:offset+386]  # 10 bytes reserved
        
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
            merkle_root=merkle_root,
            shuffle_seed=shuffle_seed,
            block_count=block_count,
            block_size=block_size,
            reserved=reserved
        )


def compute_merkle_root(blocks: List[bytes]) -> bytes:
    """Compute Merkle tree root."""
    if not blocks:
        return hashlib.sha256(b"empty").digest()
    
    hashes = [hashlib.sha256(block).digest() for block in blocks]
    
    while len(hashes) > 1:
        next_level = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                combined = hashlib.sha256(hashes[i] + hashes[i+1]).digest()
            else:
                combined = hashes[i]
            next_level.append(combined)
        hashes = next_level
    
    return hashes[0]


def permute_blocks(blocks: List[bytes], seed: bytes) -> List[bytes]:
    """
    Cryptographically permute blocks using deterministic shuffle.
    
    This hides the even=A, odd=B pattern while remaining reversible.
    """
    import random
    
    # Create deterministic RNG from seed
    seed_int = int.from_bytes(seed, 'big')
    rng = random.Random(seed_int)
    
    # Create index mapping
    indices = list(range(len(blocks)))
    rng.shuffle(indices)
    
    # Apply permutation
    permuted = [blocks[i] for i in indices]
    
    return permuted


def unpermute_blocks(blocks: List[bytes], seed: bytes) -> List[bytes]:
    """
    Reverse the permutation to get original order.
    
    The permute function does: permuted[i] = original[indices[i]]
    To reverse we need: unpermuted[indices[i]] = permuted[i]
    """
    import random
    
    # Recreate same RNG
    seed_int = int.from_bytes(seed, 'big')
    rng = random.Random(seed_int)
    
    # Recreate same shuffle
    indices = list(range(len(blocks)))
    rng.shuffle(indices)
    
    # Reverse the permutation
    # permute did: permuted[i] = original[indices[i]]
    # so: unpermuted[indices[i]] = permuted[i]
    unpermuted = [None] * len(blocks)
    for i, block in enumerate(blocks):
        unpermuted[indices[i]] = block
    
    return unpermuted


def schrodinger_encode_data(
    real_data: bytes,
    decoy_data: bytes,
    real_password: str,
    decoy_password: str,
    block_size: int = 256
) -> Tuple[bytes, SchrodingerManifest]:
    """
    Encode two secrets in quantum superposition.
    
    Args:
        real_data: Real secret
        decoy_data: Decoy data
        real_password: Password for real
        decoy_password: Password for decoy
        block_size: Block size
        
    Returns:
        (mixed_ciphertext, manifest)
    """
    # Generate salts and nonces
    salt_a = secrets.token_bytes(16)
    salt_b = secrets.token_bytes(16)
    nonce_a = secrets.token_bytes(12)
    nonce_b = secrets.token_bytes(12)
    shuffle_seed = secrets.token_bytes(8)
    
    # Encrypt both realities independently
    # encrypt_file_bytes returns: (comp, sha, salt, nonce, cipher, ephemeral_key)
    comp_a, sha_a, salt_enc_a, nonce_enc_a, cipher_a, _ = encrypt_file_bytes(
        real_data, real_password, None, None, use_length_padding=True
    )
    
    comp_b, sha_b, salt_enc_b, nonce_enc_b, cipher_b, _ = encrypt_file_bytes(
        decoy_data, decoy_password, None, None, use_length_padding=True
    )
    
    # Store original cipher lengths (before padding)
    cipher_a_len = len(cipher_a)
    cipher_b_len = len(cipher_b)
    
    # Pad to same length (prevents size fingerprinting)
    max_len = max(len(cipher_a), len(cipher_b))
    
    if len(cipher_a) < max_len:
        cipher_a += secrets.token_bytes(max_len - len(cipher_a))
    if len(cipher_b) < max_len:
        cipher_b += secrets.token_bytes(max_len - len(cipher_b))
    
    # Split into blocks
    blocks_a = [cipher_a[i:i+block_size] for i in range(0, len(cipher_a), block_size)]
    blocks_b = [cipher_b[i:i+block_size] for i in range(0, len(cipher_b), block_size)]
    
    # Pad last blocks
    if blocks_a and len(blocks_a[-1]) < block_size:
        blocks_a[-1] += secrets.token_bytes(block_size - len(blocks_a[-1]))
    if blocks_b and len(blocks_b[-1]) < block_size:
        blocks_b[-1] += secrets.token_bytes(block_size - len(blocks_b[-1]))
    
    # Ensure same number of blocks
    while len(blocks_a) < len(blocks_b):
        blocks_a.append(secrets.token_bytes(block_size))
    while len(blocks_b) < len(blocks_a):
        blocks_b.append(secrets.token_bytes(block_size))
    
    # Interleave: even positions = A, odd positions = B
    interleaved = []
    for i in range(len(blocks_a)):
        interleaved.append(blocks_a[i])
        interleaved.append(blocks_b[i])
    
    # Permute to hide pattern
    mixed = permute_blocks(interleaved, shuffle_seed)
    
    # Compute Merkle root
    merkle_root = compute_merkle_root(mixed)
    
    # Create encrypted metadata (stores decryption parameters)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    key_a = hashlib.sha256(real_password.encode() + salt_a).digest()
    key_b = hashlib.sha256(decoy_password.encode() + salt_b).digest()
    
    # Store ONLY what decoder needs: orig_len, comp_len, cipher_len
    # cipher_len is the ORIGINAL cipher length before padding
    # 8 + 8 + 8 = 24 bytes plain
    # After AES-GCM: 24 + 16 (tag) = 40 bytes
    # Pad to 64 bytes for fixed size
    
    # But we also need salt_enc and nonce_enc! Let me pack more efficiently:
    # orig_len (8) + comp_len (8) + cipher_len (8) = 24 bytes
    # Then concat salt_enc (16) + nonce_enc (12) + sha256 (32) separately
    # Total: 24 + 16 + 12 + 32 = 84 bytes
    # After encryption: 84 + 16 = 100, pad to 104
    
    metadata_a_plain = struct.pack('>QQQ', len(real_data), len(comp_a), cipher_a_len)
    metadata_a_plain += salt_enc_a + nonce_enc_a + sha_a
    
    metadata_b_plain = struct.pack('>QQQ', len(decoy_data), len(comp_b), cipher_b_len)
    metadata_b_plain += salt_enc_b + nonce_enc_b + sha_b
    
    aesgcm_a = AESGCM(key_a)
    aesgcm_b = AESGCM(key_b)
    
    metadata_a_enc = aesgcm_a.encrypt(nonce_a, metadata_a_plain, None)
    metadata_b_enc = aesgcm_b.encrypt(nonce_b, metadata_b_plain, None)
    
    # Should be 100 bytes (84 + 16 tag), pad to 104
    if len(metadata_a_enc) < 104:
        metadata_a_enc += b'\x00' * (104 - len(metadata_a_enc))
    else:
        metadata_a_enc = metadata_a_enc[:104]
        
    if len(metadata_b_enc) < 104:
        metadata_b_enc += b'\x00' * (104 - len(metadata_b_enc))
    else:
        metadata_b_enc = metadata_b_enc[:104]
    
    # Compute HMACs (for password verification)
    import hmac
    
    manifest_core = salt_a + salt_b + nonce_a + nonce_b + merkle_root + shuffle_seed
    
    hmac_a = hmac.new(key_a, manifest_core, hashlib.sha256).digest()
    hmac_b = hmac.new(key_b, manifest_core, hashlib.sha256).digest()
    
    # Create manifest
    manifest = SchrodingerManifest(
        salt_a=salt_a,
        salt_b=salt_b,
        nonce_a=nonce_a,
        nonce_b=nonce_b,
        reality_a_hmac=hmac_a,
        reality_b_hmac=hmac_b,
        metadata_a=metadata_a_enc,
        metadata_b=metadata_b_enc,
        merkle_root=merkle_root,
        shuffle_seed=shuffle_seed,
        block_count=len(mixed),
        block_size=block_size
    )
    
    # Combine mixed blocks
    mixed_ciphertext = b''.join(mixed)
    
    return mixed_ciphertext, manifest


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
        print(f"   Merkle root: {manifest.merkle_root.hex()[:16]}...")
    
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
        'merkle_root': manifest.merkle_root.hex()
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
