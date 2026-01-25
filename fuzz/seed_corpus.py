#!/usr/bin/env python3
"""
Seed corpus generator for fuzzing.
Creates valid samples that fuzzers can mutate.
"""

import os
import sys
import struct
import secrets
import argparse
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def generate_manifest_samples(output_dir: Path, count: int = 20):
    """Generate valid manifest samples for fuzzing."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    from meow_decoder.crypto import MAGIC, Manifest, pack_manifest
    
    for i in range(count):
        # Generate random but valid manifest
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=secrets.randbelow(1000000),
            comp_len=secrets.randbelow(500000),
            cipher_len=secrets.randbelow(500000),
            sha256=secrets.token_bytes(32),
            block_size=256 + secrets.randbelow(1024),
            k_blocks=1 + secrets.randbelow(1000),
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32) if i % 2 == 0 else None
        )
        
        packed = pack_manifest(manifest)
        
        with open(output_dir / f"manifest_{i:03d}.bin", "wb") as f:
            f.write(packed)
    
    # Also add some edge cases
    edge_cases = [
        b"MEOW3" + b"\x00" * 110,  # Minimal valid-ish
        b"MEOW2" + b"\x00" * 110,  # Old version
        b"MEOW3" + secrets.token_bytes(142),  # With FS
        b"MEOW3" + secrets.token_bytes(1230),  # With PQ
        b"",  # Empty
        b"MEOW",  # Truncated magic
        b"X" * 1000,  # Random garbage
    ]
    
    for i, case in enumerate(edge_cases):
        with open(output_dir / f"edge_case_{i:03d}.bin", "wb") as f:
            f.write(case)
    
    print(f"✅ Generated {count + len(edge_cases)} manifest samples in {output_dir}")


def generate_fountain_samples(output_dir: Path, count: int = 20):
    """Generate valid fountain droplet samples for fuzzing."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    from meow_decoder.fountain import Droplet, pack_droplet
    
    for i in range(count):
        # Generate random but valid droplet
        block_size = 256 + secrets.randbelow(512)
        num_indices = 1 + secrets.randbelow(10)
        
        droplet = Droplet(
            seed=secrets.randbelow(2**32),
            block_indices=sorted(set(secrets.randbelow(1000) for _ in range(num_indices))),
            data=secrets.token_bytes(block_size)
        )
        
        packed = pack_droplet(droplet)
        
        with open(output_dir / f"droplet_{i:03d}.bin", "wb") as f:
            f.write(packed)
    
    # Edge cases
    edge_cases = [
        b"",  # Empty
        struct.pack(">I", 0) + struct.pack(">H", 0),  # Zero indices
        struct.pack(">I", 12345) + struct.pack(">H", 65535),  # Max indices
        secrets.token_bytes(10),  # Truncated
        secrets.token_bytes(10000),  # Large
    ]
    
    for i, case in enumerate(edge_cases):
        with open(output_dir / f"droplet_edge_{i:03d}.bin", "wb") as f:
            f.write(case)
    
    print(f"✅ Generated {count + len(edge_cases)} fountain samples in {output_dir}")


def generate_crypto_samples(output_dir: Path, count: int = 10):
    """Generate samples for crypto fuzzing."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for i in range(count):
        # Random ciphertext-like data
        size = 100 + secrets.randbelow(10000)
        data = secrets.token_bytes(size)
        
        with open(output_dir / f"crypto_{i:03d}.bin", "wb") as f:
            f.write(data)
    
    print(f"✅ Generated {count} crypto samples in {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Generate fuzz corpus")
    parser.add_argument("--afl", action="store_true", help="Generate for AFL++")
    parser.add_argument("--output", type=Path, default=Path("fuzz/corpus"),
                       help="Output directory")
    args = parser.parse_args()
    
    if args.afl:
        # AFL uses single directory
        output_dir = Path("fuzz/afl-corpus")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate all samples in one dir
        from meow_decoder.crypto import MAGIC, Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=500,
            cipher_len=516,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=10,
            hmac=secrets.token_bytes(32)
        )
        
        with open(output_dir / "sample_manifest.bin", "wb") as f:
            f.write(pack_manifest(manifest))
        
        print(f"✅ Generated AFL corpus in {output_dir}")
    else:
        # Atheris uses separate directories
        generate_manifest_samples(args.output / "manifest")
        generate_fountain_samples(args.output / "fountain")
        generate_crypto_samples(args.output / "manifest")  # Reuse dir


if __name__ == "__main__":
    main()
