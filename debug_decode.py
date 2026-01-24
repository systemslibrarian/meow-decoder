#!/usr/bin/env python3
"""Debug Schrödinger decode"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from meow_decoder.schrodinger_encode import schrodinger_encode_data
from meow_decoder.decoy_generator import generate_convincing_decoy

# Create two realities
real_data = b"SECRET: Test message" * 10
decoy_data = generate_convincing_decoy(len(real_data))

print(f"Real: {len(real_data)} bytes")
print(f"Decoy: {len(decoy_data)} bytes")

# Encode
print("\nEncoding...")
entangled, manifest = schrodinger_encode_data(
    real_data, decoy_data,
    "password_a", "password_b"
)

print(f"Entangled: {len(entangled)} bytes")
print(f"Manifest: {len(manifest.pack())} bytes")
print(f"Metadata A: {len(manifest.metadata_a)} bytes")
print(f"Metadata B: {len(manifest.metadata_b)} bytes")

# Try to decode metadata manually
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import struct

print("\n\nDecoding metadata A...")
key_a = hashlib.sha256(b"password_a" + manifest.salt_a).digest()
aesgcm_a = AESGCM(key_a)

try:
    # Remove padding
    enc_meta_a = manifest.metadata_a.rstrip(b'\x00')
    print(f"Encrypted metadata (after strip): {len(enc_meta_a)} bytes")
    
    meta_plain_a = aesgcm_a.decrypt(manifest.nonce_a, enc_meta_a, None)
    print(f"Decrypted metadata: {len(meta_plain_a)} bytes")
    print(f"First 16 bytes (orig_len, comp_len): {meta_plain_a[:16].hex()}")
    
    orig_len, comp_len = struct.unpack('>QQ', meta_plain_a[:16])
    print(f"orig_len: {orig_len}")
    print(f"comp_len: {comp_len}")
    
    salt_enc = meta_plain_a[16:32]
    nonce_enc = meta_plain_a[32:44]
    sha256_exp = meta_plain_a[44:76]
    
    print(f"salt_enc: {salt_enc.hex()[:16]}...")
    print(f"nonce_enc: {nonce_enc.hex()}")
    print(f"sha256: {sha256_exp.hex()[:16]}...")
    
    print("\n✅ Metadata decryption successful!")
    
except Exception as e:
    print(f"❌ Metadata decryption failed: {e}")
    import traceback
    traceback.print_exc()
