#!/usr/bin/env python3
"""
Debug HMAC verification in forward secrecy mode
"""
import tempfile
from pathlib import Path

from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.crypto import (
    encrypt_file_bytes, decrypt_to_raw, compute_manifest_hmac,
    pack_manifest, Manifest
)
from cryptography.hazmat.primitives import serialization

print("=" * 70)
print("DEBUG: Forward Secrecy HMAC Verification")
print("=" * 70)

# Generate receiver keypair
print("\n1. Generating receiver keypair...")
privkey_obj, pubkey_obj = generate_receiver_keypair()

# Serialize to raw bytes
privkey = privkey_obj.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
pubkey = pubkey_obj.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print(f"✓ Private key: {privkey.hex()[:32]}... ({len(privkey)} bytes)")
print(f"✓ Public key: {pubkey.hex()[:32]}... ({len(pubkey)} bytes)")

# Encrypt data
password = "test_password_123"
test_data = b"Forward secrecy test data!"

print(f"\n2. Encrypting with forward secrecy...")
print(f"   Password: {password}")
print(f"   Data: {test_data}")

comp, sha256, salt, nonce, cipher, ephemeral_pub, encryption_key = encrypt_file_bytes(
    test_data, password, None, pubkey, use_length_padding=False
)

print(f"✓ Ephemeral public key: {ephemeral_pub.hex()[:32]}... ({len(ephemeral_pub)} bytes)")
print(f"✓ Encryption key: {encryption_key.hex()[:32]}... ({len(encryption_key)} bytes)")
print(f"✓ Salt: {salt.hex()[:16]}...")

# Create manifest
k_blocks = 1
manifest = Manifest(
    salt=salt,
    nonce=nonce,
    orig_len=len(test_data),
    comp_len=len(comp),
    cipher_len=len(cipher),
    sha256=sha256,
    block_size=512,
    k_blocks=k_blocks,
    hmac=b'\x00' * 32,
    ephemeral_public_key=ephemeral_pub
)

# Pack without HMAC
packed_no_hmac = pack_manifest(manifest)[:-32]

print(f"\n3. Computing HMAC during encoding...")
print(f"   Packed manifest (no HMAC): {len(packed_no_hmac)} bytes")

# Compute HMAC using encryption_key (encoding path)
hmac_encoding = compute_manifest_hmac(
    password, salt, packed_no_hmac, None, encryption_key=encryption_key
)

print(f"✓ HMAC (encoding): {hmac_encoding.hex()[:32]}...")

# Now simulate decoding path
print(f"\n4. Simulating decoding path...")

# Compute HMAC using receiver private key (decoding path)
hmac_decoding = compute_manifest_hmac(
    password, salt, packed_no_hmac, None, 
    ephemeral_public_key=ephemeral_pub,
    receiver_private_key=privkey
)

print(f"✓ HMAC (decoding): {hmac_decoding.hex()[:32]}...")

# Compare
print(f"\n5. Comparing HMACs...")
print(f"   Encoding HMAC: {hmac_encoding.hex()}")
print(f"   Decoding HMAC: {hmac_decoding.hex()}")

if hmac_encoding == hmac_decoding:
    print("✓✓✓ HMACs MATCH! ✓✓✓")
else:
    print("✗✗✗ HMACs DO NOT MATCH! ✗✗✗")
    print("\nThis is the bug - key derivation differs between encode/decode!")
    
    # Debug: Check if we're deriving the same key
    from meow_decoder.x25519_forward_secrecy import (
        derive_shared_secret, deserialize_public_key
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    
    print("\n6. Debugging key derivation...")
    
    # Decode path: derive key again
    receiver_privkey = X25519PrivateKey.from_private_bytes(privkey)
    sender_pubkey = deserialize_public_key(ephemeral_pub)
    
    key_decoding = derive_shared_secret(
        receiver_privkey,
        sender_pubkey,
        password,
        salt
    )
    
    print(f"   Encryption key (encoding): {encryption_key.hex()}")
    print(f"   Derived key (decoding):    {key_decoding.hex()}")
    
    if encryption_key == key_decoding:
        print("   ✓ Keys match - HMAC computation must differ")
    else:
        print("   ✗ Keys DON'T match - this is the root cause!")
