#!/usr/bin/env python3
"""
Simple test for forward secrecy CLI integration
"""

import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_key_generation():
    """Test key generation."""
    print("\n🔐 TEST 1: Key Generation")
    print("=" * 60)
    
    from meow_decoder.x25519_forward_secrecy import (
        generate_receiver_keypair,
        save_receiver_keypair,
        load_receiver_keypair,
        serialize_public_key
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Generate keypair
        print("Generating keypair...")
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        # Save to files
        privkey_file = tmpdir / "receiver_private.pem"
        pubkey_file = tmpdir / "receiver_public.key"
        
        print("Saving keys...")
        save_receiver_keypair(
            receiver_priv, receiver_pub,
            str(privkey_file), str(pubkey_file),
            "test_password"
        )
        
        # Verify files exist
        assert privkey_file.exists(), "Private key file not created"
        assert pubkey_file.exists(), "Public key file not created"
        
        # Verify public key size
        pubkey_data = pubkey_file.read_bytes()
        assert len(pubkey_data) == 32, f"Public key wrong size: {len(pubkey_data)}"
        
        # Load back
        print("Loading keys...")
        loaded_priv, loaded_pub = load_receiver_keypair(
            str(privkey_file), str(pubkey_file), "test_password"
        )
        
        # Verify they match
        original_pub_bytes = serialize_public_key(receiver_pub)
        loaded_pub_bytes = serialize_public_key(loaded_pub)
        assert original_pub_bytes == loaded_pub_bytes, "Public keys don't match"
        
        print("✅ Key generation and save/load working!")
        return True

def test_encode_decode_programmatic():
    """Test encode/decode with forward secrecy programmatically."""
    print("\n🔐 TEST 2: Encode/Decode with Forward Secrecy")
    print("=" * 60)
    
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    from meow_decoder.x25519_forward_secrecy import (
        generate_receiver_keypair,
        serialize_public_key
    )
    from cryptography.hazmat.primitives import serialization
    
    # Test data
    plaintext = b"Secret message with forward secrecy!"
    password = "test_password_123"
    
    # Generate receiver keypair
    print("Generating receiver keypair...")
    receiver_priv, receiver_pub = generate_receiver_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    
    print(f"✅ Receiver public key: {receiver_pub_bytes.hex()[:32]}... ({len(receiver_pub_bytes)} bytes)")
    
    # Encrypt with forward secrecy
    print("\nEncrypting with forward secrecy...")
    comp, sha, salt, nonce, cipher, ephemeral_pub = encrypt_file_bytes(
        plaintext, password, None, receiver_pub_bytes
    )
    
    print(f"✅ Encrypted: {len(cipher)} bytes")
    print(f"✅ Ephemeral public key: {ephemeral_pub.hex()[:32]}... ({len(ephemeral_pub)} bytes)")
    
    # Serialize receiver private key
    receiver_priv_bytes = receiver_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Decrypt
    print("\nDecrypting with forward secrecy...")
    decrypted = decrypt_to_raw(
        cipher, password, salt, nonce, None,
        len(plaintext), len(comp), sha,
        ephemeral_pub, receiver_priv_bytes
    )
    
    print(f"✅ Decrypted: {len(decrypted)} bytes")
    
    # Verify
    assert decrypted == plaintext, "Decrypted data doesn't match!"
    print(f"✅ Content matches!")
    print(f"✅ Forward secrecy working end-to-end!")
    
    return True

def test_password_only_mode():
    """Test backward-compatible password-only mode."""
    print("\n🔐 TEST 3: Password-Only Mode (Backward Compatible)")
    print("=" * 60)
    
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    
    plaintext = b"Secret without forward secrecy"
    password = "test_password_456"
    
    # Encrypt without receiver public key
    print("Encrypting (password-only)...")
    comp, sha, salt, nonce, cipher, ephemeral_pub = encrypt_file_bytes(
        plaintext, password, None, None  # No receiver pubkey
    )
    
    print(f"✅ Encrypted: {len(cipher)} bytes")
    print(f"   Ephemeral key: {ephemeral_pub} (should be None)")
    
    assert ephemeral_pub is None, "Ephemeral key should be None in password-only mode"
    
    # Decrypt without receiver private key
    print("\nDecrypting (password-only)...")
    decrypted = decrypt_to_raw(
        cipher, password, salt, nonce, None,
        len(plaintext), len(comp), sha,
        None, None  # No ephemeral key, no receiver privkey
    )
    
    print(f"✅ Decrypted: {len(decrypted)} bytes")
    
    # Verify
    assert decrypted == plaintext, "Decrypted data doesn't match!"
    print(f"✅ Content matches!")
    print(f"✅ Password-only mode working!")
    
    return True

def test_manifest_packing():
    """Test manifest packing with forward secrecy."""
    print("\n🔐 TEST 4: Manifest Packing/Unpacking")
    print("=" * 60)
    
    from meow_decoder.crypto import pack_manifest, unpack_manifest, Manifest
    import secrets
    
    # Test password-only manifest (115 bytes)
    print("Testing password-only manifest...")
    manifest1 = Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=850,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
        ephemeral_public_key=None
    )
    
    packed1 = pack_manifest(manifest1)
    print(f"✅ Password-only manifest: {len(packed1)} bytes (expected 115)")
    assert len(packed1) == 115, f"Wrong size: {len(packed1)}"
    
    unpacked1 = unpack_manifest(packed1)
    assert unpacked1.ephemeral_public_key is None, "Should be None"
    print(f"✅ Unpacked correctly (no ephemeral key)")
    
    # Test forward secrecy manifest (147 bytes)
    print("\nTesting forward secrecy manifest...")
    manifest2 = Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=850,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
        ephemeral_public_key=secrets.token_bytes(32)
    )
    
    packed2 = pack_manifest(manifest2)
    print(f"✅ Forward secrecy manifest: {len(packed2)} bytes (expected 147)")
    assert len(packed2) == 147, f"Wrong size: {len(packed2)}"
    
    unpacked2 = unpack_manifest(packed2)
    assert unpacked2.ephemeral_public_key is not None, "Should have ephemeral key"
    assert len(unpacked2.ephemeral_public_key) == 32, "Ephemeral key wrong size"
    assert unpacked2.ephemeral_public_key == manifest2.ephemeral_public_key, "Ephemeral key mismatch"
    print(f"✅ Unpacked correctly (with ephemeral key)")
    
    print(f"✅ Manifest packing/unpacking working!")
    return True

def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("🔐 FORWARD SECRECY INTEGRATION TESTS")
    print("=" * 60)
    
    tests = [
        ("Key Generation", test_key_generation),
        ("Encode/Decode with FS", test_encode_decode_programmatic),
        ("Password-Only Mode", test_password_only_mode),
        ("Manifest Packing", test_manifest_packing)
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"❌ {name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {name}: EXCEPTION - {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{len(tests)} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        print("   Forward secrecy fully integrated and working!")
        return 0
    else:
        print(f"\n❌ {failed} TEST(S) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
