#!/usr/bin/env python3
"""
Test Forward Secrecy Implementation
Tests end-to-end encryption/decryption with X25519 ephemeral keys

DEPRECATED: Merged into test_forward_secrecy_integration.py
This file is kept for reference but tests are skipped.
"""

import pytest
pytestmark = pytest.mark.skip(reason="DEPRECATED: Merged into test_forward_secrecy_integration.py")

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from meow_decoder.crypto import (
    encrypt_file_bytes,
    decrypt_to_raw,
    pack_manifest,
    unpack_manifest,
    Manifest,
    MAGIC
)
from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair, serialize_public_key


def test_password_only_mode():
    """Test backward-compatible password-only mode."""
    print("=" * 60)
    print("TEST 1: Password-Only Mode (No Forward Secrecy)")
    print("=" * 60)
    
    plaintext = b"Secret message without forward secrecy!"
    password = "test_password_123"
    
    # Encrypt (no receiver_public_key)
    comp, sha, salt, nonce, cipher, ephemeral_pub, encryption_key = encrypt_file_bytes(
        plaintext, password, None, None
    )
    
    print(f"✅ Encrypted {len(plaintext)} bytes → {len(cipher)} bytes ciphertext")
    print(f"   Ephemeral public key: {ephemeral_pub} (should be None)")
    print(f"   Salt: {salt.hex()[:16]}...")
    print(f"   Nonce: {nonce.hex()[:16]}...")
    
    # Decrypt
    decrypted = decrypt_to_raw(
        cipher, password, salt, nonce, None,
        len(plaintext), len(comp), sha,
        None, None  # No forward secrecy
    )
    
    print(f"✅ Decrypted {len(decrypted)} bytes")
    print(f"   Match: {plaintext == decrypted}")
    
    if plaintext != decrypted:
        print("❌ FAILED: Decrypted data doesn't match!")
        return False
    
    print("✅ Password-only mode working!\n")
    return True


def test_forward_secrecy_mode():
    """Test forward secrecy mode with X25519 ephemeral keys."""
    print("=" * 60)
    print("TEST 2: Forward Secrecy Mode (X25519 Ephemeral Keys)")
    print("=" * 60)
    
    plaintext = b"Secret message with forward secrecy!"
    password = "test_password_456"
    
    # Generate receiver keypair
    receiver_private, receiver_public = generate_receiver_keypair()
    receiver_public_bytes = serialize_public_key(receiver_public)
    
    print(f"✅ Generated receiver keypair")
    print(f"   Public key: {receiver_public_bytes.hex()[:32]}...")
    
    # Encrypt with forward secrecy
    comp, sha, salt, nonce, cipher, ephemeral_pub, encryption_key = encrypt_file_bytes(
        plaintext, password, None, receiver_public_bytes
    )
    
    print(f"✅ Encrypted {len(plaintext)} bytes → {len(cipher)} bytes ciphertext")
    print(f"   Ephemeral public key: {ephemeral_pub.hex()[:32]}... (32 bytes)")
    print(f"   Salt: {salt.hex()[:16]}...")
    print(f"   Nonce: {nonce.hex()[:16]}...")
    
    # Serialize receiver private key for decryption
    receiver_private_bytes = receiver_private
    
    # Decrypt with forward secrecy
    decrypted = decrypt_to_raw(
        cipher, password, salt, nonce, None,
        len(plaintext), len(comp), sha,
        ephemeral_pub, receiver_private_bytes
    )
    
    print(f"✅ Decrypted {len(decrypted)} bytes")
    print(f"   Match: {plaintext == decrypted}")
    
    if plaintext != decrypted:
        print("❌ FAILED: Decrypted data doesn't match!")
        return False
    
    print("✅ Forward secrecy mode working!\n")
    return True


def test_manifest_packing():
    """Test manifest packing/unpacking with forward secrecy."""
    print("=" * 60)
    print("TEST 3: Manifest Packing/Unpacking")
    print("=" * 60)
    
    import secrets
    
    # Test password-only manifest
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
        ephemeral_public_key=None  # Password-only
    )
    
    packed1 = pack_manifest(manifest1)
    print(f"✅ Password-only manifest: {len(packed1)} bytes (should be 115)")
    
    if len(packed1) != 115:
        print(f"❌ FAILED: Expected 115 bytes, got {len(packed1)}")
        return False
    
    unpacked1 = unpack_manifest(packed1)
    print(f"   Unpacked: ephemeral_public_key = {unpacked1.ephemeral_public_key}")
    
    # Test forward secrecy manifest
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
        ephemeral_public_key=secrets.token_bytes(32)  # Forward secrecy
    )
    
    packed2 = pack_manifest(manifest2)
    print(f"✅ Forward secrecy manifest: {len(packed2)} bytes (should be 147)")
    
    if len(packed2) != 147:
        print(f"❌ FAILED: Expected 147 bytes, got {len(packed2)}")
        return False
    
    unpacked2 = unpack_manifest(packed2)
    print(f"   Unpacked: ephemeral_public_key = {unpacked2.ephemeral_public_key.hex()[:16]}...")
    
    if unpacked2.ephemeral_public_key != manifest2.ephemeral_public_key:
        print("❌ FAILED: Ephemeral public key mismatch!")
        return False
    
    print("✅ Manifest packing/unpacking working!\n")
    return True


def test_wrong_password():
    """Test that wrong password fails properly."""
    print("=" * 60)
    print("TEST 4: Wrong Password (Should Fail)")
    print("=" * 60)
    
    plaintext = b"Secret message"
    password = "correct_password"
    wrong_password = "wrong_password"
    
    # Generate receiver keypair
    receiver_private, receiver_public = generate_receiver_keypair()
    receiver_public_bytes = serialize_public_key(receiver_public)
    
    # Encrypt
    comp, sha, salt, nonce, cipher, ephemeral_pub, encryption_key = encrypt_file_bytes(
        plaintext, password, None, receiver_public_bytes
    )
    
    print(f"✅ Encrypted with password: '{password}'")
    
    # Try to decrypt with wrong password
    receiver_private_bytes = receiver_private
    
    try:
        decrypted = decrypt_to_raw(
            cipher, wrong_password, salt, nonce, None,
            len(plaintext), len(comp), sha,
            ephemeral_pub, receiver_private_bytes
        )
        print(f"❌ FAILED: Decryption should have failed with wrong password!")
        return False
    except RuntimeError as e:
        print(f"✅ Decryption failed as expected: {str(e)[:60]}...")
        print("✅ Wrong password protection working!\n")
        return True


def main():
    """Run all tests."""
    print("\n🔐 FORWARD SECRECY IMPLEMENTATION TESTS\n")
    
    tests = [
        test_password_only_mode,
        test_forward_secrecy_mode,
        test_manifest_packing,
        test_wrong_password
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ TEST FAILED WITH EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("✅ ALL TESTS PASSED!")
        print("\n🎉 Forward secrecy implementation is working!")
        return 0
    else:
        print(f"❌ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
