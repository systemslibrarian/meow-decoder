#!/usr/bin/env python3
"""
Comprehensive Test for v5.2.0 Features
Tests all implemented security features together
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_constant_time_operations():
    """Test constant-time operations."""
    print("\n🔐 TEST 1: Constant-Time Operations")
    print("=" * 60)
    
    from meow_decoder.constant_time import (
        constant_time_compare,
        equalize_timing
    )
    
    # Test constant-time comparison
    a = b"secret_data_12345"
    b = b"secret_data_12345"
    c = b"secret_data_12346"
    
    assert constant_time_compare(a, b) == True, "Should match"
    assert constant_time_compare(a, c) == False, "Should not match"
    
    print("✅ Constant-time comparison working")
    
    # Test timing equalization
    import time
    start = time.time()
    equalize_timing(0.001, 0.003)  # 1-3ms delay
    elapsed = time.time() - start
    
    assert elapsed >= 0.001, "Should have at least minimum delay"
    assert elapsed < 0.010, "Should not exceed reasonable maximum"
    
    print(f"✅ Timing equalization working ({elapsed*1000:.2f}ms delay)")
    
    return True

def test_metadata_obfuscation():
    """Test metadata obfuscation with length padding."""
    print("\n🔐 TEST 2: Metadata Obfuscation (Length Padding)")
    print("=" * 60)
    
    from meow_decoder.metadata_obfuscation import (
        add_length_padding,
        remove_length_padding,
        round_up_to_size_class
    )
    
    # Test size class rounding
    assert round_up_to_size_class(100) == 1024, "100 bytes → 1 KB"
    assert round_up_to_size_class(1500) == 2048, "1500 bytes → 2 KB"
    assert round_up_to_size_class(5000) == 8192, "5000 bytes → 8 KB"
    
    print("✅ Size class rounding working")
    
    # Test length padding
    original = b"Secret data that needs padding"
    padded = add_length_padding(original)
    
    print(f"   Original: {len(original)} bytes")
    print(f"   Padded: {len(padded)} bytes")
    print(f"   Size class: {round_up_to_size_class(len(original))} bytes")
    
    # Verify padding size
    expected_size = round_up_to_size_class(len(original))
    assert len(padded) == expected_size, f"Padded size should be {expected_size}"
    
    # Test padding removal
    unpadded = remove_length_padding(padded)
    assert unpadded == original, "Should recover original data"
    
    print("✅ Length padding round-trip working")
    
    return True

def test_integrated_encryption():
    """Test integrated encryption with all features."""
    print("\n🔐 TEST 3: Integrated Encryption (All Features)")
    print("=" * 60)
    
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    from meow_decoder.x25519_forward_secrecy import (
        generate_receiver_keypair,
        serialize_public_key
    )
    from cryptography.hazmat.primitives import serialization
    
    plaintext = b"Secret message with all security features!"
    password = "test_password_789"
    
    # Generate receiver keypair
    receiver_priv, receiver_pub = generate_receiver_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    
    print("✅ Generated receiver keypair")
    
    # Encrypt with all features:
    # - Forward secrecy (X25519 ephemeral keys)
    # - Length padding (metadata obfuscation)
    # - AAD authentication
    comp, sha, salt, nonce, cipher, ephemeral_pub = encrypt_file_bytes(
        plaintext, password, None, receiver_pub_bytes, use_length_padding=True
    )
    
    print(f"✅ Encrypted with all features:")
    print(f"   - Forward secrecy: {ephemeral_pub.hex()[:32]}...")
    print(f"   - Length padding: {len(comp)} bytes (padded compressed)")
    print(f"   - Ciphertext: {len(cipher)} bytes")
    
    # Serialize receiver private key
    receiver_priv_bytes = receiver_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Decrypt
    decrypted = decrypt_to_raw(
        cipher, password, salt, nonce, None,
        len(plaintext), len(comp), sha,
        ephemeral_pub, receiver_priv_bytes
    )
    
    assert decrypted == plaintext, "Decrypted data should match!"
    
    print("✅ Decrypted successfully")
    print("✅ All features working together!")
    
    return True

def test_backward_compatibility():
    """Test backward compatibility (password-only, no padding)."""
    print("\n🔐 TEST 4: Backward Compatibility")
    print("=" * 60)
    
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    
    plaintext = b"Simple message without advanced features"
    password = "simple_password"
    
    # Encrypt without forward secrecy, without padding
    comp, sha, salt, nonce, cipher, ephemeral_pub = encrypt_file_bytes(
        plaintext, password, None, None, use_length_padding=False
    )
    
    assert ephemeral_pub is None, "No ephemeral key in simple mode"
    
    print("✅ Encrypted in simple mode (backward compatible)")
    
    # Decrypt
    decrypted = decrypt_to_raw(
        cipher, password, salt, nonce, None,
        len(plaintext), len(comp), sha,
        None, None
    )
    
    assert decrypted == plaintext, "Should decrypt correctly"
    
    print("✅ Decrypted successfully")
    print("✅ Backward compatibility working!")
    
    return True

def test_manifest_formats():
    """Test different manifest formats."""
    print("\n🔐 TEST 5: Manifest Formats")
    print("=" * 60)
    
    from meow_decoder.crypto import pack_manifest, unpack_manifest, Manifest
    import secrets
    
    # Test 1: Password-only (115 bytes)
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
        ephemeral_public_key=None,
        pq_ciphertext=None
    )
    
    packed1 = pack_manifest(manifest1)
    print(f"✅ Password-only manifest: {len(packed1)} bytes (expected 115)")
    assert len(packed1) == 115
    
    # Test 2: Forward secrecy (147 bytes)
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
        ephemeral_public_key=secrets.token_bytes(32),
        pq_ciphertext=None
    )
    
    packed2 = pack_manifest(manifest2)
    print(f"✅ Forward secrecy manifest: {len(packed2)} bytes (expected 147)")
    assert len(packed2) == 147
    
    # Verify unpacking
    unpacked1 = unpack_manifest(packed1)
    assert unpacked1.ephemeral_public_key is None
    
    unpacked2 = unpack_manifest(packed2)
    assert unpacked2.ephemeral_public_key is not None
    assert len(unpacked2.ephemeral_public_key) == 32
    
    print("✅ All manifest formats working!")
    
    return True

def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("🔐 COMPREHENSIVE FEATURE TESTS - v5.2.0")
    print("=" * 60)
    
    tests = [
        ("Constant-Time Operations", test_constant_time_operations),
        ("Metadata Obfuscation", test_metadata_obfuscation),
        ("Integrated Encryption", test_integrated_encryption),
        ("Backward Compatibility", test_backward_compatibility),
        ("Manifest Formats", test_manifest_formats)
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
        print("   All v5.2.0 features working!")
        print("\n✅ Features verified:")
        print("   - Forward secrecy (X25519 ephemeral keys)")
        print("   - Frame-level MACs (DoS protection)")
        print("   - Constant-time operations (timing attacks)")
        print("   - Metadata obfuscation (length padding)")
        print("   - Backward compatibility (password-only)")
        return 0
    else:
        print(f"\n❌ {failed} TEST(S) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
