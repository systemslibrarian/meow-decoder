#!/usr/bin/env python3
"""
🔬 Property-Based Testing with Hypothesis

This module uses Hypothesis to verify security invariants that MUST hold
for all possible inputs, not just hand-crafted test cases.

Property-based testing is essential for crypto code because:
1. Manual tests can't cover the input space
2. Edge cases are where security bugs hide
3. Invariants are mathematical properties that must always hold

Run with: pytest tests/test_property_based.py -v --hypothesis-show-statistics
"""

import pytest
import secrets
from typing import Optional

from hypothesis import given, settings, assume, example, Phase
from hypothesis import strategies as st

from meow_decoder.crypto_backend import (
    RustCryptoBackend,
)
from meow_decoder.crypto import (
    encrypt_file_bytes, decrypt_to_raw,
    pack_manifest, unpack_manifest, Manifest,
    compute_manifest_hmac, verify_manifest_hmac,
    derive_key, MAGIC
)
from meow_decoder.fountain import (
    FountainEncoder, FountainDecoder,
    pack_droplet, unpack_droplet
)


# =============================================================================
# Custom Strategies for Crypto Data
# =============================================================================

# Valid passwords (8+ chars as required by NIST SP 800-63B)
passwords = st.text(
    min_size=8, 
    max_size=128,
    alphabet=st.characters(blacklist_categories=('Cs',))  # Exclude surrogates
).filter(lambda x: len(x.encode('utf-8')) >= 8)

# Salt: exactly 16 bytes
salts = st.binary(min_size=16, max_size=16)

# Nonce: exactly 12 bytes
nonces = st.binary(min_size=12, max_size=12)

# AES key: exactly 32 bytes
aes_keys = st.binary(min_size=32, max_size=32)

# Plaintext: variable size (0 to 64KB for performance)
plaintexts = st.binary(min_size=0, max_size=65536)

# Small plaintexts for faster tests
small_plaintexts = st.binary(min_size=1, max_size=1024)

# AAD (Additional Authenticated Data)
aad_data = st.one_of(st.none(), st.binary(min_size=0, max_size=256))

# Block sizes for fountain codes
block_sizes = st.integers(min_value=64, max_value=1024)


# =============================================================================
# INVARIANT 1: Encrypt-Decrypt Roundtrip
# =============================================================================

class TestEncryptDecryptInvariants:
    """Properties that MUST hold for all encrypt/decrypt operations."""
    
    @given(plaintext=small_plaintexts, key=aes_keys, nonce=nonces, aad=aad_data)
    @settings(max_examples=200, deadline=None)
    def test_aes_gcm_roundtrip(self, plaintext: bytes, key: bytes, nonce: bytes, aad: Optional[bytes]):
        """
        INVARIANT: decrypt(encrypt(plaintext)) == plaintext
        """
        backend = RustCryptoBackend()
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext, "Roundtrip failed: decrypted != original"
    
    @given(plaintext=small_plaintexts, password=passwords)
    @settings(max_examples=50, deadline=None)  # Fewer due to Argon2 cost
    def test_file_encrypt_decrypt_roundtrip(self, plaintext: bytes, password: str):
        """
        INVARIANT: Full file encryption roundtrip preserves data.
        
        encrypt_file_bytes → decrypt_to_raw must recover original.
        """
        assume(len(plaintext) > 0)  # Empty files handled separately
        
        comp, sha, salt, nonce, cipher, ephem_key, enc_key = encrypt_file_bytes(
            plaintext, password, keyfile=None, receiver_public_key=None,
            use_length_padding=True
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            keyfile=None,
            orig_len=len(plaintext),
            comp_len=len(comp),
            sha256=sha,
            ephemeral_public_key=ephem_key,
            receiver_private_key=None
        )
        
        assert decrypted == plaintext, f"File roundtrip failed! len={len(plaintext)}"


# =============================================================================
# INVARIANT 2: Nonce Uniqueness
# =============================================================================

class TestNonceUniqueness:
    """Properties related to nonce generation and uniqueness."""
    
    @given(st.data())
    @settings(max_examples=50, deadline=None)
    def test_nonces_never_repeat(self, data):
        """
        INVARIANT: encrypt_file_bytes never reuses a nonce.
        
        This is CRITICAL for AES-GCM security. Nonce reuse completely
        breaks the cipher's security guarantees.
        """
        password = "TestPassword123!"
        plaintext = b"Test data"
        
        nonces_seen = set()
        num_encryptions = data.draw(st.integers(min_value=10, max_value=50))
        
        for _ in range(num_encryptions):
            _, _, salt, nonce, _, _, _ = encrypt_file_bytes(
                plaintext, password, keyfile=None, receiver_public_key=None
            )
            
            # Nonce must be unique
            nonce_key = (salt, nonce)  # Salt + nonce combination
            assert nonce_key not in nonces_seen, (
                f"CRITICAL: Nonce reuse detected! nonce={nonce.hex()}"
            )
            nonces_seen.add(nonce_key)


# =============================================================================
# INVARIANT 4: Tamper Detection
# =============================================================================

class TestTamperDetection:
    """Properties related to detecting tampering."""
    
    @given(plaintext=small_plaintexts, key=aes_keys, nonce=nonces, 
           bit_position=st.integers(min_value=0, max_value=1000))
    @settings(max_examples=200, deadline=None)
    def test_ciphertext_tampering_detected(self, plaintext: bytes, key: bytes, 
                                           nonce: bytes, bit_position: int):
        """
        INVARIANT: Any ciphertext modification MUST be detected.
        
        Flipping any bit in the ciphertext must cause decryption to fail.
        """
        assume(len(plaintext) > 0)
        
        backend = RustCryptoBackend()
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        
        # Pick a bit to flip
        byte_pos = bit_position % len(ciphertext)
        bit_pos = bit_position % 8
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[byte_pos] ^= (1 << bit_pos)
        
        # Decryption MUST fail
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, nonce, bytes(tampered), None)
    
    @given(plaintext=small_plaintexts, key=aes_keys, nonce=nonces,
           aad=st.binary(min_size=1, max_size=64),
           bit_position=st.integers(min_value=0, max_value=500))
    @settings(max_examples=200, deadline=None)
    def test_aad_tampering_detected(self, plaintext: bytes, key: bytes, 
                                    nonce: bytes, aad: bytes, bit_position: int):
        """
        INVARIANT: Any AAD modification MUST be detected.
        
        Modifying AAD after encryption must cause decryption to fail.
        """
        assume(len(plaintext) > 0)
        
        backend = RustCryptoBackend()
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        
        # Tamper with AAD
        byte_pos = bit_position % len(aad)
        tampered_aad = bytearray(aad)
        tampered_aad[byte_pos] ^= 0x01
        
        # Decryption with tampered AAD MUST fail
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, nonce, ciphertext, bytes(tampered_aad))
    
    @given(key=aes_keys, message=st.binary(min_size=1, max_size=256),
           bit_position=st.integers(min_value=0, max_value=255))
    @settings(max_examples=200, deadline=None)
    def test_hmac_tampering_detected(self, key: bytes, message: bytes, bit_position: int):
        """
        INVARIANT: Any message modification must cause HMAC verification to fail.
        """
        backend = RustCryptoBackend()
        tag = backend.hmac_sha256(key, message)
        
        # Tamper with message
        byte_pos = bit_position % len(message)
        tampered = bytearray(message)
        tampered[byte_pos] ^= 0x01
        
        # Verification MUST fail
        assert not backend.hmac_sha256_verify(key, bytes(tampered), tag)


# =============================================================================
# INVARIANT 5: Key Derivation Determinism
# =============================================================================

class TestKeyDerivationInvariants:
    """Properties related to key derivation."""
    
    @given(password=passwords, salt=salts)
    @settings(max_examples=30, deadline=None)
    def test_key_derivation_deterministic(self, password: str, salt: bytes):
        """
        INVARIANT: Same password + salt always produces same key.
        """
        key1 = derive_key(password, salt, keyfile=None)
        key2 = derive_key(password, salt, keyfile=None)
        
        assert key1 == key2, "Key derivation is non-deterministic!"
    
    @given(password1=passwords, password2=passwords, salt=salts)
    @settings(max_examples=50, deadline=None)
    def test_different_passwords_different_keys(self, password1: str, password2: str, salt: bytes):
        """
        INVARIANT: Different passwords produce different keys.
        """
        assume(password1 != password2)
        
        key1 = derive_key(password1, salt, keyfile=None)
        key2 = derive_key(password2, salt, keyfile=None)
        
        assert key1 != key2, "Different passwords produced same key!"
    
    @given(password=passwords, salt1=salts, salt2=salts)
    @settings(max_examples=50, deadline=None)
    def test_different_salts_different_keys(self, password: str, salt1: bytes, salt2: bytes):
        """
        INVARIANT: Different salts produce different keys.
        """
        assume(salt1 != salt2)
        
        key1 = derive_key(password, salt1, keyfile=None)
        key2 = derive_key(password, salt2, keyfile=None)
        
        assert key1 != key2, "Different salts produced same key!"


# =============================================================================
# INVARIANT 6: Manifest Serialization
# =============================================================================

class TestManifestInvariants:
    """Properties related to manifest packing/unpacking."""
    
    @given(
        orig_len=st.integers(min_value=0, max_value=2**32-1),
        comp_len=st.integers(min_value=0, max_value=2**32-1),
        cipher_len=st.integers(min_value=0, max_value=2**32-1),
        block_size=st.integers(min_value=64, max_value=65535),
        k_blocks=st.integers(min_value=1, max_value=2**32-1)
    )
    @settings(max_examples=200, deadline=None)
    def test_manifest_roundtrip(self, orig_len: int, comp_len: int, 
                                 cipher_len: int, block_size: int, k_blocks: int):
        """
        INVARIANT: pack_manifest(unpack_manifest(m)) == m
        
        Manifest serialization must be lossless.
        """
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=orig_len,
            comp_len=comp_len,
            cipher_len=cipher_len,
            sha256=secrets.token_bytes(32),
            block_size=block_size,
            k_blocks=k_blocks,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=None,
            pq_ciphertext=None
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.salt == manifest.salt
        assert unpacked.nonce == manifest.nonce
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.comp_len == manifest.comp_len
        assert unpacked.cipher_len == manifest.cipher_len
        assert unpacked.sha256 == manifest.sha256
        assert unpacked.block_size == manifest.block_size
        assert unpacked.k_blocks == manifest.k_blocks
        assert unpacked.hmac == manifest.hmac


# =============================================================================
# INVARIANT 7: Fountain Code Properties
# =============================================================================

class TestFountainCodeInvariants:
    """Properties related to fountain codes."""
    
    @given(
        data=st.binary(min_size=100, max_size=2000),
        block_size=st.integers(min_value=50, max_value=200)
    )
    @settings(max_examples=50, deadline=None)
    def test_fountain_roundtrip(self, data: bytes, block_size: int):
        """
        INVARIANT: Fountain encoding is recoverable.
        
        With sufficient droplets, we can always recover the original data.
        """
        k_blocks = (len(data) + block_size - 1) // block_size
        assume(k_blocks >= 1)
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))
        
        # Generate 2x droplets (should be enough for recovery)
        max_droplets = k_blocks * 3
        droplets_used = 0
        
        while not decoder.is_complete() and droplets_used < max_droplets:
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            droplets_used += 1
        
        assert decoder.is_complete(), f"Failed to decode with {droplets_used} droplets"
        
        recovered = decoder.get_data(len(data))
        assert recovered == data, "Fountain decode produced wrong data!"
    
    @given(
        data=st.binary(min_size=50, max_size=500),
        block_size=st.integers(min_value=25, max_value=100)
    )
    @settings(max_examples=100, deadline=None)
    def test_droplet_serialization(self, data: bytes, block_size: int):
        """
        INVARIANT: Droplet serialization is lossless.
        """
        k_blocks = max(1, len(data) // block_size)
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        droplet = encoder.droplet()
        
        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, block_size)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data


# =============================================================================
# INVARIANT 8: Constant-Time Comparison
# =============================================================================

class TestConstantTimeInvariants:
    """Properties related to constant-time operations."""
    
    @given(a=st.binary(min_size=1, max_size=64), b=st.binary(min_size=1, max_size=64))
    @settings(max_examples=500, deadline=None)
    def test_constant_time_compare_correctness(self, a: bytes, b: bytes):
        """
        INVARIANT: Constant-time compare produces correct results.
        
        Must return True iff a == b.
        """
        backend = RustCryptoBackend()
        
        result = backend.constant_time_compare(a, b)
        expected = (a == b)
        
        assert result == expected, f"Constant-time compare incorrect for {a.hex()} vs {b.hex()}"
    
    @given(data=st.binary(min_size=1, max_size=64))
    @settings(max_examples=200, deadline=None)
    def test_constant_time_self_compare(self, data: bytes):
        """
        INVARIANT: x == x always.
        """
        backend = RustCryptoBackend()
        
        assert backend.constant_time_compare(data, data), "Self-compare failed!"


# =============================================================================
# INVARIANT 9: X25519 Key Exchange
# =============================================================================

class TestX25519Invariants:
    """Properties related to X25519 key exchange."""
    
    @given(st.data())
    @settings(max_examples=100, deadline=None)
    def test_x25519_shared_secret_commutative(self, data):
        """
        INVARIANT: X25519 key exchange is commutative.
        
        Alice's shared secret with Bob == Bob's shared secret with Alice
        """
        backend = RustCryptoBackend()
        
        priv_a, pub_a = backend.x25519_generate_keypair()
        priv_b, pub_b = backend.x25519_generate_keypair()
        
        shared_ab = backend.x25519_exchange(priv_a, pub_b)
        shared_ba = backend.x25519_exchange(priv_b, pub_a)
        
        assert shared_ab == shared_ba, "X25519 not commutative!"
    
    @given(st.data())
    @settings(max_examples=50, deadline=None)
    def test_x25519_public_key_derivation(self, data):
        """
        INVARIANT: Public key can be derived from private key.
        """
        backend = RustCryptoBackend()
        
        priv, pub = backend.x25519_generate_keypair()
        derived_pub = backend.x25519_public_from_private(priv)
        
        assert pub == derived_pub, "Public key derivation mismatch!"


# =============================================================================
# Run with verbose hypothesis statistics
# =============================================================================

if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--hypothesis-show-statistics",
        "--tb=short"
    ])
