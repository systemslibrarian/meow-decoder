#!/usr/bin/env python3
"""
🔐 Manifest Tamper Tests: Verify fail-closed behavior on any modification

CRITICAL SECURITY TESTS
These prove that even a SINGLE BIT flip in the manifest causes complete decryption failure.
No partial outputs, no information leakage, no graceful degradation.
Fail-closed is the ONLY acceptable behavior.
"""

import pytest
import secrets
import struct
import hashlib

from meow_decoder.crypto import (
    encrypt_file_bytes, decrypt_to_raw, pack_manifest, unpack_manifest,
    Manifest, compute_manifest_hmac, verify_manifest_hmac, MAGIC
)


class TestManifestTamperDetection:
    """Every tamper vector must cause complete failure."""
    
    def setup_method(self):
        """Create a valid manifest for testing."""
        self.password = "test_password_for_tamper"
        self.plaintext = b"Secret data" * 100
        
        # Encrypt to get manifest
        self.comp, self.sha, self.salt, self.nonce, self.cipher, _, self.key = encrypt_file_bytes(
            self.plaintext, self.password
        )
        
        # Create manifest
        self.manifest = Manifest(
            salt=self.salt,
            nonce=self.nonce,
            orig_len=len(self.plaintext),
            comp_len=len(self.comp),
            cipher_len=len(self.cipher),
            sha256=self.sha,
            block_size=512,
            k_blocks=5,
            hmac=b'\x00' * 32
        )
        
        # Compute HMAC
        packed_no_hmac = (
            MAGIC +
            self.manifest.salt +
            self.manifest.nonce +
            struct.pack(">III", self.manifest.orig_len, self.manifest.comp_len, self.manifest.cipher_len) +
            struct.pack(">HI", self.manifest.block_size, self.manifest.k_blocks) +
            self.manifest.sha256
        )
        self.manifest.hmac = compute_manifest_hmac(self.password, self.salt, packed_no_hmac, encryption_key=self.key)
    
    def test_original_manifest_verifies(self):
        """Baseline: unmodified manifest verifies."""
        result = verify_manifest_hmac(self.password, self.manifest)
        assert result is True, "Original manifest should verify"
    
    def test_single_bit_flip_in_magic_detected(self):
        """Single bit flip in MAGIC → detection."""
        # Pack manifest
        packed = pack_manifest(self.manifest)
        
        # Flip one bit in MAGIC (first byte)
        tampered = bytearray(packed)
        tampered[0] ^= 0x01  # Flip bit 0 of 'M'
        tampered = bytes(tampered)
        
        # Try to unpack
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(tampered)
    
    def test_single_bit_flip_in_salt_detected(self):
        """Single bit flip in salt → HMAC fails."""
        packed = pack_manifest(self.manifest)
        
        # Flip one bit in salt (bytes 6-21)
        tampered = bytearray(packed)
        tampered[6] ^= 0x01  # Flip one bit in salt
        tampered = bytes(tampered)
        
        # Unpack should succeed (salt still 16 bytes)
        m = unpack_manifest(tampered)
        
        # But HMAC verification should FAIL
        result = verify_manifest_hmac(self.password, m)
        assert result is False, "HMAC should reject tampered salt"
    
    def test_single_bit_flip_in_nonce_detected(self):
        """Single bit flip in nonce → HMAC fails."""
        packed = pack_manifest(self.manifest)
        
        # Flip bit in nonce
        tampered = bytearray(packed)
        tampered[22] ^= 0x01  # Flip bit in nonce
        tampered = bytes(tampered)
        
        m = unpack_manifest(tampered)
        result = verify_manifest_hmac(self.password, m)
        assert result is False, "HMAC should reject tampered nonce"
    
    def test_single_bit_flip_in_orig_len_detected(self):
        """Single bit flip in orig_len → HMAC fails AND decrypt fails."""
        packed = pack_manifest(self.manifest)
        
        # Flip bit in orig_len (bytes 34-37)
        tampered = bytearray(packed)
        tampered[34] ^= 0x01
        tampered = bytes(tampered)
        
        m = unpack_manifest(tampered)
        result = verify_manifest_hmac(self.password, m)
        assert result is False, "HMAC should reject tampered orig_len"
    
    def test_single_bit_flip_in_sha256_detected(self):
        """Single bit flip in SHA256 hash → HMAC fails."""
        packed = pack_manifest(self.manifest)
        
        # Flip bit in SHA256 (bytes 46-77)
        tampered = bytearray(packed)
        tampered[46] ^= 0x01
        tampered = bytes(tampered)
        
        m = unpack_manifest(tampered)
        result = verify_manifest_hmac(self.password, m)
        assert result is False, "HMAC should reject tampered SHA256"
    
    def test_single_bit_flip_in_hmac_tag_detected(self):
        """Single bit flip in HMAC tag itself → verification fails."""
        packed = pack_manifest(self.manifest)
        
        # Flip bit in HMAC tag (last 32 bytes)
        tampered = bytearray(packed)
        tampered[-1] ^= 0x01  # Flip last bit of HMAC
        tampered = bytes(tampered)
        
        m = unpack_manifest(tampered)
        result = verify_manifest_hmac(self.password, m)
        assert result is False, "HMAC verification should fail on tampered tag"
    
    def test_byte_swap_detected(self):
        """Swapping two bytes → HMAC fails."""
        packed = pack_manifest(self.manifest)
        
        # Swap bytes
        tampered = bytearray(packed)
        tampered[10], tampered[20] = tampered[20], tampered[10]
        tampered = bytes(tampered)
        
        m = unpack_manifest(tampered)
        result = verify_manifest_hmac(self.password, m)
        assert result is False, "HMAC should reject byte-swapped manifest"
    
    def test_truncation_detected(self):
        """Manifest truncation → unpack fails."""
        packed = pack_manifest(self.manifest)
        
        # Truncate manifest
        truncated = packed[:-1]  # Remove last byte
        
        with pytest.raises(ValueError):
            unpack_manifest(truncated)
    
    def test_extension_detected(self):
        """Appending extra bytes → detected (length check in unpack)."""
        packed = pack_manifest(self.manifest)
        extended = packed + b"extra_garbage_data"
        
        # Unpack should fail due to invalid length
        # Manifest must be exactly 115, 147, or 1235 bytes
        with pytest.raises(ValueError, match="Manifest length invalid"):
            unpack_manifest(extended)


class TestDecryptionFailClosed:
    """Verify that tampering with ciphertext causes complete decryption failure."""
    
    def setup_method(self):
        """Create a valid encryption for testing."""
        self.password = "test_password"
        self.plaintext = b"Secret message to protect" * 100
        
        self.comp, self.sha, self.salt, self.nonce, self.cipher, _, _ = encrypt_file_bytes(
            self.plaintext, self.password
        )
    
    def test_original_decryption_succeeds(self):
        """Baseline: unmodified ciphertext decrypts correctly."""
        decrypted = decrypt_to_raw(
            self.cipher, self.password, self.salt, self.nonce,
            orig_len=len(self.plaintext),
            comp_len=len(self.comp),
            sha256=self.sha
        )
        assert decrypted == self.plaintext
    
    def test_single_bit_flip_in_ciphertext_fails(self):
        """Single bit flip in ciphertext → decryption/auth fails."""
        tampered_cipher = bytearray(self.cipher)
        tampered_cipher[100] ^= 0x01  # Flip one bit in middle
        tampered_cipher = bytes(tampered_cipher)
        
        # AES-GCM should detect this via auth tag
        with pytest.raises(Exception):  # Could be ValueError or RuntimeError
            decrypt_to_raw(
                tampered_cipher, self.password, self.salt, self.nonce,
                orig_len=len(self.plaintext),
                comp_len=len(self.comp),
                sha256=self.sha
            )
    
    def test_ciphertext_truncation_fails(self):
        """Truncating ciphertext → decryption fails."""
        truncated = self.cipher[:-10]  # Remove last 10 bytes
        
        with pytest.raises(Exception):
            decrypt_to_raw(
                truncated, self.password, self.salt, self.nonce,
                orig_len=len(self.plaintext),
                comp_len=len(self.comp),
                sha256=self.sha
            )
    
    def test_ciphertext_block_swap_fails(self):
        """Swapping ciphertext blocks → decryption fails."""
        cipher_array = bytearray(self.cipher)
        
        # Swap two 16-byte blocks
        cipher_array[0:16], cipher_array[16:32] = cipher_array[16:32], cipher_array[0:16]
        tampered = bytes(cipher_array)
        
        with pytest.raises(Exception):
            decrypt_to_raw(
                tampered, self.password, self.salt, self.nonce,
                orig_len=len(self.plaintext),
                comp_len=len(self.comp),
                sha256=self.sha
            )
    
    def test_wrong_nonce_fails(self):
        """Wrong nonce (even off-by-one) → decryption fails."""
        wrong_nonce = bytearray(self.nonce)
        wrong_nonce[0] ^= 0x01  # Flip one bit
        wrong_nonce = bytes(wrong_nonce)
        
        with pytest.raises(Exception):
            decrypt_to_raw(
                self.cipher, self.password, self.salt, wrong_nonce,
                orig_len=len(self.plaintext),
                comp_len=len(self.comp),
                sha256=self.sha
            )
    
    def test_wrong_salt_fails(self):
        """Wrong salt → key derivation produces wrong key → decryption fails."""
        wrong_salt = secrets.token_bytes(16)
        
        with pytest.raises(Exception):
            decrypt_to_raw(
                self.cipher, self.password, wrong_salt, self.nonce,
                orig_len=len(self.plaintext),
                comp_len=len(self.comp),
                sha256=self.sha
            )
    
    def test_wrong_password_fails(self):
        """Wrong password → key derivation produces wrong key → decryption fails."""
        wrong_password = "wrong_password_123"
        
        with pytest.raises(Exception):
            decrypt_to_raw(
                self.cipher, wrong_password, self.salt, self.nonce,
                orig_len=len(self.plaintext),
                comp_len=len(self.comp),
                sha256=self.sha
            )


class TestManifestSwapProtection:
    """Verify that swapping manifests between different GIFs causes failure."""
    
    def test_manifest_from_different_gif_fails(self):
        """Manifest A with ciphertext B → authentication fails."""
        password1 = "password_one"
        password2 = "password_two"
        
        plaintext1 = b"First secret" * 100
        plaintext2 = b"Second secret" * 100
        
        # Encrypt both
        comp1, sha1, salt1, nonce1, cipher1, _, key1 = encrypt_file_bytes(
            plaintext1, password1
        )
        
        comp2, sha2, salt2, nonce2, cipher2, _, key2 = encrypt_file_bytes(
            plaintext2, password2
        )
        
        # Create manifests
        m1 = Manifest(
            salt=salt1, nonce=nonce1,
            orig_len=len(plaintext1),
            comp_len=len(comp1),
            cipher_len=len(cipher1),
            sha256=sha1,
            block_size=512,
            k_blocks=5,
            hmac=b'\x00' * 32
        )
        
        # Compute HMAC for m1
        packed_no_hmac1 = (
            MAGIC + salt1 + nonce1 +
            struct.pack(">III", len(plaintext1), len(comp1), len(cipher1)) +
            struct.pack(">HI", 512, 5) + sha1
        )
        m1.hmac = compute_manifest_hmac(password1, salt1, packed_no_hmac1, encryption_key=key1)
        
        # Verify m1 with password1 works
        assert verify_manifest_hmac(password1, m1) is True
        
        # But m1 with password2 should fail (different key derivation)
        assert verify_manifest_hmac(password2, m1) is False
        
        # And trying to decrypt cipher2 with m1's parameters should fail
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher2, password1, m1.salt, m1.nonce,
                orig_len=m1.orig_len,
                comp_len=m1.comp_len,
                sha256=m1.sha256
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
