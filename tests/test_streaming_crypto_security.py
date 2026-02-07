"""
Security Regression Tests for Streaming Crypto (CRIT-01 Fix)

Created: 2026-02-06
Audit: audit1.md - CRIT-01 (AES-CTR Without Authentication)

These tests verify the Encrypt-then-MAC fix for streaming crypto:
1. MAC is computed during encryption
2. MAC is verified before decryption
3. Tampered ciphertext is rejected
4. Truncated ciphertext is rejected
5. Wrong MAC is rejected
"""

import io
import os
import secrets
import pytest

from meow_decoder.streaming_crypto import StreamingCipher, STREAMING_MAC_INFO


class TestStreamingCryptoAuthentication:
    """Test suite for streaming crypto MAC authentication (CRIT-01 fix)."""

    def test_encrypt_returns_mac_tag(self):
        """encrypt_stream should return MAC tag as 4th element."""
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)

        input_data = b"Test data for MAC verification"
        result = cipher.encrypt_stream(io.BytesIO(input_data), io.BytesIO())

        assert len(result) == 4, "Should return 4 elements"
        orig_len, comp_len, sha_hash, mac_tag = result

        assert orig_len == len(input_data)
        assert isinstance(mac_tag, bytes)
        assert len(mac_tag) == 32, "MAC should be 32 bytes (HMAC-SHA256)"

    def test_roundtrip_with_mac_verification(self):
        """Encrypt-then-MAC roundtrip should work correctly."""
        key = secrets.token_bytes(32)
        plaintext = b"Secret message for authenticated streaming encryption"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        orig_len, comp_len, sha_hash, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext), enc_output
        )

        # Decrypt with MAC verification
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)
        dec_output = io.BytesIO()
        bytes_written = dec_cipher.decrypt_stream(enc_output, dec_output, expected_mac=mac_tag)

        assert bytes_written == len(plaintext)
        assert dec_output.getvalue() == plaintext

    def test_tampered_ciphertext_rejected(self):
        """Tampered ciphertext should be rejected by MAC verification."""
        key = secrets.token_bytes(32)
        plaintext = b"Secret data that must not be tampered with"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Tamper with ciphertext
        ciphertext = bytearray(enc_output.getvalue())
        ciphertext[5] ^= 0xFF  # Flip a bit
        tampered = io.BytesIO(bytes(ciphertext))

        # Decrypt with MAC verification - MUST fail
        dec_cipher = StreamingCipher(key, nonce=nonce)
        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(tampered, io.BytesIO(), expected_mac=mac_tag)

    def test_truncated_ciphertext_rejected(self):
        """Truncated ciphertext should be rejected by MAC verification."""
        key = secrets.token_bytes(32)
        plaintext = b"This is a longer message that will be truncated during attack"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Truncate ciphertext
        ciphertext = enc_output.getvalue()
        truncated = io.BytesIO(ciphertext[:-10])

        # Decrypt with MAC verification - MUST fail
        dec_cipher = StreamingCipher(key, nonce=nonce)
        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(truncated, io.BytesIO(), expected_mac=mac_tag)

    def test_wrong_mac_rejected(self):
        """Wrong MAC should be rejected."""
        key = secrets.token_bytes(32)
        plaintext = b"Data with wrong MAC"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Try to decrypt with wrong MAC
        wrong_mac = secrets.token_bytes(32)
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(enc_output, io.BytesIO(), expected_mac=wrong_mac)

    def test_mac_length_validation(self):
        """MAC must be exactly 32 bytes."""
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)

        with pytest.raises(ValueError, match="MAC must be 32 bytes"):
            cipher.decrypt_stream(io.BytesIO(b"data"), io.BytesIO(), expected_mac=b"short")

    def test_mac_is_deterministic(self):
        """Same key/nonce/plaintext should produce same MAC."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        plaintext = b"Deterministic MAC test data"

        # Encrypt twice with same key/nonce
        c1 = StreamingCipher(key, nonce=nonce)
        out1 = io.BytesIO()
        _, _, _, mac1 = c1.encrypt_stream(io.BytesIO(plaintext), out1)

        c2 = StreamingCipher(key, nonce=nonce)
        out2 = io.BytesIO()
        _, _, _, mac2 = c2.encrypt_stream(io.BytesIO(plaintext), out2)

        assert mac1 == mac2
        assert out1.getvalue() == out2.getvalue()

    def test_different_keys_produce_different_macs(self):
        """Different keys should produce different MACs."""
        plaintext = b"Same plaintext, different keys"
        nonce = secrets.token_bytes(16)

        c1 = StreamingCipher(secrets.token_bytes(32), nonce=nonce)
        out1 = io.BytesIO()
        _, _, _, mac1 = c1.encrypt_stream(io.BytesIO(plaintext), out1)

        c2 = StreamingCipher(secrets.token_bytes(32), nonce=nonce)
        out2 = io.BytesIO()
        _, _, _, mac2 = c2.encrypt_stream(io.BytesIO(plaintext), out2)

        assert mac1 != mac2

    def test_mac_includes_nonce(self):
        """MAC should include nonce to prevent nonce substitution attacks."""
        key = secrets.token_bytes(32)
        plaintext = b"Test nonce binding"

        # Encrypt with nonce1
        nonce1 = secrets.token_bytes(16)
        c1 = StreamingCipher(key, nonce=nonce1)
        out1 = io.BytesIO()
        _, _, _, mac1 = c1.encrypt_stream(io.BytesIO(plaintext), out1)

        # Encrypt with nonce2
        nonce2 = secrets.token_bytes(16)
        c2 = StreamingCipher(key, nonce=nonce2)
        out2 = io.BytesIO()
        _, _, _, mac2 = c2.encrypt_stream(io.BytesIO(plaintext), out2)

        # MACs should differ due to nonce binding
        assert mac1 != mac2

    def test_decrypt_without_mac_still_works(self):
        """Decrypt without MAC should still work (backward compat, but warns)."""
        key = secrets.token_bytes(32)
        plaintext = b"Unverified decryption test"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Decrypt WITHOUT MAC verification (insecure but backward-compatible)
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)
        dec_output = io.BytesIO()
        bytes_written = dec_cipher.decrypt_stream(enc_output, dec_output)

        assert bytes_written == len(plaintext)
        assert dec_output.getvalue() == plaintext

    def test_large_data_authenticated(self):
        """MAC should work correctly for large data."""
        key = secrets.token_bytes(32)
        plaintext = secrets.token_bytes(1024 * 1024)  # 1 MB

        # Encrypt
        enc_cipher = StreamingCipher(key, chunk_size=65536)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        orig_len, _, _, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext),
            enc_output,
            enable_compression=False,  # Skip compression for raw test
        )

        # Decrypt with MAC
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce, chunk_size=65536)
        dec_output = io.BytesIO()
        dec_cipher.decrypt_stream(
            enc_output, dec_output, enable_decompression=False, expected_mac=mac_tag
        )

        assert dec_output.getvalue() == plaintext

    def test_empty_plaintext(self):
        """MAC should work for empty plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b""

        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        orig_len, _, _, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext), enc_output, enable_compression=False
        )

        assert orig_len == 0
        assert len(mac_tag) == 32

        # Verify MAC still protects against modification
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)
        dec_output = io.BytesIO()
        dec_cipher.decrypt_stream(
            enc_output, dec_output, enable_decompression=False, expected_mac=mac_tag
        )

        assert dec_output.getvalue() == plaintext


class TestMACKeyDerivation:
    """Test MAC key derivation uses proper domain separation."""

    def test_mac_key_differs_from_encryption_key(self):
        """MAC key should be derived separately from encryption key."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        cipher = StreamingCipher(key, nonce=nonce)

        # MAC key should exist and differ from encryption key
        assert hasattr(cipher, "_mac_key")
        assert cipher._mac_key != key
        assert len(cipher._mac_key) == 32

    def test_mac_key_uses_hkdf_domain_separation(self):
        """MAC key derivation should use HKDF with proper domain separation."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        cipher = StreamingCipher(key, nonce=nonce)

        # Manually derive expected MAC key
        expected_mac_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=nonce, info=STREAMING_MAC_INFO
        ).derive(key)

        assert cipher._mac_key == expected_mac_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
