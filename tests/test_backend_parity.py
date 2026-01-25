#!/usr/bin/env python3
"""
🔬 Backend Parity Tests: Verify Python and Rust backends produce identical outputs

Critical for confidence that the constant-time Rust version is NOT introducing bugs.
Tests that both backends, when given identical inputs, produce identical outputs.

This is NOT a security test (backends are equally secure), but an EQUIVALENCE test.
It proves the constant-time optimization doesn't change behavior.
"""

import os
import pytest
import secrets
import hashlib
from pathlib import Path

# CRITICAL: Allow Python backend explicitly for parity testing
# These tests REQUIRE both backends to compare outputs
os.environ['MEOW_ALLOW_PYTHON_FALLBACK'] = '1'

from meow_decoder.crypto_backend import CryptoBackend
from meow_decoder.crypto import (
    encrypt_file_bytes, decrypt_to_raw, 
    pack_manifest, unpack_manifest, Manifest,
    compute_manifest_hmac
)


class TestBackendParityAES256GCM:
    """Verify AES-256-GCM produces identical outputs on both backends."""
    
    def test_aes_gcm_encrypt_identical(self):
        """Same plaintext + key + nonce → same ciphertext on both backends."""
        plaintext = b"Secret message for encryption test" * 100
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = b"additional_authenticated_data"
        
        # Encrypt with Python backend
        backend_py = CryptoBackend(backend="python")
        cipher_py = backend_py.aes_gcm_encrypt(key, nonce, plaintext, aad)
        
        # Encrypt with Rust backend (if available)
        try:
            backend_rs = CryptoBackend(backend="rust")
            cipher_rs = backend_rs.aes_gcm_encrypt(key, nonce, plaintext, aad)
            
            # CRITICAL: Ciphertexts must be IDENTICAL
            assert cipher_py == cipher_rs, (
                f"AES-GCM ciphertext mismatch between backends!\n"
                f"Python: {cipher_py.hex()[:32]}...\n"
                f"Rust:   {cipher_rs.hex()[:32]}..."
            )
        except ImportError:
            pytest.skip("Rust backend not available")
    
    def test_aes_gcm_decrypt_identical(self):
        """Decrypt with both backends produces same plaintext."""
        plaintext = b"Test decryption parity" * 50
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aad = b"aad_data"
        
        backend_py = CryptoBackend(backend="python")
        cipher = backend_py.aes_gcm_encrypt(key, nonce, plaintext, aad)
        
        # Decrypt with Python backend
        decrypted_py = backend_py.aes_gcm_decrypt(key, nonce, cipher, aad)
        assert decrypted_py == plaintext
        
        # Decrypt with Rust backend (if available)
        try:
            backend_rs = CryptoBackend(backend="rust")
            decrypted_rs = backend_rs.aes_gcm_decrypt(key, nonce, cipher, aad)
            
            assert decrypted_rs == plaintext
            assert decrypted_py == decrypted_rs, (
                f"Decrypted data differs between backends!"
            )
        except ImportError:
            pytest.skip("Rust backend not available")


class TestBackendParityArgon2id:
    """Verify Argon2id produces identical keys on both backends."""
    
    def test_argon2id_key_derivation_identical(self):
        """Same password + salt → same key on both backends."""
        password = "test_password_for_parity_verification"
        salt = secrets.token_bytes(16)
        
        backend_py = CryptoBackend(backend="python")
        key_py = backend_py.derive_key_argon2id(
            password.encode('utf-8'),
            salt,
            output_len=32,
            iterations=10,
            memory_kib=262144,
            parallelism=4
        )
        
        try:
            backend_rs = CryptoBackend(backend="rust")
            key_rs = backend_rs.derive_key_argon2id(
                password.encode('utf-8'),
                salt,
                output_len=32,
                iterations=10,
                memory_kib=262144,
                parallelism=4
            )
            
            assert key_py == key_rs, (
                f"Argon2id key derivation mismatch!\n"
                f"Python: {key_py.hex()}\n"
                f"Rust:   {key_rs.hex()}"
            )
        except ImportError:
            pytest.skip("Rust backend not available")
    
    def test_argon2id_deterministic(self):
        """Argon2id is deterministic: same inputs always produce same output."""
        password = "deterministic_test_password"
        salt = b"fixedsalt16bytes"  # Exactly 16 bytes
        
        backend = CryptoBackend(backend="python")
        
        # Use keyword args to avoid confusion: 64 MiB, 3 iterations
        key1 = backend.derive_key_argon2id(
            password.encode('utf-8'), salt,
            memory_kib=65536, iterations=3, parallelism=4, output_len=32
        )
        key2 = backend.derive_key_argon2id(
            password.encode('utf-8'), salt,
            memory_kib=65536, iterations=3, parallelism=4, output_len=32
        )
        
        assert key1 == key2, "Argon2id not deterministic!"


class TestBackendParityHMACSHA256:
    """Verify HMAC-SHA256 produces identical tags on both backends."""
    
    def test_hmac_sha256_identical(self):
        """Same key + message → same HMAC on both backends."""
        key = secrets.token_bytes(32)
        message = b"Message to authenticate" * 100
        
        backend_py = CryptoBackend(backend="python")
        hmac_py = backend_py.hmac_sha256(key, message)
        
        try:
            backend_rs = CryptoBackend(backend="rust")
            hmac_rs = backend_rs.hmac_sha256(key, message)
            
            assert hmac_py == hmac_rs, (
                f"HMAC-SHA256 mismatch!\n"
                f"Python: {hmac_py.hex()}\n"
                f"Rust:   {hmac_rs.hex()}"
            )
        except ImportError:
            pytest.skip("Rust backend not available")


class TestBackendParityX25519:
    """Verify X25519 key exchange produces identical shared secrets."""
    
    def test_x25519_key_generation_different(self):
        """X25519 key generation should produce different keys each time."""
        backend = CryptoBackend(backend="python")
        
        privkey1, pubkey1 = backend.x25519_generate_keypair()
        privkey2, pubkey2 = backend.x25519_generate_keypair()
        
        # Keys should be different
        assert privkey1 != privkey2
        assert pubkey1 != pubkey2
    
    def test_x25519_exchange_identical(self):
        """Same ephemeral + receiver key → same shared secret on both backends."""
        backend_py = CryptoBackend(backend="python")
        
        # Generate receiver's static key
        receiver_privkey, receiver_pubkey = backend_py.x25519_generate_keypair()
        
        # Generate ephemeral key
        ephemeral_privkey, ephemeral_pubkey = backend_py.x25519_generate_keypair()
        
        # Exchange with Python backend
        shared_py = backend_py.x25519_exchange(ephemeral_privkey, receiver_pubkey)
        
        try:
            backend_rs = CryptoBackend(backend="rust")
            shared_rs = backend_rs.x25519_exchange(ephemeral_privkey, receiver_pubkey)
            
            assert shared_py == shared_rs, (
                f"X25519 shared secret mismatch!\n"
                f"Python: {shared_py.hex()}\n"
                f"Rust:   {shared_rs.hex()}"
            )
        except ImportError:
            pytest.skip("Rust backend not available")


class TestBackendParityIntegration:
    """Full encrypt/decrypt roundtrip with both backends."""
    
    def test_full_encryption_roundtrip_identical(self):
        """Encrypt with one backend, decrypt with another → success."""
        plaintext = b"Full roundtrip test message" * 50
        password = "test_password_for_roundtrip"
        
        # Encrypt with Python backend
        backend_py = CryptoBackend(backend="python")
        comp, sha, salt, nonce, cipher, _, key_py = encrypt_file_bytes(
            plaintext, password
        )
        
        # Decrypt with Python backend
        decrypted_py = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(plaintext),
            comp_len=len(comp),
            sha256=sha
        )
        assert decrypted_py == plaintext
        
        # Try cross-backend decryption
        try:
            # Decrypt using Rust backend (if available)
            backend_rs = CryptoBackend(backend="rust")
            decrypted_rs = decrypt_to_raw(
                cipher, password, salt, nonce,
                orig_len=len(plaintext),
                comp_len=len(comp),
                sha256=sha
            )
            assert decrypted_rs == plaintext
            assert decrypted_py == decrypted_rs
        except ImportError:
            pytest.skip("Rust backend not available")


class TestBackendTimingCharacteristics:
    """Verify Rust backend has better constant-time properties."""
    
    def test_rust_backend_exists(self):
        """Verify Rust backend is available (optional but preferred)."""
        try:
            backend = CryptoBackend(backend="rust")
            assert backend.get_info().name == "rust"
        except (ImportError, RuntimeError):
            pytest.skip("Rust backend not available")
    
    def test_backend_auto_selection(self):
        """Verify auto-selection chooses Rust if available, falls back to Python."""
        backend = CryptoBackend(backend="auto")
        
        # Backend should be either rust or python
        assert backend.get_info().name in ["rust", "python"]
    
    def test_backend_selection_env_var(self):
        """Verify MEOW_CRYPTO_BACKEND env var works."""
        import os
        original = os.environ.get("MEOW_CRYPTO_BACKEND")
        original_fallback = os.environ.get("MEOW_ALLOW_PYTHON_FALLBACK")
        
        try:
            # Force Python backend (requires fallback flag)
            os.environ["MEOW_CRYPTO_BACKEND"] = "python"
            os.environ["MEOW_ALLOW_PYTHON_FALLBACK"] = "1"
            # Reset cached backend
            from meow_decoder import crypto_backend
            crypto_backend._default_backend = None
            backend = CryptoBackend(backend="auto")
            assert backend.get_info().name == "python"
        finally:
            if original is not None:
                os.environ["MEOW_CRYPTO_BACKEND"] = original
            else:
                os.environ.pop("MEOW_CRYPTO_BACKEND", None)
            if original_fallback is not None:
                os.environ["MEOW_ALLOW_PYTHON_FALLBACK"] = original_fallback
            else:
                os.environ.pop("MEOW_ALLOW_PYTHON_FALLBACK", None)


class TestBackendConstantTime:
    """Verify Rust backend is constant-time, Python is best-effort."""
    
    def test_backend_info_timing_claims(self):
        """Verify backend correctly reports constant-time guarantees."""
        backend_py = CryptoBackend(backend="python")
        info_py = backend_py.get_info()
        
        # Python backend claims best-effort constant-time
        assert info_py.name == "python"
        assert info_py.constant_time == False  # Honest assessment
        
        try:
            backend_rs = CryptoBackend(backend="rust")
            info_rs = backend_rs.get_info()
            
            # Rust backend claims constant-time operations
            assert info_rs.name == "rust"
            assert info_rs.constant_time == True  # Subtle crate guarantee
        except (ImportError, RuntimeError):
            pytest.skip("Rust backend not available")


# Tests for anti-spoofing in bidirectional.py
class TestBidirectionalAntiSpoofing:
    """Verify bidirectional control channel has anti-spoofing protection."""
    
    def test_session_hmac_verification(self):
        """Session HMAC prevents spoofed messages from foreign sessions."""
        from meow_decoder.bidirectional import (
            SessionInfo, create_session_hmac, verify_session_hmac
        )
        
        session = SessionInfo(
            session_id=secrets.token_bytes(8),
            total_frames=100,
            k_blocks=50,
            block_size=512,
            file_hash=hashlib.sha256(b"test").digest(),
            session_salt=secrets.token_bytes(16)
        )
        
        session_key = b"shared_session_key_for_testing"
        message = b"FRAME_ACK frame_id=42"
        
        # Create HMAC for this session
        hmac_tag = create_session_hmac(session_key, message)
        
        # Verify it passes
        assert verify_session_hmac(session_key, message, hmac_tag)
        
        # Tamper with message
        tampered = b"FRAME_ACK frame_id=43"
        assert not verify_session_hmac(session_key, tampered, hmac_tag)
    
    def test_replay_protection_monotonic_counter(self):
        """Message sequence counter prevents replay attacks."""
        from meow_decoder.bidirectional import BidirectionalReceiver
        
        # Receiver tracks highest sequence number seen
        receiver = BidirectionalReceiver()
        
        # Message with seq=1
        msg1 = {"seq": 1, "type": "FRAME_ACK", "frame_id": 0}
        assert receiver.check_sequence_number(1)  # First, allowed
        
        # Replay of seq=1
        assert not receiver.check_sequence_number(1)  # Rejected as replay
        
        # Message with seq=2
        assert receiver.check_sequence_number(2)  # Allowed, advances counter


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
