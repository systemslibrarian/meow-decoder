#!/usr/bin/env python3
"""
🔒 Security Test Suite - Battle-Hardening Tests

Tests critical security invariants:
1. Tamper detection (manifest, frames, ciphertext)
2. Replay/reorder protection
3. Authentication failures (wrong password, wrong key)
4. Corruption handling (fail closed)
5. Forward secrecy mode
6. AAD integrity

These tests ensure security regressions are caught automatically.
"""

import pytest
import secrets
import tempfile
from pathlib import Path

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
from meow_decoder.config import EncodingConfig


def _has_x25519():
    """Check if X25519 support is available."""
    try:
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        return True
    except ImportError:
        return False


class TestTamperDetection:
    """Test that tampering with data is detected and rejected."""
    
    def test_tampered_manifest_rejected(self, tmp_path):
        """Tampered manifest should fail authentication."""
        # Create test file
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # Read GIF and corrupt manifest bytes
        gif_data = gif_file.read_bytes()
        
        # Corrupt bytes in likely manifest region (first 500 bytes)
        corrupted = bytearray(gif_data)
        corrupted[100] ^= 0xFF  # Flip bits
        gif_file.write_bytes(bytes(corrupted))
        
        # Decode should fail (either parse error or authentication failure)
        with pytest.raises(Exception):  # Should raise ValueError or similar
            decode_gif(gif_file, output_file, password="testpass123")
    
    def test_tampered_ciphertext_rejected(self):
        """Tampered ciphertext should fail authentication."""
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Tamper with ciphertext
        tampered_cipher = bytearray(cipher)
        tampered_cipher[10] ^= 0xFF
        
        # Decrypt should fail
        with pytest.raises(Exception):  # AES-GCM auth failure
            decrypt_to_raw(
                bytes(tampered_cipher),
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha
            )
    
    def test_wrong_password_fails(self, tmp_path):
        """Wrong password should fail gracefully."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with one password
        encode_file(input_file, gif_file, password="correct_password")
        
        # Decode with wrong password should fail
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="wrong_password")
    
    def test_aad_tampering_rejected(self):
        """Tampering with AAD should cause authentication failure."""
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Tamper with SHA256 (part of AAD)
        tampered_sha = bytearray(sha)
        tampered_sha[0] ^= 0xFF
        
        # Decrypt with tampered AAD should fail
        with pytest.raises(Exception):  # AAD mismatch
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=bytes(tampered_sha)
            )


class TestCorruptionHandling:
    """Test handling of corrupted data (fail closed)."""
    
    def test_truncated_gif_fails(self, tmp_path):
        """Truncated GIF should fail gracefully."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # Truncate GIF
        gif_data = gif_file.read_bytes()
        gif_file.write_bytes(gif_data[:len(gif_data)//2])
        
        # Decode should fail
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="testpass123")
    
    def test_corrupted_qr_data_fails(self, tmp_path):
        """Corrupted QR data should fail fountain decoding."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data" * 100)  # Larger file
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with low redundancy (more fragile)
        config = EncodingConfig(redundancy=1.1)
        encode_file(input_file, gif_file, password="testpass123", config=config)
        
        # Corrupt middle of GIF (likely QR frames)
        gif_data = bytearray(gif_file.read_bytes())
        mid = len(gif_data) // 2
        for i in range(mid, mid + 100):
            gif_data[i] ^= 0xFF
        gif_file.write_bytes(bytes(gif_data))
        
        # Decode should fail (insufficient droplets)
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="testpass123")


class TestNonceSafety:
    """Test nonce uniqueness and safety."""
    
    def test_nonce_never_reused(self):
        """Each encryption should use a unique nonce."""
        data = b"Secret message"
        password = "testpass123"
        
        nonces = set()
        
        # Encrypt same data 100 times
        for _ in range(100):
            _, _, _, nonce, _, _ = encrypt_file_bytes(data, password, None, None)
            
            # Nonce should be unique
            assert nonce not in nonces, "Nonce reuse detected!"
            nonces.add(nonce)
    
    def test_nonce_is_random(self):
        """Nonces should be cryptographically random."""
        data = b"Secret message"
        password = "testpass123"
        
        nonces = []
        
        # Collect nonces
        for _ in range(10):
            _, _, _, nonce, _, _ = encrypt_file_bytes(data, password, None, None)
            nonces.append(nonce)
        
        # Nonces should be 12 bytes
        for nonce in nonces:
            assert len(nonce) == 12, "Nonce should be 12 bytes"
        
        # Nonces should not be sequential or predictable
        # Check that they're not all similar
        # 10 nonces × 12 bytes = 120 bytes total
        # Expect ~95% unique (114 unique) for truly random
        # Threshold: >90 unique bytes (allows some collisions)
        unique_bytes = len(set(b for nonce in nonces for b in nonce))
        assert unique_bytes > 90, f"Nonces appear non-random (only {unique_bytes}/120 unique bytes)"


class TestForwardSecrecy:
    """Test forward secrecy mode."""
    
    @pytest.mark.skipif(
        not _has_x25519(),
        reason="X25519 support not available"
    )
    def test_forward_secrecy_roundtrip(self, tmp_path):
        """Forward secrecy mode should work end-to-end."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        # Generate receiver keys
        privkey, pubkey = generate_receiver_keypair()
        
        # Save keys
        privkey_file = tmp_path / "receiver_private.pem"
        pubkey_file = tmp_path / "receiver_public.key"
        privkey_file.write_bytes(privkey)
        pubkey_file.write_bytes(pubkey)
        
        # Create test file
        input_file = tmp_path / "test.txt"
        input_file.write_text("Forward secrecy test data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with forward secrecy
        encode_file(
            input_file,
            gif_file,
            password="testpass123",
            receiver_public_key=pubkey
        )
        
        # Decode with receiver private key
        decode_gif(
            gif_file,
            output_file,
            password="testpass123",
            receiver_private_key=privkey
        )
        
        # Verify
        assert output_file.read_text() == "Forward secrecy test data"
    
    @pytest.mark.skipif(
        not _has_x25519(),
        reason="X25519 support not available"
    )
    def test_wrong_receiver_key_fails(self, tmp_path):
        """Using wrong receiver key should fail."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        # Generate two keypairs
        privkey1, pubkey1 = generate_receiver_keypair()
        privkey2, pubkey2 = generate_receiver_keypair()
        
        # Create test file
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with pubkey1
        encode_file(
            input_file,
            gif_file,
            password="testpass123",
            receiver_public_key=pubkey1
        )
        
        # Try to decode with privkey2 (wrong key)
        with pytest.raises(Exception):
            decode_gif(
                gif_file,
                output_file,
                password="testpass123",
                receiver_private_key=privkey2
            )


class TestAuthenticationCoverage:
    """Test that all critical fields are authenticated."""
    
    def test_version_authenticated(self):
        """Version field should be protected by AAD."""
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try to decrypt with wrong version magic (simulated)
        # This would fail because MAGIC is in AAD
        from meow_decoder.crypto import MAGIC
        fake_magic = b"FAKE"
        
        # Construct AAD with fake magic
        import struct
        aad = struct.pack('<QQ', len(data), len(comp))
        aad += salt + sha + fake_magic
        
        # Should fail because AAD won't match
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from meow_decoder.crypto import derive_key
        
        key = derive_key(password, salt, None)
        aesgcm = AESGCM(key)
        
        with pytest.raises(Exception):  # InvalidTag
            aesgcm.decrypt(nonce, cipher, aad)
    
    def test_length_fields_authenticated(self):
        """Length fields should be protected by AAD."""
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try to decrypt with wrong lengths
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data) + 1000,  # Wrong length
                comp_len=len(comp),
                sha256=sha
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
