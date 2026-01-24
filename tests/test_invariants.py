#!/usr/bin/env python3
"""
🔒 Security Invariant Tests - MUST NEVER FAIL

These tests verify fundamental security properties that MUST hold
for the system to be considered secure. Any failure is CRITICAL.

Run with: pytest tests/test_invariants.py -v
"""

import pytest
import secrets
import tempfile
from pathlib import Path

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.config import EncodingConfig
from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw


class TestCriticalInvariants:
    """Tests that verify security invariants that must NEVER be violated."""
    
    def test_invariant_tampered_data_rejected(self, tmp_path):
        """
        INVARIANT: Tampered ciphertext MUST be rejected.
        
        Critical: If this fails, attackers can modify encrypted data.
        """
        data = b"Critical secret data"
        password = "password"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Tamper with ciphertext (flip one bit)
        tampered_cipher = bytearray(cipher)
        tampered_cipher[0] ^= 0x01
        
        # MUST reject
        with pytest.raises(Exception):
            decrypt_to_raw(
                bytes(tampered_cipher), password, salt, nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha
            )
    
    def test_invariant_wrong_password_rejected(self, tmp_path):
        """
        INVARIANT: Wrong password MUST be rejected.
        
        Critical: If this fails, password protection is broken.
        """
        input_file = tmp_path / "secret.txt"
        input_file.write_text("Secret")
        
        gif_file = tmp_path / "secret.gif"
        output_file = tmp_path / "output.txt"
        
        # Encrypt with correct password
        encode_file(input_file, gif_file, "correct_password")
        
        # MUST reject wrong password
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "wrong_password")
    
    def test_invariant_nonce_never_reused(self):
        """
        INVARIANT: Nonces MUST NEVER be reused.
        
        Critical: Nonce reuse breaks AES-GCM security completely.
        """
        data = b"Test"
        password = "password"
        
        nonces = set()
        for _ in range(100):
            _, _, _, nonce, _, _ = encrypt_file_bytes(data, password, None, None)
            
            # MUST be unique
            assert nonce not in nonces, f"CRITICAL: Nonce reused! {nonce.hex()}"
            nonces.add(nonce)
    
    def test_invariant_aad_modification_rejected(self):
        """
        INVARIANT: AAD tampering MUST be detected.
        
        Critical: AAD protects metadata integrity.
        """
        data = b"Data"
        password = "password"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Tamper with AAD (wrong original length)
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher, password, salt, nonce,
                orig_len=len(data) + 1,  # TAMPERED
                comp_len=len(comp),
                sha256=sha
            )
    
    def test_invariant_partial_data_rejected(self, tmp_path):
        """
        INVARIANT: Incomplete fountain decode MUST fail.
        
        Critical: Prevents returning partial/corrupted data.
        """
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Important data" * 100
        block_size = 32
        k_blocks = (len(data) + block_size - 1) // block_size
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))
        
        # Add only 50% of needed droplets
        for _ in range(k_blocks // 2):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        # MUST not be complete
        assert not decoder.is_complete()
        
        # MUST raise error on get_data()
        with pytest.raises(RuntimeError, match="Decoding incomplete"):
            decoder.get_data()
    
    def test_invariant_roundtrip_preserves_data(self, tmp_path):
        """
        INVARIANT: Roundtrip MUST preserve data exactly.
        
        Critical: Data corruption is unacceptable.
        """
        # Test various data patterns
        test_cases = [
            b"",  # Empty
            b"X",  # Single byte
            b"Hello, World!",  # Text
            secrets.token_bytes(1000),  # Random
            b"\x00" * 100,  # All zeros
            b"\xFF" * 100,  # All ones
        ]
        
        for i, original_data in enumerate(test_cases):
            input_file = tmp_path / f"test_{i}.dat"
            input_file.write_bytes(original_data)
            
            gif_file = tmp_path / f"test_{i}.gif"
            output_file = tmp_path / f"output_{i}.dat"
            
            # Encode and decode
            encode_file(input_file, gif_file, "password")
            decode_gif(gif_file, output_file, "password")
            
            # MUST match exactly
            recovered_data = output_file.read_bytes()
            assert recovered_data == original_data, \
                f"Data corruption in test case {i}: {len(original_data)} bytes"


class TestFailClosedBehavior:
    """Tests that verify fail-closed behavior under attack."""
    
    def test_fail_closed_corrupted_manifest(self, tmp_path):
        """System MUST fail closed on manifest corruption."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test")
        
        gif_file = tmp_path / "test.gif"
        encode_file(input_file, gif_file, "password")
        
        # Corrupt GIF data
        gif_data = bytearray(gif_file.read_bytes())
        
        # Find and corrupt manifest (after MEOW magic)
        for i in range(len(gif_data) - 4):
            if gif_data[i:i+4] == b"MEOW":
                # Corrupt byte after magic
                gif_data[i+10] ^= 0xFF
                break
        
        gif_file.write_bytes(bytes(gif_data))
        
        # MUST fail closed (reject)
        output_file = tmp_path / "output.txt"
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "password")
    
    def test_fail_closed_truncated_data(self, tmp_path):
        """System MUST fail closed on truncated data."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test data")
        
        gif_file = tmp_path / "test.gif"
        encode_file(input_file, gif_file, "password")
        
        # Truncate GIF (remove last 50%)
        gif_data = gif_file.read_bytes()
        truncated = gif_data[:len(gif_data) // 2]
        gif_file.write_bytes(truncated)
        
        # MUST fail closed (reject or error, not silent corruption)
        output_file = tmp_path / "output.txt"
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "password")
    
    def test_fail_closed_empty_password(self):
        """Empty password MUST be rejected."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError, match="Password cannot be empty"):
            derive_key("", secrets.token_bytes(16), None)


class TestNoRegressions:
    """Tests that verify no regressions in core functionality."""
    
    def test_no_regression_nonce_randomness(self):
        """Verify nonce randomness hasn't regressed."""
        data = b"Test"
        password = "password"
        
        nonces = []
        for _ in range(50):
            _, _, _, nonce, _, _ = encrypt_file_bytes(data, password, None, None)
            nonces.append(nonce)
        
        # Check entropy (should not have patterns)
        unique_nonces = set(nonces)
        assert len(unique_nonces) == len(nonces), "Nonce collision detected!"
        
        # Check distribution (chi-square test approximation)
        nonce_bytes = b''.join(nonces)
        byte_counts = [nonce_bytes.count(bytes([i])) for i in range(256)]
        
        # Should be roughly uniform (not all zero or all same value)
        assert len(set(byte_counts)) > 10, "Nonce distribution suspicious"
    
    def test_no_regression_compression(self):
        """Verify compression still works."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        # Highly compressible data
        compressible = b"A" * 10000
        
        comp, sha, salt, nonce, cipher, _ = encrypt_file_bytes(
            compressible, "password", None, None
        )
        
        # Should compress significantly
        compression_ratio = len(comp) / len(compressible)
        assert compression_ratio < 0.1, \
            f"Compression regressed: {compression_ratio:.2%}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
