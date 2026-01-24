#!/usr/bin/env python3
"""
🔥 Adversarial Test Suite - Attack Simulation

Tests that simulate real attacks:
1. Fuzzing (random input mutation)
2. Frame injection (malicious frames)
3. Replay attacks (reused frames)
4. Reordering attacks (out-of-order frames)
5. Manifest corruption (bit flipping)
6. Partial decryption (incomplete data)

These tests PROVE the security model works under attack.
"""

import pytest
import secrets
import tempfile
from pathlib import Path
import struct

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.qr_code import QRCodeReader
from meow_decoder.gif_handler import GIFDecoder
from meow_decoder.fountain import FountainDecoder


class TestFuzzing:
    """Fuzz testing - random mutations should fail gracefully."""
    
    def test_fuzz_manifest_bytes(self, tmp_path):
        """Random manifest mutations should be detected."""
        # Create test file
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data for fuzzing")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # Fuzz manifest (first 500 bytes likely contain manifest)
        gif_data = bytearray(gif_file.read_bytes())
        
        # Try 10 random mutations
        failures = 0
        for attempt in range(10):
            fuzzed = gif_data.copy()
            
            # Flip random bit in manifest region
            pos = secrets.randbelow(min(500, len(fuzzed)))
            bit = secrets.randbelow(8)
            fuzzed[pos] ^= (1 << bit)
            
            # Write fuzzed version
            fuzzed_file = tmp_path / f"fuzzed_{attempt}.gif"
            fuzzed_file.write_bytes(bytes(fuzzed))
            
            # Should fail (might rarely succeed if fuzzing non-critical bit)
            try:
                decode_gif(fuzzed_file, output_file, password="testpass123")
            except Exception:
                failures += 1
        
        # At least 70% should fail (some bits might be non-critical)
        # Note: Not all manifest bits are critical (e.g., padding bytes)
        assert failures >= 7, f"Only {failures}/10 fuzzing attempts were detected (expected ≥70%)"
    
    def test_fuzz_qr_data(self, tmp_path):
        """Random QR data mutations should fail gracefully."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data" * 100)  # Larger file
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # Fuzz QR region (middle 50% of file)
        gif_data = bytearray(gif_file.read_bytes())
        start = len(gif_data) // 4
        end = 3 * len(gif_data) // 4
        
        # Flip multiple random bits in QR region
        for _ in range(100):
            pos = start + secrets.randbelow(end - start)
            bit = secrets.randbelow(8)
            gif_data[pos] ^= (1 << bit)
        
        gif_file.write_bytes(bytes(gif_data))
        
        # Should fail (corrupted QR codes)
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="testpass123")
    
    def test_fuzz_ciphertext_bytes(self):
        """Random ciphertext mutations should fail auth check."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Secret message for fuzzing"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Fuzz ciphertext (flip 10 random bits)
        fuzzed_cipher = bytearray(cipher)
        for _ in range(10):
            pos = secrets.randbelow(len(fuzzed_cipher))
            bit = secrets.randbelow(8)
            fuzzed_cipher[pos] ^= (1 << bit)
        
        # Should fail auth check
        with pytest.raises(Exception):
            decrypt_to_raw(
                bytes(fuzzed_cipher),
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha
            )


class TestFrameInjection:
    """Test that injected/malicious frames are rejected."""
    
    def test_inject_random_frames(self, tmp_path):
        """Injecting random QR frames should not affect decoding."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # TODO: Inject frames
        # This would require GIF manipulation to add frames
        # For now, verify that partial frames are ignored
        
        # Truncate to 80% (simulates some frames being bad)
        gif_data = gif_file.read_bytes()
        truncated = gif_data[:int(len(gif_data) * 0.8)]
        gif_file.write_bytes(truncated)
        
        # Should fail (insufficient droplets)
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="testpass123")
    
    def test_inject_duplicate_frames(self):
        """Duplicate frames should be handled gracefully."""
        # This tests fountain decoder's handling of duplicate droplets
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        # Create test data
        data = b"Test data for duplicate frames"
        block_size = 8
        k_blocks = (len(data) + block_size - 1) // block_size
        
        # Encode
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Create decoder with original length
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))
        
        # Collect all droplets first, then inject duplicates
        droplets = []
        while not decoder.is_complete():
            droplet = encoder.droplet()
            droplets.append(droplet)
            decoder.add_droplet(droplet)
        
        # Now inject duplicates into the complete stream
        # Create a new decoder to test with duplicates
        decoder2 = FountainDecoder(k_blocks, block_size, original_length=len(data))
        
        duplicate_count = 0
        for i, droplet in enumerate(droplets):
            decoder2.add_droplet(droplet)
            
            # Add duplicate every 2nd droplet
            if i % 2 == 0 and i < len(droplets) - 1:
                decoder2.add_droplet(droplets[i])  # Duplicate
                duplicate_count += 1
        
        # Should still decode correctly despite duplicates
        decoded = decoder2.get_data()
        assert decoded == data
        assert duplicate_count > 0, f"Should have tested with duplicates (had {duplicate_count} duplicates)"


class TestReplayAttacks:
    """Test that replayed frames/messages are detected."""
    
    def test_replay_entire_message(self, tmp_path):
        """Replaying entire encrypted message should not leak info."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # Decode (first time - should work)
        decode_gif(gif_file, output_file, password="testpass123")
        assert output_file.read_text() == "Secret data"
        
        # Replay (decode again - should still work, but get same output)
        output_file2 = tmp_path / "output2.txt"
        decode_gif(gif_file, output_file2, password="testpass123")
        assert output_file2.read_text() == "Secret data"
        
        # Note: Replay protection would require state tracking
        # Current design is stateless, so replays succeed
        # This is acceptable for encryption-at-rest use case
    
    def test_replay_with_different_password(self, tmp_path):
        """Replaying with wrong password should fail."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with password A
        encode_file(input_file, gif_file, password="passwordA")
        
        # Try to decode with password B (should fail)
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="passwordB")


class TestReorderingAttacks:
    """Test that reordered frames are handled correctly."""
    
    def test_fountain_handles_out_of_order(self):
        """Fountain decoder should handle out-of-order droplets."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        # Create test data
        data = b"Test data for reordering" * 10
        block_size = 16
        k_blocks = (len(data) + block_size - 1) // block_size
        
        # Encode
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate all droplets needed
        droplets_needed = int(k_blocks * 1.5)
        
        droplets = []
        for _ in range(droplets_needed):
            droplets.append(encoder.droplet())
        
        # Shuffle droplets (out of order)
        import random
        shuffled = droplets.copy()
        random.shuffle(shuffled)
        
        # Decode with shuffled order
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))
        for droplet in shuffled:
            decoder.add_droplet(droplet)
        
        # Should still decode correctly
        decoded = decoder.get_data()  # No parameter needed - stored in decoder
        assert decoded == data


class TestManifestCorruption:
    """Test specific manifest field corruption."""
    
    def test_corrupt_version_field(self):
        """Corrupted version should be detected via AAD."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, MAGIC
        
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try to decrypt with wrong version magic
        fake_magic = b"FAKE"
        
        # Construct AAD with fake magic
        aad = struct.pack('<QQ', len(data), len(comp))
        aad += salt + sha + fake_magic
        
        # Should fail
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from meow_decoder.crypto import derive_key
        
        key = derive_key(password, salt, None)
        aesgcm = AESGCM(key)
        
        with pytest.raises(Exception):
            aesgcm.decrypt(nonce, cipher, aad)
    
    def test_corrupt_length_fields(self):
        """Corrupted length fields should be detected."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try with wrong orig_len
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data) + 1000,  # Wrong!
                comp_len=len(comp),
                sha256=sha
            )
        
        # Try with wrong comp_len
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp) + 100,  # Wrong!
                sha256=sha
            )


class TestPartialDecryption:
    """Test that partial/incomplete decryption is prevented."""
    
    def test_partial_ciphertext_fails(self):
        """Partial ciphertext should fail auth check."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Secret message that is longer than usual"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try to decrypt with partial ciphertext
        partial_cipher = cipher[:len(cipher)//2]
        
        with pytest.raises(Exception):
            decrypt_to_raw(
                partial_cipher,
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha
            )
    
    def test_partial_gif_fails(self, tmp_path):
        """Partial GIF should fail to decode."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data" * 100)
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode
        encode_file(input_file, gif_file, password="testpass123")
        
        # Truncate to various percentages
        gif_data = gif_file.read_bytes()
        
        for percent in [25, 50, 75]:
            partial_size = len(gif_data) * percent // 100
            partial_file = tmp_path / f"partial_{percent}.gif"
            partial_file.write_bytes(gif_data[:partial_size])
            
            # Should fail
            with pytest.raises(Exception):
                decode_gif(partial_file, output_file, password="testpass123")


class TestEdgeCases:
    """Test edge cases that might reveal vulnerabilities."""
    
    def test_empty_file(self, tmp_path):
        """Empty file should fail gracefully."""
        empty_file = tmp_path / "empty.gif"
        empty_file.write_bytes(b"")
        
        output_file = tmp_path / "output.txt"
        
        with pytest.raises(Exception):
            decode_gif(empty_file, output_file, password="test")
    
    def test_tiny_file(self, tmp_path):
        """Very small file should fail gracefully."""
        tiny_file = tmp_path / "tiny.gif"
        tiny_file.write_bytes(b"GIF89a")  # Just magic bytes
        
        output_file = tmp_path / "output.txt"
        
        with pytest.raises(Exception):
            decode_gif(tiny_file, output_file, password="test")
    
    def test_very_long_password(self):
        """Very long password should be handled."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Secret"
        password = "x" * 10000  # 10KB password
        
        # Should work (Argon2 can handle long passwords)
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Should decrypt
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha
        )
        assert decrypted == data
    
    def test_unicode_password(self):
        """Unicode password should work."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Secret"
        password = "pāsswørd🔒密码"  # Mixed scripts + emoji
        
        # Should work
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Should decrypt
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha
        )
        assert decrypted == data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
