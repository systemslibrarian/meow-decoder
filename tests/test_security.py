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
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
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
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
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
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(data, password, None, None)
            
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
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(data, password, None, None)
            nonces.append(nonce)
        
        # Nonces should be 12 bytes
        for nonce in nonces:
            assert len(nonce) == 12, "Nonce should be 12 bytes"
        
        # Nonces should not be sequential or predictable
        # Check that they're not all similar
        # 10 nonces × 12 bytes = 120 bytes total
        # Expect ~95% unique (114 unique) for truly random
        # Threshold: ≥85 unique bytes (allows more collisions due to birthday paradox with small sample)
        unique_bytes = len(set(b for nonce in nonces for b in nonce))
        assert unique_bytes >= 85, f"Nonces appear non-random (only {unique_bytes}/120 unique bytes)"


class TestForwardSecrecy:
    """Test forward secrecy mode."""
    
    @pytest.mark.skipif(
        not _has_x25519(),
        reason="X25519 support not available"
    )
    def test_forward_secrecy_roundtrip(self, tmp_path):
        """Forward secrecy mode should work end-to-end."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        from cryptography.hazmat.primitives import serialization
        
        # Generate receiver keys (returns key objects)
        privkey_obj, pubkey_obj = generate_receiver_keypair()
        
        # Serialize BOTH to Raw bytes (32 bytes each)
        privkey = privkey_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pubkey = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Save keys to files
        privkey_file = tmp_path / "receiver_private.key"
        pubkey_file = tmp_path / "receiver_public.key"
        privkey_file.write_bytes(privkey)
        pubkey_file.write_bytes(pubkey)
        
        # Create test file
        input_file = tmp_path / "test.txt"
        input_file.write_text("Forward secrecy test data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with forward secrecy (use serialized bytes)
        encode_file(
            input_file,
            gif_file,
            password="testpass123",
            receiver_public_key=pubkey  # 32 bytes
        )
        
        # Decode with receiver private key (use serialized bytes)
        decode_gif(
            gif_file,
            output_file,
            password="testpass123",
            receiver_private_key=privkey  # 32 bytes
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
        from cryptography.hazmat.primitives import serialization
        
        # Generate two keypairs (returns key objects)
        privkey1_obj, pubkey1_obj = generate_receiver_keypair()
        privkey2_obj, pubkey2_obj = generate_receiver_keypair()
        
        # Serialize to Raw bytes (32 bytes each)
        privkey2 = privkey2_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pubkey1 = pubkey1_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Create test file
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode with pubkey1 (use serialized bytes)
        encode_file(
            input_file,
            gif_file,
            password="testpass123",
            receiver_public_key=pubkey1  # 32 bytes
        )
        
        # Try to decode with privkey2 (wrong key, use serialized bytes)
        with pytest.raises(Exception):
            decode_gif(
                gif_file,
                output_file,
                password="testpass123",
                receiver_private_key=privkey2  # 32 bytes
            )


class TestAuthenticationCoverage:
    """Test that all critical fields are authenticated."""
    
    def test_version_authenticated(self):
        """Version field should be protected by AAD."""
        data = b"Secret message"
        password = "testpass123"
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
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
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
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


class TestFrameMACAuthentication:
    """Tests for frame-level MAC authentication."""
    
    def test_frame_mac_computation(self):
        """Test basic frame MAC computation."""
        from meow_decoder.frame_mac import compute_frame_mac, verify_frame_mac, MAC_SIZE
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_data = b"Test frame data"
        frame_index = 42
        
        # Compute MAC
        mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
        assert len(mac) == MAC_SIZE
        
        # Verify valid MAC
        assert verify_frame_mac(frame_data, mac, master_key, frame_index, salt) is True
        
        # Wrong frame index should fail
        assert verify_frame_mac(frame_data, mac, master_key, 999, salt) is False
        
        # Wrong key should fail
        wrong_key = secrets.token_bytes(32)
        assert verify_frame_mac(frame_data, mac, wrong_key, frame_index, salt) is False
        
        # Wrong salt should fail
        wrong_salt = secrets.token_bytes(16)
        assert verify_frame_mac(frame_data, mac, master_key, frame_index, wrong_salt) is False
    
    def test_frame_mac_pack_unpack(self):
        """Test frame packing and unpacking with MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac, MAC_SIZE
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_data = b"Test droplet data for fountain code"
        frame_index = 7
        
        # Pack frame
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        assert len(packed) == MAC_SIZE + len(frame_data)
        
        # Unpack valid frame
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)
        assert valid is True
        assert unpacked == frame_data
        
        # Unpack with wrong key should fail
        wrong_key = secrets.token_bytes(32)
        valid2, unpacked2 = unpack_frame_with_mac(packed, wrong_key, frame_index, salt)
        assert valid2 is False
        assert unpacked2 == b''
    
    def test_frame_mac_tamper_detection(self):
        """Tampered frame data should fail MAC verification."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_data = b"Original data"
        frame_index = 5
        
        # Pack frame
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        
        # Tamper with packed data (flip bit in data portion)
        tampered = bytearray(packed)
        tampered[10] ^= 0xFF  # Flip bit in data section
        
        # Should fail verification
        valid, unpacked = unpack_frame_with_mac(bytes(tampered), master_key, frame_index, salt)
        assert valid is False
    
    def test_frame_mac_wrong_size_rejected(self):
        """MAC with wrong size should be rejected."""
        from meow_decoder.frame_mac import verify_frame_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_data = b"Test data"
        
        # Wrong size MAC should fail
        wrong_size_mac = secrets.token_bytes(10)  # Wrong size
        assert verify_frame_mac(frame_data, wrong_size_mac, master_key, 0, salt) is False
    
    def test_frame_mac_too_short_packed(self):
        """Too short packed frame should be rejected."""
        from meow_decoder.frame_mac import unpack_frame_with_mac, MAC_SIZE
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Too short packed frame
        short_packed = secrets.token_bytes(MAC_SIZE - 1)
        valid, data = unpack_frame_with_mac(short_packed, master_key, 0, salt)
        assert valid is False
        assert data == b''
    
    def test_frame_mac_stats(self):
        """Test frame MAC statistics tracking."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        # Initial state
        assert stats.total_frames == 0
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 0
        assert stats.success_rate() == 0.0
        
        # Record some valid frames
        for _ in range(8):
            stats.record_valid()
        
        # Record some invalid frames
        for _ in range(2):
            stats.record_invalid()
        
        assert stats.total_frames == 10
        assert stats.valid_frames == 8
        assert stats.invalid_frames == 2
        assert stats.injection_attempts == 2
        assert stats.success_rate() == 0.8
        
        # Test report generation
        report = stats.report()
        assert "Total frames: 10" in report
        assert "Valid frames: 8" in report
        assert "80.0%" in report


class TestCryptoSecurityProperties:
    """Tests for cryptographic security properties."""
    
    def test_derive_key_basic(self):
        """Test basic key derivation."""
        from meow_decoder.crypto import derive_key
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        # Derive key
        key = derive_key(password, salt)
        assert len(key) == 32
        
        # Same inputs should give same output
        key2 = derive_key(password, salt)
        assert key == key2
        
        # Different salt should give different key
        salt2 = secrets.token_bytes(16)
        key3 = derive_key(password, salt2)
        assert key != key3
    
    def test_derive_key_empty_password_rejected(self):
        """Empty password should be rejected."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="empty"):
            derive_key("", salt)
    
    def test_derive_key_wrong_salt_length_rejected(self):
        """Wrong salt length should be rejected."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("password", b"short")
    
    def test_manifest_pack_unpack(self):
        """Test manifest serialization."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=12345,
            comp_len=10000,
            cipher_len=10016,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=20,
            hmac=secrets.token_bytes(32)
        )
        
        # Pack and unpack
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.salt == manifest.salt
        assert unpacked.nonce == manifest.nonce
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.cipher_len == manifest.cipher_len
    
    def test_manifest_with_fs_key(self):
        """Test manifest with forward secrecy ephemeral key."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        ephemeral_key = secrets.token_bytes(32)
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=5000,
            comp_len=4000,
            cipher_len=4016,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=16,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=ephemeral_key
        )
        
        packed = pack_manifest(manifest)
        assert len(packed) == 147  # Base 115 + 32 for FS key
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key == ephemeral_key
    
    def test_manifest_hmac_verification(self):
        """Test manifest HMAC computation and verification."""
        from meow_decoder.crypto import (
            Manifest, pack_manifest, compute_manifest_hmac, verify_manifest_hmac, MAGIC
        )
        import struct
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=4,
            hmac=b'\x00' * 32  # Placeholder
        )
        
        # Build packed manifest without HMAC
        packed_no_hmac = (
            MAGIC +
            manifest.salt +
            manifest.nonce +
            struct.pack(">III", manifest.orig_len, manifest.comp_len, manifest.cipher_len) +
            struct.pack(">HI", manifest.block_size, manifest.k_blocks) +
            manifest.sha256
        )
        
        # Compute HMAC
        hmac_tag = compute_manifest_hmac(password, salt, packed_no_hmac)
        manifest.hmac = hmac_tag
        
        # Verify HMAC
        assert verify_manifest_hmac(password, manifest) is True
        
        # Wrong password should fail
        assert verify_manifest_hmac("wrong_password", manifest) is False


class TestFountainCodeSecurity:
    """Tests for fountain code security properties."""
    
    def test_fountain_encode_decode(self):
        """Test basic fountain encoding/decoding."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Test data for fountain coding " * 10
        k_blocks = 5
        block_size = 64
        
        # Encode
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Decode with some redundancy
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))
        
        droplets_added = 0
        while not decoder.is_complete() and droplets_added < k_blocks * 2:
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            droplets_added += 1
        
        assert decoder.is_complete()
        recovered = decoder.get_data()
        assert recovered == data
    
    def test_fountain_redundancy(self):
        """Fountain codes should tolerate frame loss."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Secret data that must survive frame loss " * 5
        k_blocks = 4
        block_size = 64
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate extra droplets (redundancy)
        all_droplets = [encoder.droplet() for _ in range(k_blocks * 3)]
        
        # Skip some droplets (simulate loss)
        selected = all_droplets[::2]  # Take every other droplet
        
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))
        for droplet in selected:
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
    
    def test_fountain_droplet_packing(self):
        """Test droplet serialization."""
        from meow_decoder.fountain import (
            FountainEncoder, pack_droplet, unpack_droplet
        )
        
        data = b"Test data" * 20
        encoder = FountainEncoder(data, 5, 64)
        
        droplet = encoder.droplet()
        
        # Pack and unpack
        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, 64)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data


class TestCryptoEdgeCases:
    """Test crypto edge cases to increase coverage."""
    
    def test_derive_key_with_keyfile(self):
        """Test key derivation with keyfile."""
        from meow_decoder.crypto import derive_key
        import secrets
        
        password = "testpass"
        salt = secrets.token_bytes(16)
        keyfile = b"keyfile_content_at_least_32_bytes_long"
        
        # With keyfile
        key_with_kf = derive_key(password, salt, keyfile)
        assert len(key_with_kf) == 32
        
        # Without keyfile should be different
        key_without_kf = derive_key(password, salt, None)
        assert key_with_kf != key_without_kf
    
    def test_derive_key_empty_password_fails(self):
        """Empty password should raise ValueError."""
        from meow_decoder.crypto import derive_key
        import secrets
        
        salt = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="Password cannot be empty"):
            derive_key("", salt)
    
    def test_derive_key_wrong_salt_length(self):
        """Wrong salt length should raise ValueError."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_key("password", b"short")
    
    def test_encrypt_with_forward_secrecy_directly(self):
        """Test encrypt_file_bytes with forward secrecy."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        from cryptography.hazmat.primitives import serialization
        
        # Generate receiver keypair
        privkey_obj, pubkey_obj = generate_receiver_keypair()
        
        pubkey = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        privkey = privkey_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Encrypt with forward secrecy
        data = b"Forward secrecy test data"
        password = "testpass"
        
        comp, sha, salt, nonce, cipher, ephemeral_pubkey, _ = encrypt_file_bytes(
            data, password, None, pubkey, use_length_padding=True
        )
        
        # ephemeral_pubkey should be set
        assert ephemeral_pubkey is not None
        assert len(ephemeral_pubkey) == 32
        
        # Decrypt with forward secrecy
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, None,
            len(data), len(comp), sha,
            ephemeral_pubkey, privkey
        )
        
        assert decrypted == data
    
    def test_decrypt_fs_missing_private_key(self):
        """Forward secrecy decryption without private key should fail."""
        from meow_decoder.crypto import decrypt_to_raw
        
        # Create dummy data with ephemeral key present (forward secrecy mode)
        # ValueError gets wrapped in RuntimeError by decrypt_to_raw
        with pytest.raises(RuntimeError, match="Forward secrecy mode requires receiver private key"):
            decrypt_to_raw(
                b"cipher", "password", b"0" * 16, b"0" * 12, None,
                100, 50, b"0" * 32,
                ephemeral_public_key=b"0" * 32,  # Triggers FS mode
                receiver_private_key=None  # Missing!
            )
    
    def test_manifest_too_short(self):
        """Manifest too short should raise ValueError."""
        from meow_decoder.crypto import unpack_manifest
        
        with pytest.raises(ValueError, match="Manifest too short"):
            unpack_manifest(b"short")
    
    def test_manifest_invalid_length(self):
        """Manifest with invalid length should raise ValueError."""
        from meow_decoder.crypto import unpack_manifest, MAGIC
        
        # Create manifest with wrong length (not 115, 147, or 1235)
        invalid = MAGIC + b"0" * 150  # 155 bytes total (invalid)
        
        with pytest.raises(ValueError, match="Manifest length invalid"):
            unpack_manifest(invalid)
    
    def test_manifest_invalid_magic(self):
        """Manifest with invalid magic should raise ValueError."""
        from meow_decoder.crypto import unpack_manifest
        
        # 115 bytes with wrong magic
        invalid = b"XXXX" + b"0" + b"0" * 110
        
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(invalid)
    
    def test_manifest_meow2_backward_compat(self):
        """MEOW2 manifests should be parseable for backward compatibility."""
        from meow_decoder.crypto import unpack_manifest, Manifest, MAGIC
        import struct
        
        # Build a MEOW2 manifest (115 bytes)
        magic = b"MEOW2"  # Old magic
        salt = b"0" * 16
        nonce = b"0" * 12
        orig_len, comp_len, cipher_len = 100, 80, 96
        block_size, k_blocks = 512, 10
        sha = b"0" * 32
        hmac_tag = b"0" * 32
        
        manifest_bytes = (
            magic +
            salt +
            nonce +
            struct.pack(">III", orig_len, comp_len, cipher_len) +
            struct.pack(">HI", block_size, k_blocks) +
            sha +
            hmac_tag
        )
        
        # Should parse without error (backward compat)
        m = unpack_manifest(manifest_bytes)
        assert m.orig_len == 100
        assert m.block_size == 512
    
    def test_pack_manifest_with_fs(self):
        """Test packing manifest with forward secrecy key."""
        from meow_decoder.crypto import pack_manifest, unpack_manifest, Manifest
        
        m = Manifest(
            salt=b"0" * 16,
            nonce=b"0" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"0" * 32,
            block_size=512,
            k_blocks=10,
            hmac=b"0" * 32,
            ephemeral_public_key=b"1" * 32  # Forward secrecy
        )
        
        packed = pack_manifest(m)
        assert len(packed) == 147  # 115 + 32
        
        # Unpack and verify
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key == b"1" * 32
    
    def test_pack_manifest_invalid_ephemeral_key_length(self):
        """Invalid ephemeral key length should raise ValueError."""
        from meow_decoder.crypto import pack_manifest, Manifest
        
        m = Manifest(
            salt=b"0" * 16,
            nonce=b"0" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"0" * 32,
            block_size=512,
            k_blocks=10,
            hmac=b"0" * 32,
            ephemeral_public_key=b"wrong_length"  # Not 32 bytes
        )
        
        with pytest.raises(ValueError, match="Ephemeral public key must be 32 bytes"):
            pack_manifest(m)
    
    def test_hmac_with_encryption_key(self):
        """Test compute_manifest_hmac with pre-derived encryption key."""
        from meow_decoder.crypto import compute_manifest_hmac
        import secrets
        
        password = "testpass"
        salt = secrets.token_bytes(16)
        packed_no_hmac = b"manifest_data_here"
        encryption_key = secrets.token_bytes(32)
        
        # With encryption_key provided
        hmac1 = compute_manifest_hmac(password, salt, packed_no_hmac, 
                                      encryption_key=encryption_key)
        
        # Same key should give same HMAC
        hmac2 = compute_manifest_hmac(password, salt, packed_no_hmac,
                                      encryption_key=encryption_key)
        
        assert hmac1 == hmac2
        assert len(hmac1) == 32


class TestFountainEdgeCases:
    """Test fountain code edge cases."""
    
    def test_soliton_distribution_small_k(self):
        """Test Robust Soliton with very small k."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        # k=1 edge case
        dist = RobustSolitonDistribution(k=1)
        degree = dist.sample_degree()
        assert degree >= 1
        
        # k=2 edge case
        dist2 = RobustSolitonDistribution(k=2)
        degree2 = dist2.sample_degree()
        assert degree2 >= 1
    
    def test_fountain_decoder_incomplete(self):
        """Test decoder raises when incomplete."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(10, 64, original_length=100)
        
        # Don't add any droplets - should not be complete
        assert not decoder.is_complete()
        
        with pytest.raises(RuntimeError, match="Decoding incomplete"):
            decoder.get_data()
    
    def test_fountain_decoder_no_original_length(self):
        """Test decoder raises when original_length not provided."""
        from meow_decoder.fountain import FountainDecoder, FountainEncoder
        
        data = b"Test" * 20  # 80 bytes
        encoder = FountainEncoder(data, 5, 64)
        
        # Create decoder without original_length
        decoder = FountainDecoder(5, 64)  # No original_length!
        
        # Add droplets until complete
        while not decoder.is_complete():
            decoder.add_droplet(encoder.droplet())
        
        # Should raise because original_length not provided
        with pytest.raises(ValueError, match="original_length must be provided"):
            decoder.get_data()


class TestKeyfileValidation:
    """Test keyfile validation edge cases."""
    
    def test_verify_keyfile_not_found(self, tmp_path):
        """Missing keyfile should raise FileNotFoundError."""
        from meow_decoder.crypto import verify_keyfile
        
        with pytest.raises(FileNotFoundError):
            verify_keyfile(str(tmp_path / "nonexistent.key"))
    
    def test_verify_keyfile_too_small(self, tmp_path):
        """Keyfile under 32 bytes should raise ValueError."""
        from meow_decoder.crypto import verify_keyfile
        
        keyfile = tmp_path / "small.key"
        keyfile.write_bytes(b"too_short")  # Only 9 bytes
        
        with pytest.raises(ValueError, match="Keyfile too small"):
            verify_keyfile(str(keyfile))
    
    def test_verify_keyfile_valid(self, tmp_path):
        """Valid keyfile should be read successfully."""
        from meow_decoder.crypto import verify_keyfile
        import secrets
        
        keyfile = tmp_path / "valid.key"
        keyfile.write_bytes(secrets.token_bytes(64))
        
        data = verify_keyfile(str(keyfile))
        assert len(data) == 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

