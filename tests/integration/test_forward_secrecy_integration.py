#!/usr/bin/env python3
"""
🔐 Forward Secrecy Integration Tests - CANONICAL INTEGRATION FILE

Consolidated integration tests for Forward Secrecy functionality.
Tests complete encode/decode flow with X25519 ephemeral keys.

Merged from:
- test_forward_secrecy.py (E2E encryption tests)
- test_cli_forward_secrecy.py (CLI integration tests)
- test_fs_integration.py (key generation/load/save tests)

This is the CANONICAL integration test file for forward secrecy.
Unit tests are in tests/test_forward_secrecy_*.py files.
"""

import sys
import os
import subprocess
import tempfile
import secrets
from pathlib import Path
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# CLI HELPER
# =============================================================================

def run_command(cmd, input_text=None, **kwargs):
    """Run command and return result."""
    result = subprocess.run(cmd, capture_output=True, text=True, input=input_text, **kwargs)
    return result


# =============================================================================
# KEY GENERATION TESTS
# =============================================================================

class TestKeyGeneration:
    """Tests for X25519 key generation and management."""
    
    def test_generate_keypair(self):
        """Test generating receiver keypair programmatically."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        # Both should be 32 bytes (raw X25519 keys)
        assert len(receiver_priv) == 32, f"Private key wrong size: {len(receiver_priv)}"
        assert len(receiver_pub) == 32, f"Public key wrong size: {len(receiver_pub)}"
    
    def test_save_and_load_keypair(self):
        """Test saving and loading keypair to/from files."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair,
            serialize_public_key
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Generate keypair
            receiver_priv, receiver_pub = generate_receiver_keypair()
            
            # Save to files
            privkey_file = tmpdir / "receiver_private.pem"
            pubkey_file = tmpdir / "receiver_public.key"
            
            save_receiver_keypair(
                receiver_priv, receiver_pub,
                str(privkey_file), str(pubkey_file),
                "test_password"
            )
            
            # Verify files exist
            assert privkey_file.exists(), "Private key file not created"
            assert pubkey_file.exists(), "Public key file not created"
            
            # Verify public key size (raw 32 bytes)
            pubkey_data = pubkey_file.read_bytes()
            assert len(pubkey_data) == 32, f"Public key wrong size: {len(pubkey_data)}"
            
            # Load back
            loaded_priv, loaded_pub = load_receiver_keypair(
                str(privkey_file), str(pubkey_file), "test_password"
            )
            
            # Verify they match
            original_pub_bytes = serialize_public_key(receiver_pub)
            loaded_pub_bytes = serialize_public_key(loaded_pub)
            assert original_pub_bytes == loaded_pub_bytes, "Public keys don't match"
    
    def test_cli_key_generation(self):
        """Test generating receiver keypair via CLI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Generate keys via CLI
            result = run_command([
                sys.executable, "-m", "meow_decoder.encode",
                "--generate-keys",
                "--key-output-dir", str(tmpdir)
            ], input_text="test_password\ntest_password\n")
            
            assert result.returncode == 0, f"Key generation failed: {result.stderr}"
            
            # Check files exist
            privkey = tmpdir / "receiver_private.pem"
            pubkey = tmpdir / "receiver_public.key"
            
            assert privkey.exists(), f"Private key not generated: {privkey}"
            assert pubkey.exists(), f"Public key not generated: {pubkey}"
            
            # Check public key size
            pubkey_data = pubkey.read_bytes()
            assert len(pubkey_data) == 32, f"Public key wrong size: {len(pubkey_data)}"


# =============================================================================
# ENCRYPTION/DECRYPTION ROUNDTRIP TESTS
# =============================================================================

class TestEncryptionRoundtrip:
    """Tests for encryption/decryption with forward secrecy."""
    
    def test_forward_secrecy_mode(self):
        """Test forward secrecy mode with X25519 ephemeral keys."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            serialize_public_key
        )
        
        plaintext = b"Secret message with forward secrecy!"
        password = "test_password_456"
        
        # Generate receiver keypair
        receiver_private, receiver_public = generate_receiver_keypair()
        receiver_public_bytes = serialize_public_key(receiver_public)
        
        # Encrypt with forward secrecy
        comp, sha, salt, nonce, cipher, ephemeral_pub, encryption_key = encrypt_file_bytes(
            plaintext, password, None, receiver_public_bytes
        )
        
        assert ephemeral_pub is not None, "Ephemeral key should be present"
        assert len(ephemeral_pub) == 32, f"Ephemeral key wrong size: {len(ephemeral_pub)}"
        
        # Decrypt with forward secrecy
        receiver_private_bytes = receiver_private
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, None,
            len(plaintext), len(comp), sha,
            ephemeral_pub, receiver_private_bytes
        )
        
        assert decrypted == plaintext, "Decrypted data doesn't match!"
    
    def test_password_only_mode(self):
        """Test backward-compatible password-only mode."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        plaintext = b"Secret without forward secrecy"
        password = "test_password_789"
        
        # Encrypt without receiver public key
        comp, sha, salt, nonce, cipher, ephemeral_pub, encryption_key = encrypt_file_bytes(
            plaintext, password, None, None  # No receiver pubkey
        )
        
        assert ephemeral_pub is None, "Ephemeral key should be None in password-only mode"
        
        # Decrypt without receiver private key
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, None,
            len(plaintext), len(comp), sha,
            None, None  # No ephemeral key, no receiver privkey
        )
        
        assert decrypted == plaintext, "Decrypted data doesn't match!"
    
    def test_wrong_password_fails(self):
        """Test that wrong password fails properly."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            serialize_public_key
        )
        
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
        
        # Try to decrypt with wrong password
        receiver_private_bytes = receiver_private
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce, None,
                len(plaintext), len(comp), sha,
                ephemeral_pub, receiver_private_bytes
            )


# =============================================================================
# MANIFEST PACKING TESTS
# =============================================================================

class TestManifestPacking:
    """Tests for manifest packing/unpacking with forward secrecy."""
    
    def test_password_only_manifest(self):
        """Test password-only manifest (115 bytes)."""
        from meow_decoder.crypto import pack_manifest, unpack_manifest, Manifest
        
        manifest = Manifest(
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
        
        packed = pack_manifest(manifest)
        assert len(packed) == 115, f"Password-only manifest wrong size: {len(packed)}"
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key is None, "Should be None"
    
    def test_forward_secrecy_manifest(self):
        """Test forward secrecy manifest (147 bytes)."""
        from meow_decoder.crypto import pack_manifest, unpack_manifest, Manifest
        
        ephemeral_key = secrets.token_bytes(32)
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=ephemeral_key
        )
        
        packed = pack_manifest(manifest)
        assert len(packed) == 147, f"Forward secrecy manifest wrong size: {len(packed)}"
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key is not None, "Should have ephemeral key"
        assert len(unpacked.ephemeral_public_key) == 32, "Ephemeral key wrong size"
        assert unpacked.ephemeral_public_key == ephemeral_key, "Ephemeral key mismatch"


# =============================================================================
# FULL CLI ENCODE/DECODE TESTS
# =============================================================================

class TestCLIIntegration:
    """End-to-end CLI tests for forward secrecy."""
    
    @pytest.mark.slow
    def test_cli_encode_decode_with_fs(self):
        """Test complete CLI encode/decode flow with forward secrecy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Test data
            test_file = tmpdir / "test_input.txt"
            test_file.write_text("Secret message with forward secrecy! 🔐")
            
            gif_file = tmpdir / "test.gif"
            output_file = tmpdir / "test_output.txt"
            
            # Generate keys
            result = run_command([
                sys.executable, "-m", "meow_decoder.encode",
                "--generate-keys",
                "--key-output-dir", str(tmpdir)
            ], input_text="keypass123\nkeypass123\n")
            
            assert result.returncode == 0, f"Key generation failed: {result.stderr}"
            
            privkey = tmpdir / "receiver_private.pem"
            pubkey = tmpdir / "receiver_public.key"
            
            # Encode with forward secrecy
            result = run_command([
                sys.executable, "-m", "meow_decoder.encode",
                "-i", str(test_file),
                "-o", str(gif_file),
                "-p", "test_password_123",
                "--receiver-pubkey", str(pubkey)
            ])
            
            assert result.returncode == 0, f"Encoding failed: {result.stderr}"
            assert gif_file.exists(), f"GIF not created: {gif_file}"
            
            # Decode with forward secrecy
            result = run_command([
                sys.executable, "-m", "meow_decoder.decode_gif",
                "-i", str(gif_file),
                "-o", str(output_file),
                "-p", "test_password_123",
                "--receiver-privkey", str(privkey),
                "--receiver-privkey-password", "keypass123"
            ])
            
            assert result.returncode == 0, f"Decoding failed: {result.stderr}"
            assert output_file.exists(), f"Output not created: {output_file}"
            
            # Verify content
            original = test_file.read_text()
            decoded = output_file.read_text()
            assert original == decoded, "Content mismatch!"
    
    @pytest.mark.slow
    def test_cli_password_only_mode(self):
        """Test CLI password-only mode (no forward secrecy)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Test data
            test_file = tmpdir / "test_input.txt"
            test_file.write_text("Secret without forward secrecy")
            
            gif_file = tmpdir / "test.gif"
            output_file = tmpdir / "test_output.txt"
            
            # Encode without receiver pubkey (password-only)
            result = run_command([
                sys.executable, "-m", "meow_decoder.encode",
                "-i", str(test_file),
                "-o", str(gif_file),
                "-p", "test_password_456"
            ])
            
            assert result.returncode == 0, f"Encoding failed: {result.stderr}"
            
            # Decode without receiver privkey (password-only)
            result = run_command([
                sys.executable, "-m", "meow_decoder.decode_gif",
                "-i", str(gif_file),
                "-o", str(output_file),
                "-p", "test_password_456"
            ])
            
            assert result.returncode == 0, f"Decoding failed: {result.stderr}"
            
            # Verify
            original = test_file.read_text()
            decoded = output_file.read_text()
            assert original == decoded, "Content mismatch!"


# =============================================================================
# MAIN (for standalone execution)
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
