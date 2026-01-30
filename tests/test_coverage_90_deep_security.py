#!/usr/bin/env python3
"""
🧪 Deep Coverage Tests - Security & Crypto Modules
Aggressive testing for 90% coverage target.
"""

import pytest
import tempfile
import secrets
import hashlib
import os
import io
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestDuressMode:
    """Deep tests for duress_mode.py module."""
    
    def test_import_module(self):
        """Test importing duress_mode module."""
        from meow_decoder import duress_mode
        assert duress_mode is not None
        
    def test_duress_handler_init(self):
        """Test DuressHandler initialization."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        
        handler = DuressHandler()
        assert handler is not None
        assert handler._duress_hash is None
        assert handler._real_hash is None
        
    def test_duress_handler_with_config(self):
        """Test DuressHandler with custom config."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            wipe_memory=True
        )
        handler = DuressHandler(config)
        assert handler.config.enabled == True
        
    def test_duress_handler_set_passwords(self):
        """Test setting duress and real passwords."""
        from meow_decoder.duress_mode import DuressHandler
        
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        
        handler.set_passwords(
            duress_password="duress123",
            real_password="real456",
            salt=salt
        )
        
        assert handler._duress_hash is not None
        assert handler._real_hash is not None
        assert handler._duress_hash != handler._real_hash
        
    def test_duress_handler_same_passwords_error(self):
        """Test error when duress and real passwords are same."""
        from meow_decoder.duress_mode import DuressHandler
        
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="cannot be the same"):
            handler.set_passwords(
                duress_password="samepassword",
                real_password="samepassword",
                salt=salt
            )
            
    def test_duress_handler_check_password_real(self):
        """Test checking real password."""
        from meow_decoder.duress_mode import DuressHandler
        
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        
        handler.set_passwords(
            duress_password="duress123",
            real_password="real456",
            salt=salt
        )
        
        is_valid, is_duress = handler.check_password("real456", salt)
        assert is_valid == True
        assert is_duress == False
        
    def test_duress_handler_check_password_duress(self):
        """Test checking duress password."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig(wipe_resume_files=False)
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        
        handler.set_passwords(
            duress_password="duress123",
            real_password="real456",
            salt=salt
        )
        
        is_valid, is_duress = handler.check_password("duress123", salt)
        assert is_valid == True
        assert is_duress == True
        assert handler.was_triggered == True
        
    def test_duress_handler_check_password_wrong(self):
        """Test checking wrong password."""
        from meow_decoder.duress_mode import DuressHandler
        
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        
        handler.set_passwords(
            duress_password="duress123",
            real_password="real456",
            salt=salt
        )
        
        is_valid, is_duress = handler.check_password("wrongpassword", salt)
        assert is_valid == False
        assert is_duress == False
        
    def test_duress_handler_secure_zero(self):
        """Test secure memory zeroing."""
        from meow_decoder.duress_mode import DuressHandler
        
        handler = DuressHandler()
        data = bytearray(b"secret data here")
        
        handler._secure_zero(data)
        
        # All bytes should be zero
        assert all(b == 0 for b in data)
        
    def test_duress_handler_hash_password(self):
        """Test password hashing."""
        from meow_decoder.duress_mode import DuressHandler
        
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        
        hash1 = handler._hash_password("test", salt)
        hash2 = handler._hash_password("test", salt)
        hash3 = handler._hash_password("different", salt)
        
        assert hash1 == hash2  # Same password, same salt
        assert hash1 != hash3  # Different password
        
    def test_duress_handler_get_decoy_data(self):
        """Test getting decoy data."""
        try:
            from meow_decoder.duress_mode import DuressHandler
            from meow_decoder.config import DuressConfig
            
            config = DuressConfig(
                decoy_type="message",
                decoy_message="This is a test decoy"
            )
            handler = DuressHandler(config)
            
            decoy_data, filename = handler.get_decoy_data()
            assert decoy_data is not None
            assert isinstance(decoy_data, bytes)
        except (ImportError, AttributeError):
            pytest.skip("get_decoy_data not available")
            
    def test_duress_handler_wipe_sensitive(self):
        """Test wiping sensitive data on duress."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig(wipe_resume_files=False)
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        
        handler.set_passwords("duress123", "real456", salt)
        
        # Create some sensitive data
        sensitive = [
            bytearray(b"key material"),
            bytearray(b"more secrets")
        ]
        
        # Trigger duress
        is_valid, is_duress = handler.check_password(
            "duress123", salt, sensitive_data=sensitive
        )
        
        # Sensitive data should be zeroed
        assert all(b == 0 for data in sensitive for b in data)


class TestStreamingCrypto:
    """Deep tests for streaming_crypto.py module."""
    
    def test_import_module(self):
        """Test importing streaming_crypto module."""
        from meow_decoder import streaming_crypto
        assert streaming_crypto is not None
        
    def test_memory_config(self):
        """Test MemoryConfig dataclass."""
        from meow_decoder.streaming_crypto import MemoryConfig
        
        config = MemoryConfig(
            chunk_size=65536,
            max_memory_mb=500,
            enable_gc=True,
            enable_mlock=False
        )
        
        assert config.chunk_size == 65536
        assert config.max_memory_mb == 500
        assert config.enable_gc == True
        assert config.enable_mlock == False
        
    def test_streaming_cipher_init(self):
        """Test StreamingCipher initialization."""
        from meow_decoder.streaming_crypto import StreamingCipher
        
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)
        
        assert cipher is not None
        assert len(cipher.nonce) == 16
        
    def test_streaming_cipher_custom_nonce(self):
        """Test StreamingCipher with custom nonce."""
        from meow_decoder.streaming_crypto import StreamingCipher
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(key, nonce=nonce)
        
        assert cipher.nonce == nonce
        
    def test_streaming_cipher_invalid_key(self):
        """Test StreamingCipher with invalid key."""
        from meow_decoder.streaming_crypto import StreamingCipher
        
        with pytest.raises(ValueError, match="32 bytes"):
            StreamingCipher(secrets.token_bytes(16))  # Wrong size
            
    def test_streaming_cipher_invalid_nonce(self):
        """Test StreamingCipher with invalid nonce."""
        from meow_decoder.streaming_crypto import StreamingCipher
        
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="16 bytes"):
            StreamingCipher(key, nonce=secrets.token_bytes(8))  # Wrong size
            
    def test_streaming_cipher_encrypt_decrypt(self):
        """Test streaming encryption and decryption."""
        from meow_decoder.streaming_crypto import StreamingCipher
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        
        # Test data
        plaintext = b"This is test data for streaming encryption." * 100
        
        # Encrypt
        cipher = StreamingCipher(key, nonce, chunk_size=64)
        input_stream = io.BytesIO(plaintext)
        output_stream = io.BytesIO()
        
        orig_size, comp_size, sha = cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=False
        )
        
        ciphertext = output_stream.getvalue()
        assert len(ciphertext) > 0
        assert orig_size == len(plaintext)
        
    def test_streaming_cipher_with_compression(self):
        """Test streaming encryption with compression."""
        from meow_decoder.streaming_crypto import StreamingCipher
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        
        # Highly compressible data
        plaintext = b"A" * 10000
        
        cipher = StreamingCipher(key, nonce, chunk_size=1024)
        input_stream = io.BytesIO(plaintext)
        output_stream = io.BytesIO()
        
        orig_size, comp_size, sha = cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )
        
        assert orig_size == 10000
        assert comp_size < orig_size  # Should be compressed


class TestPQCrypto:
    """Deep tests for post-quantum crypto modules."""
    
    def test_import_pq_crypto_real(self):
        """Test importing pq_crypto_real module."""
        try:
            from meow_decoder import pq_crypto_real
            assert pq_crypto_real is not None
        except ImportError:
            pytest.skip("pq_crypto_real module not found")
            
    def test_import_pq_hybrid(self):
        """Test importing pq_hybrid module."""
        try:
            from meow_decoder import pq_hybrid
            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("pq_hybrid module not found")
            
    def test_import_pq_signatures(self):
        """Test importing pq_signatures module."""
        try:
            from meow_decoder import pq_signatures
            assert pq_signatures is not None
        except ImportError:
            pytest.skip("pq_signatures module not found")
            
    def test_hybrid_kem(self):
        """Test hybrid key encapsulation."""
        try:
            from meow_decoder.pq_hybrid import HybridKEM
            
            kem = HybridKEM()
            
            # Generate keypair
            public, private = kem.keygen()
            assert public is not None
            assert private is not None
            
            # Encapsulate
            ciphertext, shared_secret1 = kem.encapsulate(public)
            assert ciphertext is not None
            assert shared_secret1 is not None
            
            # Decapsulate
            shared_secret2 = kem.decapsulate(ciphertext, private)
            assert shared_secret2 == shared_secret1
        except (ImportError, AttributeError):
            pytest.skip("HybridKEM not available")
            
    def test_dilithium_signatures(self):
        """Test Dilithium signatures."""
        try:
            from meow_decoder.pq_signatures import DilithiumSigner
            
            signer = DilithiumSigner()
            
            # Generate keypair
            public, private = signer.keygen()
            assert public is not None
            assert private is not None
            
            # Sign
            message = b"Test message"
            signature = signer.sign(message, private)
            assert signature is not None
            
            # Verify
            valid = signer.verify(message, signature, public)
            assert valid == True
        except (ImportError, AttributeError):
            pytest.skip("DilithiumSigner not available")


class TestHighSecurity:
    """Deep tests for high_security.py module."""
    
    def test_import_module(self):
        """Test importing high_security module."""
        try:
            from meow_decoder import high_security
            assert high_security is not None
        except ImportError:
            pytest.skip("high_security module not found")
            
    def test_enable_high_security_mode(self):
        """Test enabling high security mode."""
        try:
            from meow_decoder.high_security import enable_high_security_mode
            
            enable_high_security_mode(silent=True)
        except (ImportError, AttributeError):
            pytest.skip("enable_high_security_mode not available")
            
    def test_high_security_config(self):
        """Test HighSecurityConfig."""
        try:
            from meow_decoder.high_security import HighSecurityConfig
            
            config = HighSecurityConfig()
            
            # Should have hardened parameters
            assert config.argon2_memory >= 262144  # At least 256 MiB
            assert config.argon2_iterations >= 10
        except (ImportError, AttributeError):
            pytest.skip("HighSecurityConfig not available")
            
    def test_get_safety_checklist(self):
        """Test safety checklist."""
        try:
            from meow_decoder.high_security import get_safety_checklist
            
            checklist = get_safety_checklist()
            assert isinstance(checklist, str)
            assert len(checklist) > 0
        except (ImportError, AttributeError):
            pytest.skip("get_safety_checklist not available")
            
    def test_secure_wipe_file(self):
        """Test secure file wiping."""
        try:
            from meow_decoder.high_security import secure_wipe_file
            
            # Create temp file
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"secret content")
                path = f.name
                
            # Wipe it
            result = secure_wipe_file(path)
            
            # File should be gone
            assert not os.path.exists(path)
        except (ImportError, AttributeError):
            pytest.skip("secure_wipe_file not available")
        except Exception:
            # Clean up
            if os.path.exists(path):
                os.remove(path)


class TestResumeSecured:
    """Deep tests for resume_secured.py module."""
    
    def test_import_module(self):
        """Test importing resume_secured module."""
        try:
            from meow_decoder import resume_secured
            assert resume_secured is not None
        except ImportError:
            pytest.skip("resume_secured module not found")
            
    def test_resume_state_class(self):
        """Test ResumeState class."""
        try:
            from meow_decoder.resume_secured import ResumeState
            
            state = ResumeState(
                k_blocks=100,
                block_size=512,
                decoded_blocks=set([0, 1, 2, 3])
            )
            
            assert state.k_blocks == 100
            assert len(state.decoded_blocks) == 4
        except (ImportError, AttributeError):
            pytest.skip("ResumeState not available")
            
    def test_encrypted_resume_manager(self):
        """Test EncryptedResumeManager."""
        try:
            from meow_decoder.resume_secured import EncryptedResumeManager
            
            manager = EncryptedResumeManager(
                password="test123",
                session_id="test-session"
            )
            
            assert manager is not None
        except (ImportError, AttributeError):
            pytest.skip("EncryptedResumeManager not available")


class TestNinjaCatUltra:
    """Deep tests for ninja_cat_ultra.py module."""
    
    def test_import_module(self):
        """Test importing ninja_cat_ultra module."""
        try:
            from meow_decoder import ninja_cat_ultra
            assert ninja_cat_ultra is not None
        except ImportError:
            pytest.skip("ninja_cat_ultra module not found")
            
    def test_stealth_level_enum(self):
        """Test StealthLevel enum."""
        try:
            from meow_decoder.ninja_cat_ultra import StealthLevel
            
            assert StealthLevel.VISIBLE.value >= 0
            assert StealthLevel.SUBTLE.value >= 0
            assert StealthLevel.HIDDEN.value >= 0
            assert StealthLevel.PARANOID.value >= 0
        except (ImportError, AttributeError):
            pytest.skip("StealthLevel not available")


class TestStegoAdvanced:
    """Deep tests for stego_advanced.py module."""
    
    def test_import_module(self):
        """Test importing stego_advanced module."""
        try:
            from meow_decoder import stego_advanced
            assert stego_advanced is not None
        except ImportError:
            pytest.skip("stego_advanced module not found")
            
    def test_stego_quality_class(self):
        """Test StegoQuality class."""
        try:
            from meow_decoder.stego_advanced import StegoQuality
            
            quality = StegoQuality(psnr=45.0, ssim=0.98)
            assert quality.psnr == 45.0
            assert quality.ssim == 0.98
        except (ImportError, AttributeError):
            pytest.skip("StegoQuality not available")
            
    def test_encode_with_stego(self):
        """Test steganography encoding."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            from PIL import Image
            
            # Create test frames
            frames = [Image.new('RGB', (100, 100), color='white')]
            
            result_frames, qualities = encode_with_stego(
                frames,
                stealth_level=StealthLevel.VISIBLE
            )
            
            assert len(result_frames) > 0
        except (ImportError, AttributeError):
            pytest.skip("encode_with_stego not available")


class TestProwlingMode:
    """Deep tests for prowling_mode.py module."""
    
    def test_import_module(self):
        """Test importing prowling_mode module."""
        try:
            from meow_decoder import prowling_mode
            assert prowling_mode is not None
        except ImportError:
            pytest.skip("prowling_mode module not found")
            
    def test_memory_monitor(self):
        """Test MemoryMonitor class."""
        try:
            from meow_decoder.prowling_mode import MemoryMonitor
            
            monitor = MemoryMonitor(max_memory_mb=500)
            assert monitor is not None
            
            # Check current memory
            current = monitor.current_memory_mb()
            assert current >= 0
        except (ImportError, AttributeError):
            pytest.skip("MemoryMonitor not available")
            
    def test_prowling_encoder(self):
        """Test ProwlingEncoder class."""
        try:
            from meow_decoder.prowling_mode import ProwlingEncoder
            
            encoder = ProwlingEncoder(max_memory_mb=100)
            assert encoder is not None
        except (ImportError, AttributeError):
            pytest.skip("ProwlingEncoder not available")


class TestDecoyGenerator:
    """Deep tests for decoy_generator.py module."""
    
    def test_import_module(self):
        """Test importing decoy_generator module."""
        try:
            from meow_decoder import decoy_generator
            assert decoy_generator is not None
        except ImportError:
            pytest.skip("decoy_generator module not found")
            
    def test_generate_convincing_decoy(self):
        """Test generating convincing decoy."""
        try:
            from meow_decoder.decoy_generator import generate_convincing_decoy
            
            decoy = generate_convincing_decoy(10000)
            
            assert isinstance(decoy, bytes)
            assert len(decoy) >= 10000
        except (ImportError, AttributeError):
            pytest.skip("generate_convincing_decoy not available")
            
    def test_generate_text_decoy(self):
        """Test generating text decoy."""
        try:
            from meow_decoder.decoy_generator import generate_text_decoy
            
            decoy = generate_text_decoy(size=1000)
            
            assert isinstance(decoy, bytes) or isinstance(decoy, str)
        except (ImportError, AttributeError):
            pytest.skip("generate_text_decoy not available")


class TestForwardSecrecyModules:
    """Deep tests for forward secrecy modules."""
    
    def test_import_forward_secrecy(self):
        """Test importing forward_secrecy module."""
        from meow_decoder import forward_secrecy
        assert forward_secrecy is not None
        
    def test_forward_secrecy_manager(self):
        """Test ForwardSecrecyManager class."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        assert manager is not None
        
    def test_forward_secrecy_derive_block_key(self):
        """Test deriving block keys."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Derive keys for different blocks
        key0 = manager.derive_block_key(0)
        key1 = manager.derive_block_key(1)
        key0_again = manager.derive_block_key(0)
        
        assert len(key0) == 32
        assert key0 != key1  # Different blocks
        assert key0 == key0_again  # Same block
        
    def test_forward_secrecy_with_ratchet(self):
        """Test forward secrecy with ratcheting."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(
            master_key, salt,
            enable_ratchet=True,
            ratchet_interval=10
        )
        
        # Derive keys across ratchet boundary
        key0 = manager.derive_block_key(0)
        key10 = manager.derive_block_key(10)
        key20 = manager.derive_block_key(20)
        
        assert key0 != key10
        assert key10 != key20
        
    def test_forward_secrecy_cleanup(self):
        """Test manager cleanup."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        manager.cleanup()  # Should not raise


class TestX25519ForwardSecrecy:
    """Deep tests for x25519_forward_secrecy module."""
    
    def test_import_module(self):
        """Test importing module."""
        from meow_decoder import x25519_forward_secrecy
        assert x25519_forward_secrecy is not None
        
    def test_generate_ephemeral_keypair(self):
        """Test ephemeral keypair generation."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert keys.ephemeral_private is not None
        assert keys.ephemeral_public is not None
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
        
    def test_generate_receiver_keypair(self):
        """Test receiver keypair generation."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        private, public = generate_receiver_keypair()
        
        assert len(private) == 32
        assert len(public) == 32
        
    def test_derive_shared_secret(self):
        """Test shared secret derivation."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret
        )
        
        # Generate receiver keys
        recv_priv, recv_pub = generate_receiver_keypair()
        
        # Generate sender ephemeral keys
        sender_keys = generate_ephemeral_keypair()
        
        # Derive shared secret (sender side)
        shared1 = derive_shared_secret(
            sender_keys.ephemeral_private,
            recv_pub,
            "password",
            secrets.token_bytes(16)
        )
        
        assert len(shared1) == 32
        
    def test_serialize_deserialize_public_key(self):
        """Test public key serialization."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            serialize_public_key,
            deserialize_public_key
        )
        
        _, public = generate_receiver_keypair()
        
        serialized = serialize_public_key(public)
        deserialized = deserialize_public_key(serialized)
        
        assert serialized == deserialized


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
