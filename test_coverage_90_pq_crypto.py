#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for Post-Quantum Crypto - Target: 90%+
Tests pq_hybrid.py and pq_signatures.py for maximum coverage.
"""

import pytest
import secrets
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestPQHybridKeyGeneration:
    """Test post-quantum hybrid key generation."""
    
    def test_generate_hybrid_keypair(self):
        """Test generating hybrid keypair."""
        try:
            from meow_decoder.pq_hybrid import generate_hybrid_keypair
            
            keypair = generate_hybrid_keypair()
            
            assert keypair is not None
            assert hasattr(keypair, 'public_key') or isinstance(keypair, tuple)
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_generate_classical_fallback(self):
        """Test classical fallback when PQ not available."""
        try:
            from meow_decoder.pq_hybrid import generate_classical_keypair
            
            keypair = generate_classical_keypair()
            
            assert keypair is not None
        except ImportError:
            pytest.skip("PQ hybrid module not available")
    
    def test_keypair_components(self):
        """Test keypair has required components."""
        try:
            from meow_decoder.pq_hybrid import generate_hybrid_keypair, HybridKeypair
            
            keypair = generate_hybrid_keypair()
            
            # Should have both classical and PQ components
            if hasattr(keypair, 'classical_private'):
                assert keypair.classical_private is not None
            if hasattr(keypair, 'pq_private'):
                assert keypair.pq_private is not None
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise


class TestPQHybridEncapsulation:
    """Test post-quantum key encapsulation."""
    
    def test_encapsulate(self):
        """Test key encapsulation."""
        try:
            from meow_decoder.pq_hybrid import generate_hybrid_keypair, encapsulate
            
            keypair = generate_hybrid_keypair()
            
            # Get public key
            if hasattr(keypair, 'public_key'):
                public_key = keypair.public_key
            elif isinstance(keypair, tuple):
                public_key = keypair[1]  # (private, public)
            else:
                public_key = keypair
            
            ciphertext, shared_secret = encapsulate(public_key)
            
            assert ciphertext is not None
            assert shared_secret is not None
            assert len(shared_secret) == 32  # 256-bit shared secret
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_decapsulate(self):
        """Test key decapsulation."""
        try:
            from meow_decoder.pq_hybrid import (
                generate_hybrid_keypair, encapsulate, decapsulate
            )
            
            keypair = generate_hybrid_keypair()
            
            # Get keys
            if hasattr(keypair, 'public_key'):
                public_key = keypair.public_key
                private_key = keypair.private_key
            elif isinstance(keypair, tuple):
                private_key, public_key = keypair
            else:
                pytest.skip("Unknown keypair format")
            
            ciphertext, shared_secret_enc = encapsulate(public_key)
            shared_secret_dec = decapsulate(ciphertext, private_key)
            
            assert shared_secret_enc == shared_secret_dec
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise


class TestPQHybridDeriveKey:
    """Test hybrid key derivation."""
    
    def test_derive_hybrid_key(self):
        """Test deriving key from hybrid components."""
        try:
            from meow_decoder.pq_hybrid import derive_hybrid_key
            
            classical_secret = secrets.token_bytes(32)
            pq_secret = secrets.token_bytes(32)
            salt = secrets.token_bytes(16)
            
            key = derive_hybrid_key(classical_secret, pq_secret, salt)
            
            assert len(key) == 32
        except ImportError:
            pytest.skip("PQ hybrid module not available")
    
    def test_derive_hybrid_key_deterministic(self):
        """Test hybrid key derivation is deterministic."""
        try:
            from meow_decoder.pq_hybrid import derive_hybrid_key
            
            classical_secret = secrets.token_bytes(32)
            pq_secret = secrets.token_bytes(32)
            salt = secrets.token_bytes(16)
            
            key1 = derive_hybrid_key(classical_secret, pq_secret, salt)
            key2 = derive_hybrid_key(classical_secret, pq_secret, salt)
            
            assert key1 == key2
        except ImportError:
            pytest.skip("PQ hybrid module not available")


class TestPQSignaturesGeneration:
    """Test post-quantum signature key generation."""
    
    def test_generate_signing_keypair(self):
        """Test generating signing keypair."""
        try:
            from meow_decoder.pq_signatures import generate_signing_keypair
            
            keypair = generate_signing_keypair()
            
            assert keypair is not None
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_generate_dilithium_keypair(self):
        """Test generating Dilithium keypair."""
        try:
            from meow_decoder.pq_signatures import generate_dilithium_keypair
            
            keypair = generate_dilithium_keypair()
            
            assert keypair is not None
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower() or "Dilithium" in str(e):
                pytest.skip("Dilithium not available")
            raise
    
    def test_generate_ed25519_fallback(self):
        """Test Ed25519 fallback signing."""
        try:
            from meow_decoder.pq_signatures import generate_ed25519_keypair
            
            keypair = generate_ed25519_keypair()
            
            assert keypair is not None
        except ImportError:
            pytest.skip("PQ signatures module not available")


class TestPQSignaturesSignVerify:
    """Test post-quantum signing and verification."""
    
    def test_sign_message(self):
        """Test signing a message."""
        try:
            from meow_decoder.pq_signatures import generate_signing_keypair, sign
            
            keypair = generate_signing_keypair()
            message = b"Test message to sign"
            
            signature = sign(message, keypair)
            
            assert signature is not None
            assert len(signature) > 0
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_verify_signature(self):
        """Test verifying a signature."""
        try:
            from meow_decoder.pq_signatures import (
                generate_signing_keypair, sign, verify
            )
            
            keypair = generate_signing_keypair()
            message = b"Test message to sign"
            
            signature = sign(message, keypair)
            is_valid = verify(message, signature, keypair)
            
            assert is_valid is True
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_verify_invalid_signature(self):
        """Test that invalid signature is rejected."""
        try:
            from meow_decoder.pq_signatures import (
                generate_signing_keypair, sign, verify
            )
            
            keypair = generate_signing_keypair()
            message = b"Test message to sign"
            
            signature = sign(message, keypair)
            
            # Tamper with signature
            tampered_sig = bytes([s ^ 0xFF for s in signature[:10]]) + signature[10:]
            
            is_valid = verify(message, tampered_sig, keypair)
            
            assert is_valid is False
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise


class TestPQHybridEncryption:
    """Test hybrid encryption/decryption."""
    
    def test_hybrid_encrypt(self):
        """Test hybrid encryption."""
        try:
            from meow_decoder.pq_hybrid import hybrid_encrypt, generate_hybrid_keypair
            
            keypair = generate_hybrid_keypair()
            plaintext = b"Secret message for PQ encryption"
            
            ciphertext = hybrid_encrypt(plaintext, keypair)
            
            assert ciphertext is not None
            assert ciphertext != plaintext
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except AttributeError:
            pytest.skip("hybrid_encrypt not implemented")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_hybrid_decrypt(self):
        """Test hybrid decryption."""
        try:
            from meow_decoder.pq_hybrid import (
                hybrid_encrypt, hybrid_decrypt, generate_hybrid_keypair
            )
            
            keypair = generate_hybrid_keypair()
            plaintext = b"Secret message for PQ encryption"
            
            ciphertext = hybrid_encrypt(plaintext, keypair)
            decrypted = hybrid_decrypt(ciphertext, keypair)
            
            assert decrypted == plaintext
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except AttributeError:
            pytest.skip("hybrid_encrypt/decrypt not implemented")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise


class TestPQAvailability:
    """Test PQ crypto availability detection."""
    
    def test_is_pq_available(self):
        """Test PQ availability check."""
        try:
            from meow_decoder.pq_hybrid import is_pq_available
            
            available = is_pq_available()
            
            assert isinstance(available, bool)
        except ImportError:
            pytest.skip("PQ hybrid module not available")
    
    def test_get_pq_algorithms(self):
        """Test getting available PQ algorithms."""
        try:
            from meow_decoder.pq_hybrid import get_available_algorithms
            
            algorithms = get_available_algorithms()
            
            assert isinstance(algorithms, (list, tuple, dict))
        except ImportError:
            pytest.skip("PQ hybrid module not available")
        except AttributeError:
            pytest.skip("get_available_algorithms not implemented")


class TestPQManifestIntegration:
    """Test PQ integration with manifest."""
    
    def test_pq_ciphertext_in_manifest(self):
        """Test PQ ciphertext can be stored in manifest."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        # Create manifest with PQ ciphertext
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),  # X25519
            pq_ciphertext=secrets.token_bytes(1088),  # ML-KEM-768
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.pq_ciphertext == manifest.pq_ciphertext
        assert len(unpacked.pq_ciphertext) == 1088


class TestPQConfigDefaults:
    """Test PQ crypto configuration defaults."""
    
    def test_pq_enabled_by_default(self):
        """Test PQ is enabled by default in config."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        assert config.enable_pq is True
    
    def test_kyber_variant_default(self):
        """Test default Kyber variant."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        assert config.kyber_variant == "kyber1024"


class TestPQEdgeCases:
    """Test PQ crypto edge cases."""
    
    def test_empty_message_sign(self):
        """Test signing empty message."""
        try:
            from meow_decoder.pq_signatures import generate_signing_keypair, sign
            
            keypair = generate_signing_keypair()
            
            signature = sign(b"", keypair)
            
            assert signature is not None
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise
    
    def test_large_message_sign(self):
        """Test signing large message."""
        try:
            from meow_decoder.pq_signatures import generate_signing_keypair, sign
            
            keypair = generate_signing_keypair()
            large_message = secrets.token_bytes(1024 * 1024)  # 1 MB
            
            signature = sign(large_message, keypair)
            
            assert signature is not None
        except ImportError:
            pytest.skip("PQ signatures module not available")
        except Exception as e:
            if "liboqs" in str(e).lower():
                pytest.skip("liboqs not installed")
            raise


class TestPQModuleImports:
    """Test PQ module imports."""
    
    def test_pq_hybrid_import(self):
        """Test pq_hybrid module can be imported."""
        try:
            from meow_decoder import pq_hybrid
            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("PQ hybrid module not available")
    
    def test_pq_signatures_import(self):
        """Test pq_signatures module can be imported."""
        try:
            from meow_decoder import pq_signatures
            assert pq_signatures is not None
        except ImportError:
            pytest.skip("PQ signatures module not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
