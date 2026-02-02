#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for Schrödinger mode - Target: 90%+
Tests schrodinger_encode.py, schrodinger_decode.py, quantum_mixer.py, and multi_secret.py.
"""

import pytest
import secrets
import hashlib
import struct
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestQuantumMixer:
    """Test quantum_mixer.py core functions."""
    
    def test_import_quantum_mixer(self):
        """Test importing quantum_mixer module."""
        from meow_decoder import quantum_mixer
        assert quantum_mixer is not None
    
    def test_derive_quantum_noise(self):
        """Test quantum noise derivation."""
        from meow_decoder.quantum_mixer import derive_quantum_noise
        
        password_a = "RealSecret123!"
        password_b = "DecoyPassword456"
        salt = secrets.token_bytes(16)
        
        noise = derive_quantum_noise(password_a, password_b, salt, length=32)
        
        assert isinstance(noise, bytes)
        assert len(noise) == 32
    
    def test_quantum_noise_deterministic(self):
        """Test that same inputs give same noise."""
        from meow_decoder.quantum_mixer import derive_quantum_noise
        
        password_a = "Password1"
        password_b = "Password2"
        salt = b"fixed_salt_16byt"
        
        noise1 = derive_quantum_noise(password_a, password_b, salt)
        noise2 = derive_quantum_noise(password_a, password_b, salt)
        
        assert noise1 == noise2
    
    def test_quantum_noise_different_passwords(self):
        """Test different passwords give different noise."""
        from meow_decoder.quantum_mixer import derive_quantum_noise
        
        salt = secrets.token_bytes(16)
        
        noise1 = derive_quantum_noise("pass1", "pass2", salt)
        noise2 = derive_quantum_noise("pass3", "pass4", salt)
        
        assert noise1 != noise2
    
    def test_entangle_realities(self):
        """Test reality entanglement."""
        from meow_decoder.quantum_mixer import entangle_realities
        
        reality_a = b"Secret data A" * 10
        reality_b = b"Secret data B" * 10
        
        superposition = entangle_realities(reality_a, reality_b)
        
        assert isinstance(superposition, bytes)
        # Superposition should be interleaved
        assert len(superposition) == 2 * max(len(reality_a), len(reality_b))
    
    def test_entangle_different_sizes(self):
        """Test entanglement with different sized inputs."""
        from meow_decoder.quantum_mixer import entangle_realities
        
        reality_a = b"Short"
        reality_b = b"Much longer secret data here"
        
        superposition = entangle_realities(reality_a, reality_b)
        
        # Should pad shorter to match
        assert len(superposition) == 2 * len(reality_b)
    
    def test_collapse_to_reality_a(self):
        """Test collapsing to reality A."""
        from meow_decoder.quantum_mixer import entangle_realities, collapse_to_reality
        
        reality_a = b"AAAAAAAAAA"
        reality_b = b"BBBBBBBBBB"
        
        superposition = entangle_realities(reality_a, reality_b)
        collapsed = collapse_to_reality(superposition, reality_index=0)
        
        assert collapsed == reality_a
    
    def test_collapse_to_reality_b(self):
        """Test collapsing to reality B."""
        from meow_decoder.quantum_mixer import entangle_realities, collapse_to_reality
        
        reality_a = b"AAAAAAAAAA"
        reality_b = b"BBBBBBBBBB"
        
        superposition = entangle_realities(reality_a, reality_b)
        collapsed = collapse_to_reality(superposition, reality_index=1)
        
        assert collapsed == reality_b
    
    def test_expand_noise(self):
        """Test noise expansion."""
        from meow_decoder.quantum_mixer import expand_noise
        
        seed = secrets.token_bytes(32)
        
        expanded = expand_noise(seed, length=1000)
        
        assert len(expanded) == 1000
    
    def test_expand_noise_short(self):
        """Test noise expansion shorter than seed."""
        from meow_decoder.quantum_mixer import expand_noise
        
        seed = secrets.token_bytes(32)
        
        expanded = expand_noise(seed, length=16)
        
        assert len(expanded) == 16
        assert expanded == seed[:16]
    
    def test_compute_entanglement_root(self):
        """Test Merkle root computation."""
        from meow_decoder.quantum_mixer import compute_entanglement_root
        
        blocks = [b"block1", b"block2", b"block3"]
        
        root = compute_entanglement_root(blocks)
        
        assert isinstance(root, bytes)
        assert len(root) == 32  # SHA-256
    
    def test_entanglement_root_empty(self):
        """Test Merkle root with empty blocks."""
        from meow_decoder.quantum_mixer import compute_entanglement_root
        
        root = compute_entanglement_root([])
        
        assert isinstance(root, bytes)
        assert len(root) == 32
    
    def test_entanglement_root_single_block(self):
        """Test Merkle root with single block."""
        from meow_decoder.quantum_mixer import compute_entanglement_root
        
        root = compute_entanglement_root([b"single block"])
        
        assert isinstance(root, bytes)
        assert len(root) == 32
    
    def test_verify_indistinguishability(self):
        """Test statistical indistinguishability verification."""
        from meow_decoder.quantum_mixer import verify_indistinguishability
        
        # Create random data (should be indistinguishable)
        data_a = secrets.token_bytes(1000)
        data_b = secrets.token_bytes(1000)
        
        is_indist, results = verify_indistinguishability(data_a, data_b, threshold=0.5)
        
        assert isinstance(results, dict)
        assert 'entropy_a' in results
        assert 'entropy_b' in results
        assert 'entropy_diff' in results
    
    def test_yarn_constants(self):
        """Test yarn metaphor constants."""
        from meow_decoder.quantum_mixer import YARN_REALITY_A, YARN_REALITY_B, YARN_TANGLED
        
        assert YARN_REALITY_A == 0
        assert YARN_REALITY_B == 1
        assert YARN_TANGLED == 2


class TestSchrodingerManifest:
    """Test SchrodingerManifest dataclass."""
    
    def test_manifest_creation(self):
        """Test creating manifest."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        manifest = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=100,
            block_size=256,
            superposition_len=25600
        )
        
        assert manifest.magic == b"MEOW"
        assert manifest.version == 0x07
        assert manifest.block_count == 100
    
    def test_manifest_pack(self):
        """Test packing manifest."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        manifest = SchrodingerManifest(
            salt_a=b'\x00' * 16,
            salt_b=b'\x01' * 16,
            nonce_a=b'\x02' * 12,
            nonce_b=b'\x03' * 12,
            reality_a_hmac=b'\x04' * 32,
            reality_b_hmac=b'\x05' * 32,
            metadata_a=b'\x06' * 104,
            metadata_b=b'\x07' * 104,
            block_count=50,
            block_size=512,
            superposition_len=25600
        )
        
        packed = manifest.pack()
        
        assert isinstance(packed, bytes)
        assert len(packed) == 382
        assert packed[:4] == b"MEOW"
    
    def test_manifest_unpack(self):
        """Test unpacking manifest."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        # Create and pack
        original = SchrodingerManifest(
            salt_a=b'\xAA' * 16,
            salt_b=b'\xBB' * 16,
            nonce_a=b'\xCC' * 12,
            nonce_b=b'\xDD' * 12,
            reality_a_hmac=b'\xEE' * 32,
            reality_b_hmac=b'\xFF' * 32,
            metadata_a=b'\x11' * 104,
            metadata_b=b'\x22' * 104,
            block_count=75,
            block_size=128,
            superposition_len=9600
        )
        
        packed = original.pack()
        
        # Unpack
        unpacked = SchrodingerManifest.unpack(packed)
        
        assert unpacked.salt_a == original.salt_a
        assert unpacked.salt_b == original.salt_b
        assert unpacked.block_count == original.block_count
        assert unpacked.block_size == original.block_size
        assert unpacked.superposition_len == original.superposition_len
    
    def test_manifest_unpack_invalid_magic(self):
        """Test unpack with invalid magic."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        bad_data = b"WOOF" + b'\x00' * 378
        
        with pytest.raises(ValueError, match="Invalid manifest magic"):
            SchrodingerManifest.unpack(bad_data)
    
    def test_manifest_unpack_too_short(self):
        """Test unpack with too short data."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        short_data = b"MEOW" + b'\x00' * 10
        
        with pytest.raises(ValueError, match="too short"):
            SchrodingerManifest.unpack(short_data)
    
    def test_manifest_pack_core_for_auth(self):
        """Test packing core for authentication."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        manifest = SchrodingerManifest(
            salt_a=b'\x00' * 16,
            salt_b=b'\x01' * 16,
            nonce_a=b'\x02' * 12,
            nonce_b=b'\x03' * 12,
            reality_a_hmac=b'\x04' * 32,
            reality_b_hmac=b'\x05' * 32,
            metadata_a=b'\x06' * 104,
            metadata_b=b'\x07' * 104,
            block_count=50,
            block_size=512,
            superposition_len=25600
        )
        
        core = manifest.pack_core_for_auth()
        
        # Core excludes HMACs
        assert isinstance(core, bytes)
        assert len(core) < len(manifest.pack())


class TestSchrodingerEncodeData:
    """Test schrodinger_encode_data function."""
    
    def test_encode_data_basic(self):
        """Test basic data encoding."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        
        real_data = b"TOP SECRET: Launch codes" * 10
        decoy_data = b"Vacation photos metadata" * 10
        
        entangled, manifest = schrodinger_encode_data(
            real_data,
            decoy_data,
            "RealPassword123!",
            "DecoyPassword456!",
            block_size=256
        )
        
        assert isinstance(entangled, bytes)
        assert len(entangled) > 0
        assert manifest.block_count > 0
    
    def test_encode_data_different_sizes(self):
        """Test encoding with different sized data."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        
        real_data = b"Short secret"
        decoy_data = b"Much longer decoy data that is significantly bigger than the real data"
        
        entangled, manifest = schrodinger_encode_data(
            real_data,
            decoy_data,
            "Pass1234567!",
            "Pass7654321!",
            block_size=128
        )
        
        assert isinstance(entangled, bytes)
        assert manifest.superposition_len > 0


class TestMultiSecret:
    """Test multi_secret.py for N-level deniability."""
    
    def test_import_multi_secret(self):
        """Test importing multi_secret module."""
        try:
            from meow_decoder import multi_secret
            assert multi_secret is not None
        except ImportError:
            pytest.skip("multi_secret not available")
    
    def test_multi_secret_encoder(self):
        """Test multi-secret encoder initialization with realities."""
        try:
            from meow_decoder.multi_secret import MultiSecretEncoder
            
            # New API: realities must be passed at initialization
            realities = [
                (b"Secret A", "password_a"),
                (b"Secret B", "password_b"),
            ]
            encoder = MultiSecretEncoder(realities=realities, block_size=256)
            
            assert encoder is not None
            assert encoder.block_size == 256
            assert len(encoder.realities) == 2
        except ImportError:
            pytest.skip("MultiSecretEncoder not available")
    
    def test_add_secrets(self):
        """Test multi-secret encoder with multiple secrets."""
        try:
            from meow_decoder.multi_secret import MultiSecretEncoder
            
            # New API: all secrets passed at initialization
            realities = [
                (b"Secret 1", "password1"),
                (b"Secret 2", "password2"),
                (b"Secret 3", "password3"),
            ]
            encoder = MultiSecretEncoder(realities=realities, block_size=256)
            
            assert len(encoder.realities) == 3
        except ImportError:
            pytest.skip("MultiSecretEncoder not available")


class TestDecoyGenerator:
    """Test decoy generator functionality."""
    
    def test_generate_convincing_decoy(self):
        """Test generating convincing decoy data."""
        try:
            from meow_decoder.schrodinger_encode import generate_convincing_decoy
            
            decoy = generate_convincing_decoy(10000)
            
            assert isinstance(decoy, bytes)
            assert len(decoy) >= 10000
        except (ImportError, NameError):
            # Try alternate location
            try:
                from meow_decoder.decoy_generator import generate_convincing_decoy
                
                decoy = generate_convincing_decoy(5000)
                
                assert isinstance(decoy, bytes)
            except ImportError:
                pytest.skip("generate_convincing_decoy not available")
    
    def test_decoy_randomness(self):
        """Test that decoys are random."""
        try:
            from meow_decoder.schrodinger_encode import generate_convincing_decoy
            
            decoy1 = generate_convincing_decoy(1000)
            decoy2 = generate_convincing_decoy(1000)
            
            # Different decoys should be different
            assert decoy1 != decoy2
        except (ImportError, NameError):
            pytest.skip("generate_convincing_decoy not available")


class TestQuantumStateDataclass:
    """Test QuantumState dataclass if available."""
    
    def test_quantum_state_creation(self):
        """Test creating QuantumState."""
        from meow_decoder.quantum_mixer import QuantumState
        
        state = QuantumState(
            mixed_data=b"mixed",
            reality_a_key=b"key_a",
            reality_b_key=b"key_b",
            quantum_noise=b"noise",
            entanglement_root=b"root"
        )
        
        assert state.mixed_data == b"mixed"
        assert state.reality_a_key == b"key_a"


class TestSchrodingerEdgeCases:
    """Test Schrödinger edge cases."""
    
    def test_empty_data(self):
        """Test with empty data."""
        from meow_decoder.quantum_mixer import entangle_realities
        
        superposition = entangle_realities(b"", b"")
        
        assert isinstance(superposition, bytes)
    
    def test_single_byte_data(self):
        """Test with single byte data."""
        from meow_decoder.quantum_mixer import entangle_realities, collapse_to_reality
        
        reality_a = b"A"
        reality_b = b"B"
        
        superposition = entangle_realities(reality_a, reality_b)
        
        collapsed_a = collapse_to_reality(superposition, 0)
        collapsed_b = collapse_to_reality(superposition, 1)
        
        assert collapsed_a == b"A"
        assert collapsed_b == b"B"
    
    def test_large_data(self):
        """Test with larger data."""
        from meow_decoder.quantum_mixer import entangle_realities
        
        reality_a = secrets.token_bytes(10000)
        reality_b = secrets.token_bytes(10000)
        
        superposition = entangle_realities(reality_a, reality_b)
        
        assert len(superposition) == 20000
    
    def test_statistical_properties(self):
        """Test statistical properties of entangled data."""
        from meow_decoder.quantum_mixer import (
            entangle_realities, 
            verify_indistinguishability
        )
        
        # Create high-entropy random data
        reality_a = secrets.token_bytes(1000)
        reality_b = secrets.token_bytes(1000)
        
        superposition = entangle_realities(reality_a, reality_b)
        
        # Check first half vs second half
        half = len(superposition) // 2
        is_indist, results = verify_indistinguishability(
            superposition[:half],
            superposition[half:]
        )
        
        # Both halves should have high entropy
        assert results['entropy_a'] > 7.0
        assert results['entropy_b'] > 7.0


class TestIndistinguishabilityMetrics:
    """Test indistinguishability metrics in detail."""
    
    def test_entropy_calculation(self):
        """Test entropy is calculated correctly."""
        from meow_decoder.quantum_mixer import verify_indistinguishability
        
        # Uniform random data should have entropy close to 8.0 bits/byte
        random_data = secrets.token_bytes(10000)
        
        _, results = verify_indistinguishability(random_data, random_data)
        
        assert 7.0 < results['entropy_a'] <= 8.0
    
    def test_low_entropy_detection(self):
        """Test detection of low entropy data."""
        from meow_decoder.quantum_mixer import verify_indistinguishability
        
        # Repetitive data has low entropy
        repetitive = b"AAAA" * 1000
        random = secrets.token_bytes(4000)
        
        _, results = verify_indistinguishability(repetitive, random)
        
        # Repetitive data should have lower entropy
        assert results['entropy_a'] < results['entropy_b']


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
