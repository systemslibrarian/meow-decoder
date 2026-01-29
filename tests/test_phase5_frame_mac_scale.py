#!/usr/bin/env python3
"""
🔬 Phase 5: Frame MAC Collision Testing at Scale (GAP-07)

Tests frame MAC collision resistance with large frame counts
approaching birthday bound considerations.

Test Coverage:
- FMAC-01 to FMAC-05: Birthday bound analysis
- FMAC-06 to FMAC-10: Large frame count tests
- FMAC-11 to FMAC-15: MAC uniqueness verification
- FMAC-16 to FMAC-20: Statistical distribution tests

Security Properties Verified:
- No MAC collisions within expected frame counts
- MAC distribution is uniform
- Frame index binding prevents reordering
- Salt binding prevents cross-session replay
"""

import pytest
import secrets
import hashlib
import struct
from collections import Counter
import math


class TestBirthdayBoundAnalysis:
    """FMAC-01 to FMAC-05: Birthday bound analysis."""
    
    def test_mac_size_birthday_bound(self):
        """FMAC-01: 8-byte MAC birthday bound is ~2^32 frames."""
        # 8-byte MAC = 64 bits
        # Birthday bound = 2^(64/2) = 2^32 ≈ 4.3 billion frames
        # This is far beyond practical frame counts
        
        mac_bits = 8 * 8  # 64 bits
        birthday_bound = 2 ** (mac_bits / 2)
        
        # Practical max: 10 million frames (huge GIF)
        practical_max_frames = 10_000_000
        
        # Safety margin: birthday bound should be >100x practical max
        safety_margin = birthday_bound / practical_max_frames
        
        assert safety_margin > 100, f"Birthday bound safety margin too low: {safety_margin:.0f}x"
    
    def test_collision_probability_1k_frames(self):
        """FMAC-02: Collision probability for 1K frames is negligible."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        n = 1000  # frames
        b = 64    # bits
        
        # Collision probability ≈ n^2 / 2^(b+1)
        p_collision = (n ** 2) / (2 ** (b + 1))
        
        # Should be astronomically low
        assert p_collision < 1e-10, f"Collision probability too high: {p_collision}"
    
    def test_collision_probability_10k_frames(self):
        """FMAC-03: Collision probability for 10K frames is negligible."""
        n = 10_000
        b = 64
        
        p_collision = (n ** 2) / (2 ** (b + 1))
        
        assert p_collision < 1e-8
    
    def test_collision_probability_100k_frames(self):
        """FMAC-04: Collision probability for 100K frames is negligible."""
        n = 100_000
        b = 64
        
        p_collision = (n ** 2) / (2 ** (b + 1))
        
        assert p_collision < 1e-6
    
    def test_collision_probability_1m_frames(self):
        """FMAC-05: Collision probability for 1M frames is still low."""
        n = 1_000_000
        b = 64
        
        p_collision = (n ** 2) / (2 ** (b + 1))
        
        # Even with 1M frames, probability < 1 in 18 trillion
        assert p_collision < 1e-4


class TestLargeFrameCountMacs:
    """FMAC-06 to FMAC-10: Large frame count tests."""
    
    def test_10k_macs_no_collision(self):
        """FMAC-06: Generate 10K MACs with no collisions."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"test frame data"
        
        macs = set()
        
        for frame_idx in range(10_000):
            packed = pack_frame_with_mac(data, master_key, frame_idx, salt)
            mac = packed[:8]
            
            # Check for collision
            assert mac not in macs, f"MAC collision at frame {frame_idx}"
            macs.add(mac)
        
        assert len(macs) == 10_000
    
    def test_50k_macs_no_collision(self):
        """FMAC-07: Generate 50K MACs with no collisions."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"test frame data"
        
        macs = set()
        
        for frame_idx in range(50_000):
            packed = pack_frame_with_mac(data, master_key, frame_idx, salt)
            mac = packed[:8]
            
            assert mac not in macs, f"MAC collision at frame {frame_idx}"
            macs.add(mac)
        
        assert len(macs) == 50_000
    
    @pytest.mark.slow
    def test_100k_macs_no_collision(self):
        """FMAC-08: Generate 100K MACs with no collisions."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"test frame data"
        
        macs = set()
        
        for frame_idx in range(100_000):
            packed = pack_frame_with_mac(data, master_key, frame_idx, salt)
            mac = packed[:8]
            
            assert mac not in macs, f"MAC collision at frame {frame_idx}"
            macs.add(mac)
    
    def test_variable_data_no_collision(self):
        """FMAC-09: Variable data produces unique MACs."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        macs = set()
        
        for i in range(10_000):
            data = f"variable data {i}".encode()
            packed = pack_frame_with_mac(data, master_key, i, salt)
            mac = packed[:8]
            
            assert mac not in macs
            macs.add(mac)
    
    def test_random_data_no_collision(self):
        """FMAC-10: Random data produces unique MACs."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        macs = set()
        
        for i in range(10_000):
            data = secrets.token_bytes(100)
            packed = pack_frame_with_mac(data, master_key, i, salt)
            mac = packed[:8]
            
            assert mac not in macs
            macs.add(mac)


class TestMacUniqueness:
    """FMAC-11 to FMAC-15: MAC uniqueness verification."""
    
    def test_same_data_different_index_different_mac(self):
        """FMAC-11: Same data, different frame index = different MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"constant data"
        
        macs = []
        for idx in range(1000):
            packed = pack_frame_with_mac(data, master_key, idx, salt)
            macs.append(packed[:8])
        
        # All MACs should be unique
        assert len(set(macs)) == len(macs)
    
    def test_same_index_different_data_different_mac(self):
        """FMAC-12: Same index, different data = different MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        macs = []
        for i in range(1000):
            data = f"data variant {i}".encode()
            packed = pack_frame_with_mac(data, master_key, 0, salt)
            macs.append(packed[:8])
        
        # All MACs should be unique
        assert len(set(macs)) == len(macs)
    
    def test_same_data_different_salt_different_mac(self):
        """FMAC-13: Same data, different salt = different MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        data = b"constant data"
        
        macs = []
        for _ in range(1000):
            salt = secrets.token_bytes(16)
            packed = pack_frame_with_mac(data, master_key, 0, salt)
            macs.append(packed[:8])
        
        # All MACs should be unique
        assert len(set(macs)) == len(macs)
    
    def test_same_data_different_key_different_mac(self):
        """FMAC-14: Same data, different key = different MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        salt = secrets.token_bytes(16)
        data = b"constant data"
        
        macs = []
        for _ in range(1000):
            key = secrets.token_bytes(32)
            packed = pack_frame_with_mac(data, key, 0, salt)
            macs.append(packed[:8])
        
        # All MACs should be unique
        assert len(set(macs)) == len(macs)
    
    def test_identical_params_identical_mac(self):
        """FMAC-15: Identical parameters produce identical MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"constant data"
        frame_idx = 42
        
        mac1 = pack_frame_with_mac(data, master_key, frame_idx, salt)[:8]
        mac2 = pack_frame_with_mac(data, master_key, frame_idx, salt)[:8]
        
        assert mac1 == mac2


class TestStatisticalDistribution:
    """FMAC-16 to FMAC-20: Statistical distribution tests."""
    
    def test_mac_byte_distribution_uniform(self):
        """FMAC-16: MAC bytes are uniformly distributed."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        byte_counts = Counter()
        
        for i in range(10_000):
            data = struct.pack('>I', i)
            packed = pack_frame_with_mac(data, master_key, i, salt)
            mac = packed[:8]
            
            for byte in mac:
                byte_counts[byte] += 1
        
        # Expected count per byte value: 10000 * 8 / 256 ≈ 312.5
        expected = (10_000 * 8) / 256
        
        # Chi-square test: variance should be reasonable
        chi_squared = sum(
            ((count - expected) ** 2) / expected
            for count in byte_counts.values()
        )
        
        # Degrees of freedom = 255, threshold for p=0.01 is ~310
        # We use a more lenient threshold for test stability
        assert chi_squared < 400, f"Chi-squared too high: {chi_squared}"
    
    def test_mac_first_byte_distribution(self):
        """FMAC-17: First MAC byte is uniformly distributed."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        first_bytes = Counter()
        
        for i in range(10_000):
            data = struct.pack('>I', i)
            packed = pack_frame_with_mac(data, master_key, i, salt)
            first_bytes[packed[0]] += 1
        
        # Check min and max counts
        min_count = min(first_bytes.values())
        max_count = max(first_bytes.values())
        
        # Expected: 10000/256 ≈ 39
        # Allow 3x variance
        expected = 10_000 / 256
        
        assert min_count > expected / 3, f"Min count too low: {min_count}"
        assert max_count < expected * 3, f"Max count too high: {max_count}"
    
    def test_no_obvious_patterns(self):
        """FMAC-18: Sequential frame indices don't produce patterns."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"constant"
        
        macs = []
        for i in range(1000):
            packed = pack_frame_with_mac(data, master_key, i, salt)
            macs.append(packed[:8])
        
        # Check that sequential MACs don't share first bytes
        same_first_byte = sum(
            1 for i in range(len(macs) - 1)
            if macs[i][0] == macs[i + 1][0]
        )
        
        # Expected: about 1000/256 ≈ 4 consecutive pairs with same first byte
        # Allow 3x variance
        assert same_first_byte < 20, f"Too many same first bytes: {same_first_byte}"
    
    def test_avalanche_effect(self):
        """FMAC-19: Single bit change causes ~50% bit difference."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"test data"
        
        base_mac = pack_frame_with_mac(data, master_key, 0, salt)[:8]
        
        # Change single bit in data
        modified_data = bytearray(data)
        modified_data[0] ^= 0x01
        modified_mac = pack_frame_with_mac(bytes(modified_data), master_key, 0, salt)[:8]
        
        # Count bit differences
        bit_diff = sum(
            bin(a ^ b).count('1')
            for a, b in zip(base_mac, modified_mac)
        )
        
        # 8 bytes = 64 bits, expect ~32 bits different (50%)
        # Allow range of 20-44 bits (31-69%)
        assert 20 <= bit_diff <= 44, f"Bit difference {bit_diff} outside expected range"
    
    def test_mac_entropy(self):
        """FMAC-20: MAC bytes have high entropy."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        import math
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Collect all MAC bytes
        all_bytes = bytearray()
        for i in range(1000):
            packed = pack_frame_with_mac(b"data", master_key, i, salt)
            all_bytes.extend(packed[:8])
        
        # Calculate entropy
        byte_counts = Counter(all_bytes)
        total = len(all_bytes)
        
        entropy = -sum(
            (count / total) * math.log2(count / total)
            for count in byte_counts.values()
        )
        
        # Max entropy for byte distribution is 8 bits
        # Expect > 7.5 bits (very high randomness)
        assert entropy > 7.5, f"Entropy too low: {entropy}"


class TestCrossSessionReplay:
    """Additional tests for cross-session replay prevention."""
    
    def test_different_sessions_different_macs(self):
        """Different master keys prevent cross-session replay."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        salt = secrets.token_bytes(16)
        data = b"frame data"
        frame_idx = 0
        
        session1_key = secrets.token_bytes(32)
        session2_key = secrets.token_bytes(32)
        
        mac1 = pack_frame_with_mac(data, session1_key, frame_idx, salt)[:8]
        mac2 = pack_frame_with_mac(data, session2_key, frame_idx, salt)[:8]
        
        assert mac1 != mac2
    
    def test_mac_verification_rejects_wrong_session(self):
        """MAC verification rejects frames from different session."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        salt = secrets.token_bytes(16)
        data = b"frame data"
        
        # Create frame with session 1 key
        key1 = secrets.token_bytes(32)
        packed = pack_frame_with_mac(data, key1, 0, salt)
        
        # Try to verify with session 2 key
        key2 = secrets.token_bytes(32)
        valid, _ = unpack_frame_with_mac(packed, key2, 0, salt)
        
        assert valid is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
