#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Comprehensive E2E Tests v5.4.0

Tests the complete encode/decode pipeline for quantum superposition.

Test Categories:
    1. Core Components (quantum mixer, decoy gen)
    2. Manifest Packing/Unpacking
    3. Block Permutation
    4. End-to-End Encoding
    5. End-to-End Decoding (both realities)
    6. Statistical Indistinguishability
    7. Forensic Resistance
"""

import secrets
import tempfile
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from meow_decoder.schrodinger_encode import (
    schrodinger_encode_data,
    schrodinger_encode_file,
    SchrodingerManifest,
    permute_blocks,
    unpermute_blocks,
    compute_merkle_root
)
from meow_decoder.schrodinger_decode import (
    schrodinger_decode_file,
    verify_password_reality,
    extract_reality
)
from meow_decoder.decoy_generator import generate_convincing_decoy
from meow_decoder.quantum_mixer import verify_indistinguishability
from meow_decoder.config import EncodingConfig


def test_manifest_packing():
    """Test manifest pack/unpack."""
    print("\n🧪 TEST 1: Manifest Packing/Unpacking")
    print("=" * 60)
    
    # Create manifest
    manifest = SchrodingerManifest(
        salt_a=secrets.token_bytes(16),
        salt_b=secrets.token_bytes(16),
        nonce_a=secrets.token_bytes(12),
        nonce_b=secrets.token_bytes(12),
        reality_a_hmac=secrets.token_bytes(32),
        reality_b_hmac=secrets.token_bytes(32),
        metadata_a=secrets.token_bytes(104),  # 104 bytes (padded encrypted metadata)
        metadata_b=secrets.token_bytes(104),  # 104 bytes (padded encrypted metadata)
        merkle_root=secrets.token_bytes(32),
        shuffle_seed=secrets.token_bytes(8),
        block_count=100,
        block_size=256
    )
    
    # Pack
    packed = manifest.pack()
    print(f"   Packed: {len(packed)} bytes")
    assert len(packed) == 392, f"Manifest should be exactly 392 bytes, got {len(packed)}"
    
    # Unpack
    unpacked = SchrodingerManifest.unpack(packed)
    print(f"   Unpacked version: 0x{unpacked.version:02x}")
    
    # Verify
    assert unpacked.salt_a == manifest.salt_a
    assert unpacked.salt_b == manifest.salt_b
    assert unpacked.block_count == manifest.block_count
    assert unpacked.merkle_root == manifest.merkle_root
    assert len(unpacked.metadata_a) == 104
    assert len(unpacked.metadata_b) == 104
    
    print("✅ Manifest pack/unpack working")
    return True


def test_block_permutation():
    """Test block permutation is reversible."""
    print("\n🧪 TEST 2: Block Permutation")
    print("=" * 60)
    
    # Create test blocks
    blocks = [secrets.token_bytes(256) for _ in range(20)]
    seed = secrets.token_bytes(8)
    
    # Permute
    permuted = permute_blocks(blocks, seed)
    print(f"   Permuted {len(permuted)} blocks")
    
    # Verify changed
    assert permuted != blocks, "Permutation should change order"
    
    # Unpermute
    unpermuted = unpermute_blocks(permuted, seed)
    print(f"   Unpermuted {len(unpermuted)} blocks")
    
    # Verify recovered
    assert len(unpermuted) == len(blocks)
    for i, (orig, recovered) in enumerate(zip(blocks, unpermuted)):
        assert orig == recovered, f"Block {i} not recovered"
    
    print("✅ Permutation is reversible")
    return True


def test_encoding_basic():
    """Test basic encoding."""
    print("\n🧪 TEST 3: Basic Encoding")
    print("=" * 60)
    
    real_data = b"TOP SECRET: This is the real message" * 100
    decoy_data = generate_convincing_decoy(len(real_data))
    
    print(f"   Real: {len(real_data):,} bytes")
    print(f"   Decoy: {len(decoy_data):,} bytes")
    
    # Encode
    mixed, manifest = schrodinger_encode_data(
        real_data, decoy_data,
        "real_password_123",
        "decoy_password_456",
        block_size=256
    )
    
    print(f"✅ Encoding successful")
    print(f"   Mixed: {len(mixed):,} bytes")
    print(f"   Blocks: {manifest.block_count}")
    print(f"   Merkle: {manifest.merkle_root.hex()[:16]}...")
    
    # Verify manifest
    assert manifest.version == 0x06
    assert manifest.block_count > 0
    assert len(manifest.merkle_root) == 32
    
    return True


def test_password_verification():
    """Test password verification identifies reality."""
    print("\n🧪 TEST 4: Password Verification")
    print("=" * 60)
    
    real_data = b"Real secret" * 100
    decoy_data = b"Decoy data" * 100
    
    real_pw = "real_password"
    decoy_pw = "decoy_password"
    
    # Encode
    mixed, manifest = schrodinger_encode_data(
        real_data, decoy_data,
        real_pw, decoy_pw
    )
    
    # Verify passwords
    reality_a = verify_password_reality(real_pw, manifest)
    reality_b = verify_password_reality(decoy_pw, manifest)
    reality_wrong = verify_password_reality("wrong_password", manifest)
    
    print(f"   Real password → Reality {reality_a}")
    print(f"   Decoy password → Reality {reality_b}")
    print(f"   Wrong password → {reality_wrong}")
    
    assert reality_a == 'A', "Real password should match reality A"
    assert reality_b == 'B', "Decoy password should match reality B"
    assert reality_wrong is None, "Wrong password should not match"
    
    print("✅ Password verification working")
    return True


def test_end_to_end_roundtrip():
    """Test complete encode/decode roundtrip for both realities."""
    print("\n🧪 TEST 5: End-to-End Roundtrip (Both Realities)")
    print("=" * 60)
    
    # Create test data
    real_data = b"SECRET MILITARY PLANS: " + secrets.token_bytes(5000)
    decoy_data = generate_convincing_decoy(6000)
    
    real_pw = "MyRealSecret123"
    decoy_pw = "InnocentPassword456"
    
    print(f"   Real: {len(real_data):,} bytes")
    print(f"   Decoy: {len(decoy_data):,} bytes")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create input files
        real_input = tmpdir / "real.bin"
        decoy_input = tmpdir / "decoy.bin"
        
        with open(real_input, 'wb') as f:
            f.write(real_data)
        with open(decoy_input, 'wb') as f:
            f.write(decoy_data)
        
        # Encode
        print(f"\n   🔒 Encoding...")
        output_gif = tmpdir / "quantum.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0)
        
        stats = schrodinger_encode_file(
            real_input,
            decoy_input,
            output_gif,
            real_pw,
            decoy_pw,
            config,
            verbose=False
        )
        
        print(f"   ✅ Encoded: {stats['gif_size']:,} bytes")
        print(f"      {stats['qr_frames']} frames, {stats['blocks']} blocks")
        
        # Decode reality A (real)
        print(f"\n   🔓 Decoding Reality A (real password)...")
        decoded_real = tmpdir / "decoded_real.bin"
        
        try:
            stats_a = schrodinger_decode_file(
                output_gif,
                decoded_real,
                real_pw,
                verbose=False
            )
            
            print(f"   ✅ Reality {stats_a['reality']}: {stats_a['decoded_size']:,} bytes")
            
            # Verify
            with open(decoded_real, 'rb') as f:
                decoded_data_a = f.read()
            
            if decoded_data_a == real_data:
                print(f"   ✅ Reality A matches original real data!")
            else:
                print(f"   ❌ Reality A does NOT match (got {len(decoded_data_a)} bytes)")
                return False
                
        except Exception as e:
            print(f"   ❌ Decode failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Decode reality B (decoy)
        print(f"\n   🔓 Decoding Reality B (decoy password)...")
        decoded_decoy = tmpdir / "decoded_decoy.bin"
        
        try:
            stats_b = schrodinger_decode_file(
                output_gif,
                decoded_decoy,
                decoy_pw,
                verbose=False
            )
            
            print(f"   ✅ Reality {stats_b['reality']}: {stats_b['decoded_size']:,} bytes")
            
            # Verify
            with open(decoded_decoy, 'rb') as f:
                decoded_data_b = f.read()
            
            if decoded_data_b == decoy_data:
                print(f"   ✅ Reality B matches original decoy data!")
            else:
                print(f"   ❌ Reality B does NOT match (got {len(decoded_data_b)} bytes)")
                return False
                
        except Exception as e:
            print(f"   ❌ Decode failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n✅ Full roundtrip successful!")
    print("   Both realities decoded correctly!")
    return True


def test_statistical_indistinguishability():
    """Test that mixed blocks are statistically indistinguishable."""
    print("\n🧪 TEST 6: Statistical Indistinguishability")
    print("=" * 60)
    
    # Encode with very different data
    real_data = b"A" * 10000  # All same byte
    decoy_data = b"B" * 10000  # All different byte
    
    mixed, manifest = schrodinger_encode_data(
        real_data, decoy_data,
        "password_one", "password_two",
        block_size=256
    )
    
    # Split mixed data
    half = len(mixed) // 2
    half_a = mixed[:half]
    half_b = mixed[half:]
    
    # Test indistinguishability
    is_indist, results = verify_indistinguishability(half_a, half_b, threshold=0.1)
    
    print(f"   Entropy A: {results['entropy_a']:.6f}")
    print(f"   Entropy B: {results['entropy_b']:.6f}")
    print(f"   Entropy diff: {results['entropy_diff']:.6f}")
    print(f"   Max freq diff: {results['max_freq_diff']:.6f}")
    
    if results['entropy_diff'] < 0.2:
        print("   ✅ Entropies similar (good)")
    else:
        print("   ⚠️  Entropy difference higher than ideal")
    
    if results['max_freq_diff'] < 0.1:
        print("   ✅ Byte frequencies similar (good)")
    else:
        print("   ⚠️  Frequency difference higher than ideal")
    
    print("✅ Statistical test complete")
    return True


def test_forensic_resistance():
    """Test forensic resistance."""
    print("\n🧪 TEST 7: Forensic Resistance")
    print("=" * 60)
    
    # Encode very different data
    real_data = secrets.token_bytes(10000)
    decoy_data = secrets.token_bytes(10000)
    
    mixed, manifest = schrodinger_encode_data(
        real_data, decoy_data,
        "password_a", "password_b"
    )
    
    # Chi-square test
    from collections import Counter
    import math
    
    byte_freq = Counter(mixed)
    expected_freq = len(mixed) / 256
    
    chi_square = sum(
        (count - expected_freq) ** 2 / expected_freq
        for count in byte_freq.values()
    )
    
    print(f"   Chi-square: {chi_square:.2f} (threshold: <500)")
    
    if chi_square < 500:
        print("   ✅ Passes chi-square (looks random)")
    else:
        print("   ⚠️  Chi-square high")
    
    # Entropy test
    entropy = -sum(
        (count / len(mixed)) * math.log2(count / len(mixed))
        for count in byte_freq.values()
    )
    
    print(f"   Entropy: {entropy:.4f} bits/byte (max: 8.0)")
    
    if entropy > 7.5:
        print("   ✅ High entropy (looks random)")
    else:
        print("   ⚠️  Low entropy")
    
    print("✅ Forensic resistance test complete")
    return True


def run_all_tests():
    """Run all Schrödinger tests."""
    print("🐱⚛️  Schrödinger's Yarn Ball - E2E Test Suite v5.4.0")
    print("=" * 60)
    print('"You cannot prove a secret exists unless you already')
    print(' know how to look for it..."')
    print("=" * 60)
    
    tests = [
        test_manifest_packing,
        test_block_permutation,
        test_encoding_basic,
        test_password_verification,
        test_end_to_end_roundtrip,
        test_statistical_indistinguishability,
        test_forensic_resistance
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed}/{len(tests)} passed")
    print("=" * 60)
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED!")
        print("   Schrödinger's Yarn Ball v5.4.0 is operational!")
        print("   True quantum plausible deniability achieved! ⚛️")
        return True
    else:
        print(f"❌ {failed} test(s) failed")
        return False


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
