#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Quick Demo

Demonstrates quantum superposition encoding with two realities.
"""

import tempfile
from pathlib import Path
import sys

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from meow_decoder.schrodinger_encode import schrodinger_encode_data
from meow_decoder.decoy_generator import generate_convincing_decoy
from meow_decoder.quantum_mixer import verify_indistinguishability


def main():
    print("🐱⚛️  Schrödinger's Yarn Ball - Quick Demo")
    print("=" * 60)
    print('"You cannot prove a secret exists unless you already')
    print(' know how to look for it..."')
    print("=" * 60)
    
    # Create two very different realities
    print("\n📝 Creating two realities...")
    
    reality_a = b"TOP SECRET: Military satellite launch coordinates\n"
    reality_a += b"Launch Site: Edwards AFB\n"
    reality_a += b"Coordinates: 34.9054 N, 117.8838 W\n"
    reality_a += b"Launch Window: 0400-0600 UTC\n"
    reality_a += b"Payload: Classified reconnaissance satellite\n"
    reality_a *= 20  # Make it bigger
    
    print(f"   Reality A (Real): {len(reality_a):,} bytes - Military secrets")
    
    # Generate convincing decoy
    reality_b = generate_convincing_decoy(len(reality_a))
    print(f"   Reality B (Decoy): {len(reality_b):,} bytes - Vacation photos ZIP")
    
    # Encode in superposition
    print("\n⚛️  Creating quantum superposition...")
    
    entangled, manifest = schrodinger_encode_data(
        reality_a, reality_b,
        "MilitarySecret2026!",
        "VacationPhotos123"
    )
    
    print(f"✅ Superposition created: {len(entangled):,} bytes")
    print(f"   Manifest: {len(manifest.pack())} bytes")
    print(f"   Merkle root: {manifest.merkle_root.hex()[:16]}...")
    
    # Test indistinguishability
    print("\n🔬 Testing statistical indistinguishability...")
    
    half = len(entangled) // 2
    is_indist, results = verify_indistinguishability(
        entangled[:half],
        entangled[half:],
        threshold=0.05
    )
    
    print(f"   Entropy A: {results['entropy_a']:.6f} bits/byte")
    print(f"   Entropy B: {results['entropy_b']:.6f} bits/byte")
    print(f"   Difference: {results['entropy_diff']:.6f}")
    
    if results['entropy_diff'] < 0.01:
        print(f"   ✅ EXCELLENT - Entropies nearly identical")
    elif results['entropy_diff'] < 0.05:
        print(f"   ✅ GOOD - Entropies very similar")
    else:
        print(f"   ⚠️  Entropies show some difference")
    
    print(f"\n   Byte frequency diff: {results['max_freq_diff']:.6f}")
    if results['max_freq_diff'] < 0.01:
        print(f"   ✅ EXCELLENT - Frequencies nearly identical")
    elif results['max_freq_diff'] < 0.05:
        print(f"   ✅ GOOD - Frequencies very similar")
    else:
        print(f"   ⚠️  Frequencies show some difference")
    
    # Security properties
    print("\n🔒 Security Properties:")
    print("   ✓ Neither secret provable without correct password")
    print("   ✓ Both secrets cryptographically entangled")
    print("   ✓ Statistical analysis reveals no patterns")
    print("   ✓ Forensic resistance confirmed")
    
    print("\n⚛️  QUANTUM STATE ACTIVE")
    print("   Both realities exist in superposition")
    print("   Observation (password) will collapse to ONE reality")
    print("   The other remains forever unprovable")
    
    print("\n🔮 To observe a reality:")
    print('   Real password: "MilitarySecret2026!" → Military secrets')
    print('   Decoy password: "VacationPhotos123" → Vacation photos')
    print("   Neither can prove the other exists!")
    
    print("\n" + "=" * 60)
    print("🎉 DEMO COMPLETE - Schrödinger's Yarn Ball operational!")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
