"""
🧪 Schrödinger's Yarn Ball - End-to-End Roundtrip Test
"""

import tempfile
import hashlib
from pathlib import Path
import sys
import os
import secrets

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.schrodinger_encode import schrodinger_encode_data
from meow_decoder.schrodinger_decode import schrodinger_decode_data
from meow_decoder.decoy_generator import generate_convincing_decoy

def test_schrodinger_roundtrip():
    """
    Tests the full encode -> decode pipeline for Schrödinger mode.
    Ensures both realities can be recovered with the correct password.
    """
    print("🧪 Running Schrödinger E2E Roundtrip Test")
    print("=" * 60)

    # 1. Create two distinct realities
    real_data = b"This is the real, top-secret message. The launch codes are 1234." * 10
    decoy_data = generate_convincing_decoy(len(real_data))
    
    real_password = "RealPasswordForSecret"
    decoy_password = "DecoyPasswordForInnocentFile"

    print(f"📄 Reality A (Real): {len(real_data)} bytes")
    print(f"📄 Reality B (Decoy): {len(decoy_data)} bytes")

    # 2. Encode them into a superposition
    print("\n⚛️  Encoding into superposition...")
    superposition, manifest = schrodinger_encode_data(
        real_data,
        decoy_data,
        real_password,
        decoy_password,
        block_size=256
    )
    print(f"✅ Superposition created: {len(superposition)} bytes")

    # 3. Decode Reality A (Real Secret)
    print("\n🔍 Collapsing to Reality A (Real)...")
    decoded_real = schrodinger_decode_data(superposition, manifest, real_password)
    
    assert decoded_real is not None, "Decoding with real password failed to return data."
    assert decoded_real == real_data, "Decoded real data does not match original."
    print("✅ Successfully decoded Reality A with the real password.")

    # 4. Decode Reality B (Decoy)
    print("\n🔍 Collapsing to Reality B (Decoy)...")
    decoded_decoy = schrodinger_decode_data(superposition, manifest, decoy_password)

    assert decoded_decoy is not None, "Decoding with decoy password failed to return data."
    assert decoded_decoy == decoy_data, "Decoded decoy data does not match original."
    print("✅ Successfully decoded Reality B with the decoy password.")

    # 5. Test failure with wrong password
    print("\n🔍 Testing with an incorrect password...")
    wrong_password = "ThisPasswordIsIncorrect"
    decoded_wrong = schrodinger_decode_data(superposition, manifest, wrong_password)

    assert decoded_wrong is None, "Decoding with wrong password should return None."
    print("✅ Correctly failed to decode with an incorrect password.")
    
    # 6. Test that decoy password cannot get real data
    print("\n🔍 Testing that decoy password cannot access real data...")
    decoded_with_decoy_pass = schrodinger_decode_data(superposition, manifest, decoy_password)
    assert decoded_with_decoy_pass != real_data, "Decoy password should not decrypt real data."
    print("✅ Decoy password correctly accessed only decoy data.")

    print("\n🎉 SUCCESS! Schrödinger roundtrip verified!")
    print("=" * 60)


if __name__ == "__main__":
    test_schrodinger_roundtrip()
