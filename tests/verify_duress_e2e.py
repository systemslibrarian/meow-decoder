"""
DEPRECATED: This file is deprecated as of Merge 5 consolidation.
E2E duress tests are now in:
- test_duress_mode.py (includes integration scenarios)
- test_e2e.py (general encode/decode e2e)
"""

import os
import sys
import shutil
import pytest
from pathlib import Path

# Skip entire file - deprecated in favor of canonical test files
pytestmark = pytest.mark.skip(reason="DEPRECATED: Merged into canonical duress test files (Merge 5)")

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.config import EncodingConfig
from meow_decoder.duress_mode import DuressHandler
from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair

def test_duress_e2e():
    """Manual E2E test for duress mode (requires FS)."""
    print("\n🚨 Testing Duress Mode E2E")
    
    # Setup
    tmp_dir = Path("tests/temp_duress")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)
    
    input_file = tmp_dir / "secret.txt"
    input_file.write_text("Real Secret Data")
    
    output_gif = tmp_dir / "duress.gif"
    decoded_file = tmp_dir / "decoded.txt"
    
    real_password = "real_password"
    duress_password = "duress_password"
    
    # Generate keys for FS (required for Duress ambiguity resolution)
    receiver_priv, receiver_pub = generate_receiver_keypair()
    
    config = EncodingConfig(
        block_size=64, # Small block size
        redundancy=3.0, # High redundancy for reliable tests
        fps=10
    )
    
    # 1. Encode with duress password configuration + FS
    print("1. Encoding with duress password configured (+FS)...")
    encode_file(
        input_file, 
        output_gif, 
        real_password, 
        duress_password=duress_password,
        receiver_public_key=receiver_pub,
        forward_secrecy=True,
        config=config,
        verbose=True
    )
    
    assert output_gif.exists()
    
    # 2. Decode with REAL password (should work)
    print("\n2. Decoding with REAL password...")
    decode_gif(
        str(output_gif),
        str(decoded_file),
        real_password,
        receiver_private_key=receiver_priv,
        verbose=True
    )
    
    assert decoded_file.exists()
    assert decoded_file.read_text() == "Real Secret Data"
    print("   ✅ Real password works")
    
    # 3. Decode with DURESS password (should trigger exception + cleanup)
    print("\n3. Decoding with DURESS password...")
    decoded_file.unlink() # Cleanup previous decode
    
    try:
        decode_gif(
            str(output_gif),
            str(decoded_file),
            duress_password,
            receiver_private_key=receiver_priv,
            verbose=True
        )
        print("   ❌ Failed: Should have raised exception")
        assert False, "Duress decoding should fail"
    except ValueError as e:
        print(f"   ✅ Correctly raised exception: {e}")
        # Message might vary based on how DuressHandler exits or mocks
        # But we expect failure.
        assert not decoded_file.exists()
        
    # Cleanup
    shutil.rmtree(tmp_dir)
    print("\n✅ Duress E2E Test Passed!")

if __name__ == "__main__":
    test_duress_e2e()
