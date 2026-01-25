#!/usr/bin/env python3
"""
Complete E2E test for Schrödinger's Yarn Ball
"""

import sys
import tempfile
from pathlib import Path
import hashlib

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from meow_decoder.schrodinger_encode import schrodinger_encode_file
from meow_decoder.schrodinger_decode import schrodinger_decode_file
from meow_decoder.config import EncodingConfig

def test_full_roundtrip():
    """Test complete encode/decode roundtrip"""
    
    print("🐱⚛️  Testing Full Schrödinger Roundtrip")
    print("=" * 60)
    
    # Create test data
    real_data = b"TOP SECRET: This is the real message!" * 50
    decoy_data = b"Innocent vacation photos and shopping lists..." * 50
    
    real_hash = hashlib.sha256(real_data).digest()
    decoy_hash = hashlib.sha256(decoy_data).digest()
    
    print(f"\n📝 Test Data:")
    print(f"   Real: {len(real_data)} bytes")
    print(f"   Real hash: {real_hash.hex()[:16]}...")
    print(f"   Decoy: {len(decoy_data)} bytes")
    print(f"   Decoy hash: {decoy_hash.hex()[:16]}...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Write test files
        real_file = tmpdir / "real.txt"
        decoy_file = tmpdir / "decoy.txt"
        gif_file = tmpdir / "quantum.gif"
        out_real = tmpdir / "decoded_real.txt"
        out_decoy = tmpdir / "decoded_decoy.txt"
        
        real_file.write_bytes(real_data)
        decoy_file.write_bytes(decoy_data)
        
        # Encode
        print("\n⚛️  Encoding...")
        config = EncodingConfig(block_size=256, redundancy=1.5)
        
        try:
            stats = schrodinger_encode_file(
                real_file,
                decoy_file,
                gif_file,
                "password_real_123",
                "password_decoy_456",
                config,
                auto_generate_decoy=False,
                verbose=False
            )
            
            print(f"✅ Encoding successful")
            print(f"   GIF: {stats['gif_size']:,} bytes")
            print(f"   Frames: {stats['qr_frames']}")
            print(f"   Merkle: {stats['merkle_root'][:16]}...")
            
        except Exception as e:
            print(f"❌ Encoding failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Decode reality A (real)
        print("\n🔮 Decoding Reality A (real password)...")
        try:
            stats_a = schrodinger_decode_file(
                gif_file,
                out_real,
                "password_real_123",
                verbose=False
            )
            
            decoded_real = out_real.read_bytes()
            decoded_hash = hashlib.sha256(decoded_real).digest()
            
            print(f"✅ Decoded: {len(decoded_real)} bytes")
            print(f"   Hash: {decoded_hash.hex()[:16]}...")
            
            if decoded_hash == real_hash:
                print(f"   ✅ MATCH! Reality A correct")
            else:
                print(f"   ❌ MISMATCH! Reality A incorrect")
                return False
                
        except Exception as e:
            print(f"❌ Decode A failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Decode reality B (decoy)
        print("\n🔮 Decoding Reality B (decoy password)...")
        try:
            stats_b = schrodinger_decode_file(
                gif_file,
                out_decoy,
                "password_decoy_456",
                verbose=False
            )
            
            decoded_decoy = out_decoy.read_bytes()
            decoded_hash = hashlib.sha256(decoded_decoy).digest()
            
            print(f"✅ Decoded: {len(decoded_decoy)} bytes")
            print(f"   Hash: {decoded_hash.hex()[:16]}...")
            
            if decoded_hash == decoy_hash:
                print(f"   ✅ MATCH! Reality B correct")
            else:
                print(f"   ❌ MISMATCH! Reality B incorrect")
                return False
                
        except Exception as e:
            print(f"❌ Decode B failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n" + "=" * 60)
    print("🎉 FULL ROUNDTRIP SUCCESS!")
    print("   Both realities decoded correctly")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    success = test_full_roundtrip()
    sys.exit(0 if success else 1)
