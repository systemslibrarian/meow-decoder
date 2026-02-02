#!/usr/bin/env python3
"""
Standalone Forward Secrecy Debug Test
Run this to see exactly what's happening during HMAC computation
"""

import sys
import tempfile
from pathlib import Path

# Add debug flag
sys.argv.append('--debug')

def test_forward_secrecy_debug():
    """Run forward secrecy test with full debug output"""
    from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
    from meow_decoder.encode import encode_file
    from meow_decoder.decode_gif import decode_gif
    from cryptography.hazmat.primitives import serialization
    
    print("\n" + "="*80)
    print("FORWARD SECRECY DEBUG TEST")
    print("="*80 + "\n")
    
    # Generate receiver keys (returns key objects)
    print("Step 1: Generating X25519 receiver keypair...")
    privkey_obj, pubkey_obj = generate_receiver_keypair()
    
    # Serialize BOTH to Raw bytes (32 bytes each)
    privkey = privkey_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pubkey = pubkey_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    print(f"  Receiver public key (hex): {pubkey.hex()}")
    print(f"  Receiver private key (first 8 bytes): {privkey[:8].hex()}")
    
    # Create test data
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        input_file = tmpdir / "test.txt"
        gif_file = tmpdir / "test.gif"
        output_file = tmpdir / "output.txt"
        
        test_data = "Forward secrecy test data"
        input_file.write_text(test_data)
        
        password = "testpass123"
        
        print(f"\nStep 2: Encoding with forward secrecy...")
        print(f"  Password: {password}")
        print(f"  Test data: {test_data}")
        print()
        
        # ENCODING
        encode_file(
            input_file,
            gif_file,
            password=password,
            receiver_public_key=pubkey  # 32 bytes
        )
        
        print(f"\nStep 3: Decoding with receiver private key...")
        print()
        
        # DECODING
        try:
            decode_gif(
                gif_file,
                output_file,
                password=password,
                receiver_private_key=privkey  # 32 bytes
            )
            
            # Verify
            result = output_file.read_text()
            
            print("\n" + "="*80)
            if result == test_data:
                print("✅ SUCCESS: Forward secrecy roundtrip worked!")
                print(f"   Original: {test_data}")
                print(f"   Decoded:  {result}")
            else:
                print("❌ FAILURE: Data mismatch!")
                print(f"   Original: {test_data}")
                print(f"   Decoded:  {result}")
            print("="*80 + "\n")
            
        except Exception as e:
            print("\n" + "="*80)
            print(f"❌ FAILURE: {type(e).__name__}: {e}")
            print("="*80 + "\n")
            raise

if __name__ == "__main__":
    test_forward_secrecy_debug()
