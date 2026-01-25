#!/usr/bin/env python3
"""
🧪 End-to-End Integration Test
Tests the complete encode → decode pipeline with SHA256 verification.
"""

import tempfile
import hashlib
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.config import EncodingConfig


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def test_encode_decode_roundtrip():
    """
    Golden Path Test: Encode a file, decode it back, verify hash matches.
    
    This is the canonical "it actually works end-to-end" test.
    """
    print("🧪 Running E2E Integration Test")
    print("=" * 60)
    
    # Test data
    test_data = ("Hello, Meow Decoder! This is a test message. 😺🔐\n" * 100).encode("utf-8")
    test_password = "TestCatPassword123!"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create test file
        input_file = tmpdir / "test_input.txt"
        input_file.write_bytes(test_data)
        print(f"✅ Created test input: {len(test_data)} bytes")
        
        # Compute original hash
        original_hash = compute_sha256(input_file)
        print(f"📋 Original SHA256: {original_hash}")
        
        # Encode
        output_gif = tmpdir / "test_output.gif"
        config = EncodingConfig(
            block_size=256,  # Small for faster test
            redundancy=2.0,  # Increased for reliable decoding
            fps=15
        )
        
        print("\n🔒 Encoding...")
        try:
            stats = encode_file(
                input_file,
                output_gif,
                test_password,
                config=config,
                verbose=False
            )
            print(f"✅ Encoded: {stats['qr_frames']} frames")
        except Exception as e:
            print(f"❌ ENCODE FAILED: {e}")
            import traceback
            traceback.print_exc()
            raise AssertionError(f"Encoding failed: {e}")
        
        # Verify GIF was created
        assert output_gif.exists(), f"Output GIF not created: {output_gif}"
        
        print(f"📊 GIF size: {output_gif.stat().st_size} bytes")
        
        # Decode
        decoded_file = tmpdir / "test_decoded.txt"
        
        print("\n🔓 Decoding...")
        try:
            decode_gif(
                str(output_gif),
                str(decoded_file),
                test_password,
                verbose=False
            )
            print(f"✅ Decoded to: {decoded_file}")
        except Exception as e:
            print(f"❌ DECODE FAILED: {e}")
            import traceback
            traceback.print_exc()
            raise AssertionError(f"Decoding failed: {e}")
        
        # Verify decoded file was created
        assert decoded_file.exists(), f"Decoded file not created: {decoded_file}"
        
        # Compute decoded hash
        decoded_hash = compute_sha256(decoded_file)
        print(f"📋 Decoded SHA256: {decoded_hash}")
        
        # Compare hashes
        print(f"\n📊 Comparing hashes...")
        print(f"   Original:  {original_hash}")
        print(f"   Decoded:   {decoded_hash}")
        
        assert original_hash == decoded_hash, f"Hash mismatch! Original: {original_hash}, Decoded: {decoded_hash}"
        
        print("\n✅ SUCCESS! Hash match - roundtrip verified!")
        return True

def test_wrong_password():
    """Test that wrong password fails gracefully."""
    print("\n🧪 Testing wrong password handling")
    print("=" * 60)
    
    test_data = b"Secret data"
    correct_password = "CorrectPassword123"
    wrong_password = "WrongPassword456"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create and encode
        input_file = tmpdir / "secret.txt"
        input_file.write_bytes(test_data)
        
        output_gif = tmpdir / "secret.gif"
        config = EncodingConfig(block_size=128, redundancy=1.1, fps=10)
        
        try:
            encode_file(
                input_file,
                output_gif,
                correct_password,
                config=config,
                verbose=False
            )
        except Exception as e:
            print(f"❌ Encode failed: {e}")
            raise AssertionError(f"Encode failed in wrong password test: {e}")
        
        # Try to decode with wrong password
        decoded_file = tmpdir / "decoded.txt"
        
        try:
            decode_gif(
                str(output_gif),
                str(decoded_file),
                wrong_password,
                verbose=False
            )
            # Should not reach here - wrong password should raise exception
            raise AssertionError("Should have rejected wrong password!")
        except AssertionError:
            raise  # Re-raise assertion errors
        except Exception as e:
            print(f"✅ Correctly rejected wrong password: {type(e).__name__}")
            return True


def main():
    """Run all integration tests."""
    print("🐱 Meow Decoder - Integration Tests")
    print("=" * 60)
    print()
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: Golden path roundtrip
    try:
        if test_encode_decode_roundtrip():
            tests_passed += 1
        else:
            tests_failed += 1
    except Exception as e:
        print(f"❌ Test crashed: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    # Test 2: Wrong password
    try:
        if test_wrong_password():
            tests_passed += 1
        else:
            tests_failed += 1
    except Exception as e:
        print(f"❌ Test crashed: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"🧪 Test Results: {tests_passed} passed, {tests_failed} failed")
    print("=" * 60)
    
    if tests_failed == 0:
        print("✅ All tests passed! 🎉")
        return 0
    else:
        print("❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
