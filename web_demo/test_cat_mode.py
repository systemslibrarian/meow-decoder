#!/usr/bin/env python3
"""
Quick integration test for Cat Mode encoding/decoding
"""

import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.config import EncodingConfig, DecodingConfig


def test_cat_mode():
    """Test Cat Mode encoding and decoding."""
    print("🐱 Testing Cat Mode Integration...")

    # Create test file
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Test input
        input_file = tmpdir / "test.txt"
        input_file.write_text("Hello, Cat Mode! 😻")

        # Test output — use PNG (APNG) for stego cat mode.
        # GIF palette quantization (256 colors) destroys LSB-embedded data.
        # APNG is lossless, preserving stego pixel values through save/load.
        output_gif = tmpdir / "test_cat.png"

        # Test recovered file
        recovered_file = tmpdir / "recovered.txt"

        # Cat carrier path
        cat_carrier = Path(__file__).parent.parent / "assets" / "demo_logo_eyes.gif"

        if not cat_carrier.exists():
            print(f"❌ Cat carrier not found at: {cat_carrier}")
            return False

        print(f"✅ Cat carrier found: {cat_carrier}")

        # Configure encoding - stego needs higher redundancy due to lossy channel
        config = EncodingConfig()
        config.redundancy = 2.5

        # Encode with Cat Mode
        print("\n📝 Encoding with Cat Mode...")
        try:
            stats = encode_file(
                input_path=input_file,
                output_path=output_gif,
                password="test1234",  # Must be 8+ characters
                config=config,
                stego_level=2,
                carrier_images=[cat_carrier],
                verbose=True,
            )
            print(f"✅ Encoding successful!")
            print(f"   QR frames: {stats.get('qr_frames', 'N/A')}")
            print(f"   GIF size: {output_gif.stat().st_size} bytes")
        except Exception as e:
            print(f"❌ Encoding failed: {e}")
            import traceback

            traceback.print_exc()
            return False

        # Decode
        print("\n🔓 Decoding...")
        try:
            decode_config = DecodingConfig()
            decode_stats = decode_gif(
                input_path=output_gif,
                output_path=recovered_file,
                password="test1234",  # Must match encoding password
                config=decode_config,
                verbose=True,
            )
            print(f"✅ Decoding successful!")
        except Exception as e:
            print(f"❌ Decoding failed: {e}")
            import traceback

            traceback.print_exc()
            return False

        # Verify content
        original_content = input_file.read_text()
        recovered_content = recovered_file.read_text()

        if original_content == recovered_content:
            print(f"✅ Content matches! '{recovered_content}'")
            print("\n🎉 Cat Mode integration test PASSED! 😻")
            return True
        else:
            print(f"❌ Content mismatch!")
            print(f"   Original:  {original_content}")
            print(f"   Recovered: {recovered_content}")
            return False


if __name__ == "__main__":
    success = test_cat_mode()
    sys.exit(0 if success else 1)
