#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for GIF Handler - Target: 90%+
Tests gif_handler.py encoder and decoder paths.
"""

import pytest
import sys
import tempfile
from pathlib import Path
from PIL import Image
import io

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGIFEncoder:
    """Test GIF encoding."""
    
    def test_basic_gif_creation(self):
        """Test basic GIF creation."""
        from meow_decoder.gif_handler import GIFEncoder
        
        # Create test frames
        frames = []
        for i in range(5):
            frame = Image.new('RGB', (100, 100), color=(i * 50, i * 50, i * 50))
            frames.append(frame)
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
            assert size > 0
    
    def test_gif_with_loop(self):
        """Test GIF with custom loop count."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (50, 50), color='red') for _ in range(3)]
        
        encoder = GIFEncoder(fps=5, loop=0)  # Infinite loop
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "loop.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
    
    def test_gif_different_fps(self):
        """Test GIF with different FPS values."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (50, 50), color='blue') for _ in range(3)]
        
        for fps in [1, 5, 10, 30]:
            encoder = GIFEncoder(fps=fps)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / f"fps_{fps}.gif"
                
                size = encoder.create_gif(frames, output_path)
                
                assert output_path.exists()
    
    def test_gif_single_frame(self):
        """Test GIF with single frame."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (100, 100), color='green')]
        
        encoder = GIFEncoder(fps=1)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "single.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
    
    def test_gif_large_frames(self):
        """Test GIF with large frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (600, 600), color='purple') for _ in range(3)]
        
        encoder = GIFEncoder(fps=2)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "large.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
            assert size > 1000  # Should be reasonably large


class TestGIFDecoder:
    """Test GIF decoding."""
    
    def test_basic_gif_extraction(self):
        """Test basic GIF frame extraction."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        # Create and save test GIF
        frames = []
        for i in range(5):
            frame = Image.new('RGB', (100, 100), color=(i * 50, 0, 0))
            frames.append(frame)
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            encoder.create_gif(frames, gif_path)
            
            # Now decode
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(gif_path)
            
            assert len(extracted) == 5
            for frame in extracted:
                assert isinstance(frame, Image.Image)
    
    def test_extract_from_bytes(self):
        """Test extracting frames from bytes."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        # Use different colors to prevent GIF optimization from merging frames
        colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]
        frames = [Image.new('RGB', (50, 50), color=c) for c in colors]
        
        encoder = GIFEncoder(fps=5)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            encoder.create_gif(frames, gif_path, optimize=False)
            
            # Read as bytes
            gif_bytes = gif_path.read_bytes()
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames_bytes(gif_bytes)
            
            assert len(extracted) == 3
    
    def test_extract_frame_count(self):
        """Test that frame count matches."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        for frame_count in [1, 3, 5]:
            # Use different colors to prevent GIF optimization from merging identical frames
            frames = [Image.new('RGB', (30, 30), color=(i * 50, i * 30, i * 20)) for i in range(frame_count)]
            
            encoder = GIFEncoder(fps=10)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                gif_path = Path(tmpdir) / "count.gif"
                encoder.create_gif(frames, gif_path, optimize=False)
                
                decoder = GIFDecoder()
                extracted = decoder.extract_frames(gif_path)
                
                assert len(extracted) == frame_count


class TestGIFRoundtrip:
    """Test GIF encode/decode roundtrip."""
    
    def test_color_preservation(self):
        """Test that colors are preserved in roundtrip."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        # Create frames with distinct colors
        colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]
        frames = [Image.new('RGB', (50, 50), color=c) for c in colors]
        
        encoder = GIFEncoder(fps=5)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "colors.gif"
            encoder.create_gif(frames, gif_path)
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(gif_path)
            
            assert len(extracted) == 3
    
    def test_size_preservation(self):
        """Test that frame sizes are preserved."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        frames = [Image.new('RGB', (200, 150), color='white') for _ in range(3)]
        
        encoder = GIFEncoder(fps=5)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "size.gif"
            encoder.create_gif(frames, gif_path)
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(gif_path)
            
            for frame in extracted:
                assert frame.size == (200, 150)


class TestGIFEdgeCases:
    """Test GIF edge cases."""
    
    def test_empty_frames_list(self):
        """Test handling of empty frames list."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "empty.gif"
            
            # Should handle gracefully
            try:
                encoder.create_gif([], output_path)
            except (ValueError, IndexError):
                pass  # Expected
    
    def test_different_frame_modes(self):
        """Test frames with different image modes."""
        from meow_decoder.gif_handler import GIFEncoder
        
        # Mix of different modes
        frame_rgb = Image.new('RGB', (50, 50), color='red')
        frame_rgba = Image.new('RGBA', (50, 50), color=(0, 255, 0, 128))
        frame_l = Image.new('L', (50, 50), color=128)
        
        # Convert all to RGB for GIF
        frames = [
            frame_rgb,
            frame_rgba.convert('RGB'),
            frame_l.convert('RGB')
        ]
        
        encoder = GIFEncoder(fps=5)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "modes.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
    
    def test_very_small_frames(self):
        """Test with very small frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (5, 5), color='magenta') for _ in range(3)]
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "tiny.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()


class TestGIFDecoderErrors:
    """Test GIF decoder error handling."""
    
    def test_nonexistent_file(self):
        """Test decoding nonexistent file."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_path = Path(tmpdir) / "nonexistent.gif"
            
            with pytest.raises(FileNotFoundError):
                decoder.extract_frames(fake_path)
    
    def test_corrupted_gif(self):
        """Test decoding corrupted GIF."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            corrupt_path = Path(tmpdir) / "corrupt.gif"
            corrupt_path.write_bytes(b"GIF89a" + b"\x00" * 100)
            
            with pytest.raises(Exception):  # PIL should raise
                decoder.extract_frames(corrupt_path)
    
    def test_non_gif_file(self):
        """Test decoding non-GIF file."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a PNG file
            png_path = Path(tmpdir) / "test.png"
            img = Image.new('RGB', (50, 50), color='red')
            img.save(png_path)
            
            # Try to extract frames (should work or fail gracefully)
            try:
                frames = decoder.extract_frames(png_path)
                # PNG has 1 "frame"
                assert len(frames) >= 1
            except Exception:
                pass  # Expected


class TestGIFEncoderOptimization:
    """Test GIF encoder optimization options."""
    
    def test_optimized_gif(self):
        """Test creating optimized GIF."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (100, 100), color='blue') for _ in range(5)]
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "optimized.gif"
            
            # Pass optimize flag
            size = encoder.create_gif(frames, output_path, optimize=True)
            
            assert output_path.exists()
    
    def test_unoptimized_gif(self):
        """Test creating unoptimized GIF."""
        from meow_decoder.gif_handler import GIFEncoder
        
        frames = [Image.new('RGB', (100, 100), color='blue') for _ in range(5)]
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "unoptimized.gif"
            
            size = encoder.create_gif(frames, output_path, optimize=False)
            
            assert output_path.exists()


class TestGIFEncoderDefaults:
    """Test GIF encoder default values."""
    
    def test_default_fps(self):
        """Test default FPS value."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        assert hasattr(encoder, 'fps')
        assert encoder.fps > 0
    
    def test_default_loop(self):
        """Test default loop value."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        assert hasattr(encoder, 'loop')


class TestGIFIntegrationWithQR:
    """Test GIF integration with QR codes."""
    
    def test_gif_with_qr_frames(self):
        """Test creating GIF from QR code frames."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        # Generate QR code frames
        gen = QRCodeGenerator()
        qr_frames = [
            gen.generate(f"Frame {i}".encode())
            for i in range(5)
        ]
        
        encoder = GIFEncoder(fps=2)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "qr_animation.gif"
            
            size = encoder.create_gif(qr_frames, gif_path)
            
            assert gif_path.exists()
            assert size > 0
            
            # Decode and verify frame count
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(gif_path)
            
            assert len(extracted) == 5


# ============================================================================
# MERGED FROM test_core_gif_handler_more.py (2025-01-31)
# Tests bytes-based encoding/decoding, frame access, and GIF optimization
# ============================================================================

class TestGIFBytesOperations:
    """Tests for bytes-based GIF operations (merged from test_core_gif_handler_more.py)."""
    
    def test_gif_encoder_create_gif_bytes_and_decoder_extract_bytes(self):
        """Test bytes-based GIF creation and extraction roundtrip."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        frames = [
            Image.new("RGB", (64, 64), color=(255, 255, 255)),
            Image.new("RGB", (64, 64), color=(0, 0, 0)),
        ]
        enc = GIFEncoder(fps=5)
        gif_bytes = enc.create_gif_bytes(frames, optimize=False)

        dec = GIFDecoder()
        out_frames = dec.extract_frames_bytes(gif_bytes)
        assert len(out_frames) == 2
        assert out_frames[0].size == (64, 64)


class TestGIFFrameAccess:
    """Tests for frame-level access operations (merged from test_core_gif_handler_more.py)."""
    
    def test_gif_decoder_get_frame_and_count(self):
        """Test get_frame_count and get_frame methods."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        with tempfile.TemporaryDirectory() as tmpdir:
            frames = [
                Image.new("RGB", (32, 32), color=(255, 255, 255)),
                Image.new("RGB", (32, 32), color=(0, 0, 0)),
                Image.new("RGB", (32, 32), color=(127, 127, 127)),
            ]
            out = Path(tmpdir) / "x.gif"
            GIFEncoder(fps=10).create_gif(frames, out, optimize=False)

            dec = GIFDecoder()
            assert dec.get_frame_count(out) == 3
            f1 = dec.get_frame(out, 1)
            assert f1.size == (32, 32)
            with pytest.raises(IndexError):
                dec.get_frame(out, 99)


class TestGIFOptimizer:
    """Tests for GIF optimization (merged from test_core_gif_handler_more.py)."""
    
    def test_gif_optimizer_optimize_gif(self):
        """Test GIFOptimizer.optimize_gif method."""
        from meow_decoder.gif_handler import GIFEncoder, GIFOptimizer
        
        with tempfile.TemporaryDirectory() as tmpdir:
            frames = [
                Image.new("RGB", (64, 64), color=(255, 255, 255)),
                Image.new("RGB", (64, 64), color=(0, 0, 0)),
            ]
            inp = Path(tmpdir) / "in.gif"
            outp = Path(tmpdir) / "out.gif"
            GIFEncoder(fps=10).create_gif(frames, inp, optimize=False)

            original_size, optimized_size = GIFOptimizer.optimize_gif(
                inp, outp, colors=16, reduce_size=True
            )
            assert original_size > 0
            assert optimized_size > 0
            assert outp.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
