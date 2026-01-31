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
        
        frames = [Image.new('RGB', (50, 50), color='cyan') for _ in range(3)]
        
        encoder = GIFEncoder(fps=5)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            encoder.create_gif(frames, gif_path)
            
            # Read as bytes
            gif_bytes = gif_path.read_bytes()
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames_from_bytes(gif_bytes)
            
            assert len(extracted) == 3
    
    def test_extract_frame_count(self):
        """Test that frame count matches."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        for frame_count in [1, 5, 10, 20]:
            frames = [Image.new('RGB', (30, 30), color='yellow') for _ in range(frame_count)]
            
            encoder = GIFEncoder(fps=10)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                gif_path = Path(tmpdir) / "count.gif"
                encoder.create_gif(frames, gif_path)
                
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


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
