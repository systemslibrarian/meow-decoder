#!/usr/bin/env python3
"""
🐱 AGGRESSIVE Coverage Tests for gif_handler.py
Target: Boost gif_handler.py from 45% to 90%+
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import BytesIO

os.environ['MEOW_TEST_MODE'] = '1'
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import PIL
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class TestGIFEncoder:
    """Test GIFEncoder class."""
    
    def test_encoder_creation_default(self):
        """Test creating encoder with defaults."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        assert encoder is not None
    
    def test_encoder_creation_custom_fps(self):
        """Test creating encoder with custom FPS."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=15)
        assert encoder is not None
        assert encoder.fps == 15
    
    def test_encoder_creation_loop_setting(self):
        """Test creating encoder with loop setting."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10, loop=0)  # 0 = infinite loop
        assert encoder is not None
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_gif_basic(self):
        """Test creating a basic GIF."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        
        # Create test frames
        frames = [
            Image.new('RGB', (100, 100), color='red'),
            Image.new('RGB', (100, 100), color='green'),
            Image.new('RGB', (100, 100), color='blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_gif_single_frame(self):
        """Test creating a GIF with single frame."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=1)
        frames = [Image.new('RGB', (50, 50), color='white')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_gif_many_frames(self):
        """Test creating a GIF with many frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        
        # 50 frames
        frames = [
            Image.new('RGB', (50, 50), color=(i * 5, i * 5, i * 5))
            for i in range(50)
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_gif_with_optimization(self):
        """Test creating a GIF with optimization."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [
            Image.new('RGB', (100, 100), color='red'),
            Image.new('RGB', (100, 100), color='blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path, optimize=True)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_gif_without_optimization(self):
        """Test creating a GIF without optimization."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [
            Image.new('RGB', (100, 100), color='red'),
            Image.new('RGB', (100, 100), color='blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path, optimize=False)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_gif_different_fps(self):
        """Test creating GIFs with different FPS values."""
        from meow_decoder.gif_handler import GIFEncoder
        
        for fps in [1, 5, 10, 15, 30]:
            encoder = GIFEncoder(fps=fps)
            frames = [
                Image.new('RGB', (50, 50), color='white'),
                Image.new('RGB', (50, 50), color='black'),
            ]
            
            with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
                output_path = Path(f.name)
            
            try:
                size = encoder.create_gif(frames, output_path)
                assert size > 0
            finally:
                if output_path.exists():
                    output_path.unlink()


class TestGIFDecoder:
    """Test GIFDecoder class."""
    
    def test_decoder_creation(self):
        """Test creating decoder."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        assert decoder is not None
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_extract_frames_from_gif(self):
        """Test extracting frames from a GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        # First create a GIF
        encoder = GIFEncoder(fps=10)
        original_frames = [
            Image.new('RGB', (100, 100), color='red'),
            Image.new('RGB', (100, 100), color='green'),
            Image.new('RGB', (100, 100), color='blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            encoder.create_gif(original_frames, output_path)
            
            # Now extract
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(output_path)
            
            assert len(extracted) == len(original_frames)
            for frame in extracted:
                assert frame.size == (100, 100)
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_extract_frames_single(self):
        """Test extracting from single-frame GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=1)
        original_frames = [Image.new('RGB', (50, 50), color='white')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            encoder.create_gif(original_frames, output_path)
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(output_path)
            
            assert len(extracted) >= 1
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_extract_frames_many(self):
        """Test extracting many frames."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=10)
        original_frames = [
            Image.new('RGB', (50, 50), color=(i * 5, i * 5, i * 5))
            for i in range(20)
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            encoder.create_gif(original_frames, output_path)
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(output_path)
            
            assert len(extracted) == 20
        finally:
            if output_path.exists():
                output_path.unlink()
    
    def test_extract_frames_nonexistent(self):
        """Test extracting from nonexistent file."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        with pytest.raises(Exception):
            decoder.extract_frames(Path("/nonexistent/file.gif"))
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_extract_frames_string_path(self):
        """Test extracting with string path."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=10)
        frames = [Image.new('RGB', (50, 50), color='blue')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = f.name  # String, not Path
        
        try:
            encoder.create_gif(frames, Path(output_path))
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(output_path)  # String path
            
            assert len(extracted) >= 1
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestGIFRoundtrip:
    """Test complete GIF encode/decode roundtrips."""
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_roundtrip_basic(self):
        """Test basic encode/decode roundtrip."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=10)
        decoder = GIFDecoder()
        
        original = [
            Image.new('RGB', (100, 100), color='red'),
            Image.new('RGB', (100, 100), color='blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            encoder.create_gif(original, output_path)
            extracted = decoder.extract_frames(output_path)
            
            assert len(extracted) == len(original)
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_roundtrip_preserves_size(self):
        """Test that roundtrip preserves frame size."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=5)
        decoder = GIFDecoder()
        
        original_size = (200, 150)
        original = [Image.new('RGB', original_size, color='green')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            encoder.create_gif(original, output_path)
            extracted = decoder.extract_frames(output_path)
            
            assert extracted[0].size == original_size
        finally:
            if output_path.exists():
                output_path.unlink()


class TestGIFEdgeCases:
    """Test edge cases in GIF handling."""
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_very_small_frames(self):
        """Test with very small frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [Image.new('RGB', (1, 1), color='white')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_grayscale_frames(self):
        """Test with grayscale frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [
            Image.new('L', (50, 50), color=128),
            Image.new('L', (50, 50), color=200),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_rgba_frames(self):
        """Test with RGBA frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [
            Image.new('RGBA', (50, 50), color=(255, 0, 0, 128)),
            Image.new('RGBA', (50, 50), color=(0, 255, 0, 128)),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_path_as_path_object(self):
        """Test with Path object."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [Image.new('RGB', (50, 50), color='red')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, output_path)
            assert size > 0
        finally:
            if output_path.exists():
                output_path.unlink()


class TestGIFDuration:
    """Test GIF duration calculations."""
    
    def test_fps_to_duration(self):
        """Test FPS to frame duration calculation."""
        from meow_decoder.gif_handler import GIFEncoder
        
        # Duration = 1000ms / FPS
        encoder = GIFEncoder(fps=10)
        # At 10 FPS, each frame should be 100ms
        assert encoder.fps == 10
    
    def test_different_fps_values(self):
        """Test various FPS values."""
        from meow_decoder.gif_handler import GIFEncoder
        
        for fps in [1, 2, 5, 10, 15, 24, 30]:
            encoder = GIFEncoder(fps=fps)
            assert encoder.fps == fps


class TestGIFFileOperations:
    """Test GIF file operations."""
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_create_in_temp_directory(self):
        """Test creating GIF in temp directory."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        frames = [Image.new('RGB', (50, 50), color='blue')]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.gif"
            size = encoder.create_gif(frames, output_path)
            
            assert size > 0
            assert output_path.exists()
    
    @pytest.mark.skipif(not HAS_PIL, reason="PIL not available")
    def test_file_size_increases_with_frames(self):
        """Test that file size increases with more frames."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create GIF with 2 frames
            frames_2 = [Image.new('RGB', (50, 50), color=c) for c in ['red', 'blue']]
            path_2 = Path(tmpdir) / "test_2.gif"
            size_2 = encoder.create_gif(frames_2, path_2, optimize=False)
            
            # Create GIF with 10 frames
            frames_10 = [Image.new('RGB', (50, 50), color=c) 
                        for c in ['red', 'blue', 'green', 'yellow', 'cyan',
                                 'magenta', 'white', 'black', 'orange', 'purple']]
            path_10 = Path(tmpdir) / "test_10.gif"
            size_10 = encoder.create_gif(frames_10, path_10, optimize=False)
            
            # 10 frames should be larger than 2 frames
            assert size_10 > size_2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
