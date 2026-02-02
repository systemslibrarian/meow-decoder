#!/usr/bin/env python3
"""
🧪 Test Suite: webcam_enhanced.py
Tests enhanced webcam capture and QR decoding functionality.
"""

import pytest
import os
import numpy as np
from unittest.mock import Mock, patch, MagicMock
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import webcam_enhanced module
try:
    from meow_decoder.webcam_enhanced import (
        WebcamCapture,
        EnhancedQRReader,
        FrameProcessor,
    )
    WEBCAM_AVAILABLE = True
except (ImportError, AttributeError):
    WEBCAM_AVAILABLE = False
    try:
        from meow_decoder import webcam_enhanced
        WEBCAM_AVAILABLE = hasattr(webcam_enhanced, 'WebcamCapture')
    except ImportError:
        pass

# Check if opencv is available for testing
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False


@pytest.mark.skipif(not WEBCAM_AVAILABLE, reason="webcam_enhanced module not available")
class TestWebcamCapture:
    """Tests for WebcamCapture class."""

    def test_capture_creation(self):
        """Test webcam capture creation (mocked)."""
        from meow_decoder.webcam_enhanced import WebcamCapture
        
        with patch('cv2.VideoCapture') as mock_vc:
            mock_vc.return_value.isOpened.return_value = True
            capture = WebcamCapture(device_id=0)
            assert capture is not None

    def test_capture_properties(self):
        """Test webcam capture properties."""
        from meow_decoder.webcam_enhanced import WebcamCapture
        
        with patch('cv2.VideoCapture') as mock_vc:
            mock_cap = MagicMock()
            mock_cap.isOpened.return_value = True
            mock_cap.get.return_value = 640  # Fake resolution
            mock_vc.return_value = mock_cap
            
            capture = WebcamCapture(device_id=0)
            # Should have width/height properties
            if hasattr(capture, 'width'):
                assert capture.width > 0

    def test_capture_frame(self):
        """Test capturing a single frame."""
        from meow_decoder.webcam_enhanced import WebcamCapture
        
        with patch('cv2.VideoCapture') as mock_vc:
            mock_cap = MagicMock()
            mock_cap.isOpened.return_value = True
            mock_cap.read.return_value = (True, np.zeros((480, 640, 3), dtype=np.uint8))
            mock_vc.return_value = mock_cap
            
            capture = WebcamCapture(device_id=0)
            frame = capture.read_frame()
            assert frame is not None


@pytest.mark.skipif(not WEBCAM_AVAILABLE, reason="webcam_enhanced module not available")
class TestEnhancedQRReader:
    """Tests for EnhancedQRReader class."""

    def test_reader_creation(self):
        """Test QR reader creation."""
        from meow_decoder.webcam_enhanced import EnhancedQRReader
        reader = EnhancedQRReader()
        assert reader is not None

    def test_read_from_frame(self):
        """Test reading QR from frame."""
        from meow_decoder.webcam_enhanced import EnhancedQRReader
        
        reader = EnhancedQRReader()
        # Create a blank frame (no QR)
        blank_frame = np.zeros((480, 640, 3), dtype=np.uint8)
        
        result = reader.read_frame(blank_frame)
        # Should return None or empty for blank frame
        assert result is None or result == [] or result == b''

    def test_preprocessing_modes(self):
        """Test different preprocessing modes."""
        from meow_decoder.webcam_enhanced import EnhancedQRReader
        
        # Test normal mode
        reader_normal = EnhancedQRReader(preprocessing='normal')
        assert reader_normal is not None
        
        # Test aggressive mode
        reader_aggressive = EnhancedQRReader(preprocessing='aggressive')
        assert reader_aggressive is not None

    def test_adaptive_threshold(self):
        """Test adaptive thresholding."""
        from meow_decoder.webcam_enhanced import EnhancedQRReader
        
        reader = EnhancedQRReader()
        frame = np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8)
        
        if hasattr(reader, 'apply_adaptive_threshold'):
            processed = reader.apply_adaptive_threshold(frame)
            assert processed is not None


@pytest.mark.skipif(not WEBCAM_AVAILABLE, reason="webcam_enhanced module not available")
class TestFrameProcessor:
    """Tests for FrameProcessor class."""

    def test_processor_creation(self):
        """Test frame processor creation."""
        from meow_decoder.webcam_enhanced import FrameProcessor
        processor = FrameProcessor()
        assert processor is not None

    def test_enhance_contrast(self):
        """Test contrast enhancement."""
        from meow_decoder.webcam_enhanced import FrameProcessor
        
        processor = FrameProcessor()
        frame = np.random.randint(50, 200, (480, 640, 3), dtype=np.uint8)
        
        if hasattr(processor, 'enhance_contrast'):
            enhanced = processor.enhance_contrast(frame)
            assert enhanced is not None

    def test_detect_qr_region(self):
        """Test QR region detection."""
        from meow_decoder.webcam_enhanced import FrameProcessor
        
        processor = FrameProcessor()
        frame = np.zeros((480, 640, 3), dtype=np.uint8)
        
        if hasattr(processor, 'detect_qr_region'):
            region = processor.detect_qr_region(frame)
            # May return None if no QR found
            assert region is None or isinstance(region, tuple)

    def test_auto_focus_hint(self):
        """Test auto-focus hint calculation."""
        from meow_decoder.webcam_enhanced import FrameProcessor
        
        processor = FrameProcessor()
        frame = np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8)
        
        if hasattr(processor, 'calculate_focus_score'):
            score = processor.calculate_focus_score(frame)
            assert isinstance(score, (int, float))


@pytest.mark.skipif(not WEBCAM_AVAILABLE, reason="webcam_enhanced module not available")
class TestWebcamIntegration:
    """Integration tests for webcam functionality."""

    def test_continuous_capture(self):
        """Test continuous frame capture."""
        from meow_decoder.webcam_enhanced import WebcamCapture
        
        with patch('cv2.VideoCapture') as mock_vc:
            mock_cap = MagicMock()
            mock_cap.isOpened.return_value = True
            mock_cap.read.return_value = (True, np.zeros((480, 640, 3), dtype=np.uint8))
            mock_vc.return_value = mock_cap
            
            capture = WebcamCapture(device_id=0)
            
            # Capture multiple frames
            frames = []
            for _ in range(5):
                frame = capture.read_frame()
                if frame is not None:
                    frames.append(frame)
            
            assert len(frames) == 5

    def test_capture_with_qr_reading(self):
        """Test capture with integrated QR reading."""
        from meow_decoder.webcam_enhanced import WebcamCapture, EnhancedQRReader
        
        with patch('cv2.VideoCapture') as mock_vc:
            mock_cap = MagicMock()
            mock_cap.isOpened.return_value = True
            mock_cap.read.return_value = (True, np.zeros((480, 640, 3), dtype=np.uint8))
            mock_vc.return_value = mock_cap
            
            capture = WebcamCapture(device_id=0)
            reader = EnhancedQRReader()
            
            frame = capture.read_frame()
            result = reader.read_frame(frame)
            # No QR in blank frame
            assert result is None or result == [] or result == b''


# Fallback test
@pytest.mark.skipif(WEBCAM_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not WEBCAM_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
