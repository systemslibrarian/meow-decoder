"""
QR Code Module for Meow Decoder
Handles QR code generation and reading using qrcode and pyzbar libraries
"""

import qrcode
from PIL import Image
from typing import List, Optional, Tuple
import cv2
import numpy as np
from pyzbar import pyzbar


class QRCodeGenerator:
    """
    QR code generator with configurable parameters.
    """
    
    def __init__(self,
                 error_correction: str = "H",
                 box_size: int = 14,
                 border: int = 4):
        """
        Initialize QR code generator.
        
        Args:
            error_correction: Error correction level (L/M/Q/H) - default "H" for GIF
            box_size: Size of each box in pixels - default 14 for GIF readability
            border: Border size in boxes
            
        Note:
            Defaults are optimized for QR codes embedded in GIF animations.
            High error correction (H) and larger box size (14) improve decode
            reliability after GIF compression/quantization.
        """
        self.error_correction_map = {
            "L": qrcode.constants.ERROR_CORRECT_L,  # ~7% correction
            "M": qrcode.constants.ERROR_CORRECT_M,  # ~15% correction
            "Q": qrcode.constants.ERROR_CORRECT_Q,  # ~25% correction
            "H": qrcode.constants.ERROR_CORRECT_H   # ~30% correction
        }
        
        self.error_correction = self.error_correction_map.get(
            error_correction, qrcode.constants.ERROR_CORRECT_M
        )
        self.box_size = box_size
        self.border = border
    
    def generate(self, data: bytes) -> Image.Image:
        """
        Generate QR code from data.
        
        Args:
            data: Binary data to encode
            
        Returns:
            PIL Image of QR code
            
        Note:
            Data is base85-encoded before QR generation to avoid qrcode library
            issues with certain binary patterns (glog(0) error). This makes the
            QR payload purely ASCII and sidesteps Reed-Solomon edge cases.
        """
        import base64
        
        # Base85 encode to make data ASCII-safe for QR library
        # This avoids glog(0) errors with certain binary patterns
        ascii_data = base64.b85encode(data).decode('ascii')
        
        qr = qrcode.QRCode(
            version=None,  # Auto-detect
            error_correction=self.error_correction,
            box_size=self.box_size,
            border=self.border
        )
        
        # Use ASCII string (not bytes) to avoid binary encoding issues
        qr.add_data(ascii_data, optimize=0)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        return img.convert("RGB")
    
    def generate_batch(self, data_list: List[bytes]) -> List[Image.Image]:
        """
        Generate multiple QR codes.
        
        Args:
            data_list: List of binary data to encode
            
        Returns:
            List of QR code images
        """
        return [self.generate(data) for data in data_list]


class QRCodeReader:
    """
    QR code reader using pyzbar and OpenCV.
    """
    
    def __init__(self, preprocessing: str = "normal"):
        """
        Initialize QR code reader.
        
        Args:
            preprocessing: Preprocessing mode (normal/aggressive)
        """
        self.preprocessing = preprocessing
    
    def read_image(self, image: Image.Image) -> List[bytes]:
        """
        Read QR codes from PIL Image.
        
        Args:
            image: PIL Image containing QR code(s)
            
        Returns:
            List of decoded data (bytes)
            
        Note:
            Automatically decodes base85-encoded QR data back to binary.
        """
        import base64
        
        # Convert PIL to numpy array
        img_array = np.array(image)
        
        # Apply preprocessing
        if self.preprocessing == "aggressive":
            img_array = self._preprocess_aggressive(img_array)
        elif self.preprocessing == "normal":
            img_array = self._preprocess_normal(img_array)
        
        # Decode QR codes
        decoded_objects = pyzbar.decode(img_array)
        
        # Extract data and decode base85
        results = []
        for obj in decoded_objects:
            try:
                # Decode as ASCII string first, then base85 decode to binary
                if isinstance(obj.data, bytes):
                    ascii_str = obj.data.decode('ascii')
                else:
                    ascii_str = obj.data
                binary_data = base64.b85decode(ascii_str)
                results.append(binary_data)
            except Exception:
                # Fall back to raw bytes (old format or non-base85 data)
                results.append(obj.data if isinstance(obj.data, bytes) else obj.data.encode())
        
        return results
    
    def read_frame(self, frame: np.ndarray) -> List[bytes]:
        """
        Read QR codes from OpenCV frame.
        
        Args:
            frame: OpenCV frame (numpy array)
            
        Returns:
            List of decoded data (bytes)
            
        Note:
            Automatically decodes base85-encoded QR data back to binary.
        """
        import base64
        
        # Apply preprocessing
        if self.preprocessing == "aggressive":
            frame = self._preprocess_aggressive(frame)
        elif self.preprocessing == "normal":
            frame = self._preprocess_normal(frame)
        
        # Decode QR codes
        decoded_objects = pyzbar.decode(frame)
        
        # Extract data and decode base85
        results = []
        for obj in decoded_objects:
            try:
                # Decode as ASCII string first, then base85 decode to binary
                if isinstance(obj.data, bytes):
                    ascii_str = obj.data.decode('ascii')
                else:
                    ascii_str = obj.data
                binary_data = base64.b85decode(ascii_str)
                results.append(binary_data)
            except Exception:
                # Fall back to raw bytes (old format or non-base85 data)
                results.append(obj.data if isinstance(obj.data, bytes) else obj.data.encode())
        
        return results
    
    def _preprocess_normal(self, img: np.ndarray) -> np.ndarray:
        """
        Apply normal preprocessing.
        
        Args:
            img: Input image
            
        Returns:
            Preprocessed image
        """
        # Convert to grayscale if needed
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Simple thresholding
        _, img = cv2.threshold(img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        
        return img
    
    def _preprocess_aggressive(self, img: np.ndarray) -> np.ndarray:
        """
        Apply aggressive preprocessing for difficult QR codes.
        
        Args:
            img: Input image
            
        Returns:
            Preprocessed image
        """
        # Convert to grayscale if needed
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Denoise
        img = cv2.fastNlMeansDenoising(img, None, 10, 7, 21)
        
        # Adaptive thresholding
        img = cv2.adaptiveThreshold(
            img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
            cv2.THRESH_BINARY, 11, 2
        )
        
        # Morphological operations to clean up
        kernel = np.ones((3, 3), np.uint8)
        img = cv2.morphologyEx(img, cv2.MORPH_CLOSE, kernel)
        img = cv2.morphologyEx(img, cv2.MORPH_OPEN, kernel)
        
        return img


class WebcamQRReader:
    """
    QR code reader from webcam feed.
    """
    
    def __init__(self,
                 device: int = 0,
                 preprocessing: str = "normal",
                 frame_skip: int = 0):
        """
        Initialize webcam QR reader.
        
        Args:
            device: Webcam device index
            preprocessing: Preprocessing mode
            frame_skip: Skip N frames between reads (for performance)
        """
        self.device = device
        self.reader = QRCodeReader(preprocessing)
        self.frame_skip = frame_skip
        self.frame_count = 0
        
        # Open webcam
        self.cap = cv2.VideoCapture(device)
        if not self.cap.isOpened():
            raise RuntimeError(f"Failed to open webcam device {device}")
    
    def read_next(self) -> Optional[Tuple[bytes, np.ndarray]]:
        """
        Read next QR code from webcam.
        
        Returns:
            Tuple of (qr_data, frame) or None if no QR found
        """
        while True:
            ret, frame = self.cap.read()
            
            if not ret:
                return None
            
            # Skip frames if configured
            self.frame_count += 1
            if self.frame_skip > 0 and self.frame_count % (self.frame_skip + 1) != 0:
                continue
            
            # Try to read QR code
            results = self.reader.read_frame(frame)
            
            if results:
                return results[0], frame
    
    def read_continuous(self, callback, max_frames: Optional[int] = None):
        """
        Continuously read QR codes and call callback.
        
        Args:
            callback: Function to call with (qr_data, frame)
            max_frames: Maximum frames to read (None = infinite)
        """
        frames_read = 0
        
        while True:
            if max_frames and frames_read >= max_frames:
                break
            
            result = self.read_next()
            if result:
                qr_data, frame = result
                callback(qr_data, frame)
                frames_read += 1
    
    def release(self):
        """Release webcam."""
        if self.cap:
            self.cap.release()
    
    def __del__(self):
        """Cleanup on deletion."""
        self.release()


# Testing
if __name__ == "__main__":
    print("Testing QR Code Module...\n")
    
    # Test 1: Generate QR code
    print("1. Testing QR code generation...")
    
    generator = QRCodeGenerator(error_correction="M")
    test_data = b"Hello, Meow Decoder!"
    
    qr_image = generator.generate(test_data)
    print(f"   Generated QR code: {qr_image.size}")
    print("   ✓ QR generation works")
    
    # Test 2: Read QR code
    print("\n2. Testing QR code reading...")
    
    reader = QRCodeReader(preprocessing="normal")
    decoded = reader.read_image(qr_image)
    
    if decoded and decoded[0] == test_data:
        print("   ✓ QR reading works (roundtrip successful)")
    else:
        print(f"   ✗ QR reading failed (got: {decoded})")
    
    # Test 3: Batch generation
    print("\n3. Testing batch generation...")
    
    batch_data = [
        b"Droplet 1",
        b"Droplet 2",
        b"Droplet 3"
    ]
    
    batch_qr = generator.generate_batch(batch_data)
    print(f"   Generated {len(batch_qr)} QR codes")
    
    # Read them back
    all_match = True
    for i, qr in enumerate(batch_qr):
        decoded = reader.read_image(qr)
        if not decoded or decoded[0] != batch_data[i]:
            all_match = False
            break
    
    if all_match:
        print("   ✓ Batch roundtrip successful")
    else:
        print("   ✗ Batch roundtrip failed")
    
    # Test 4: Different error correction levels
    print("\n4. Testing error correction levels...")
    
    for level in ["L", "M", "Q", "H"]:
        gen = QRCodeGenerator(error_correction=level)
        qr = gen.generate(test_data)
        decoded = reader.read_image(qr)
        
        if decoded and decoded[0] == test_data:
            print(f"   Level {level}: ✓ ({qr.size[0]}x{qr.size[1]})")
        else:
            print(f"   Level {level}: ✗")
    
    # Test 5: Large data
    print("\n5. Testing large data...")
    
    large_data = b"X" * 2000  # ~2KB
    try:
        qr = generator.generate(large_data)
        decoded = reader.read_image(qr)
        
        if decoded and decoded[0] == large_data:
            print(f"   ✓ Large data works ({len(large_data)} bytes → {qr.size})")
        else:
            print("   ✗ Large data failed")
    except Exception as e:
        print(f"   ✗ Large data error: {e}")
    
    print("\n✅ All QR code tests complete!")
    print("\nNote: Webcam test requires physical webcam - skipped")
