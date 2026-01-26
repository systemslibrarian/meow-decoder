"""
🐱 Logo-Eyes Carrier for Meow Decoder
Embeds QR codes in the eye regions of the ACTUAL Meow Decoder logo.

Uses the real logo from assets/meow-decoder-logo.png and places
QR codes in the eye regions, scaled to be readable.

Features:
- Uses the actual Meow Decoder branded logo
- QR codes embedded in eye regions  
- Scales logo up for readable QR codes
- Works with the official logo design
"""

import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Optional
from PIL import Image, ImageDraw, ImageFont
import numpy as np


# Eye positions in the ORIGINAL 765x602 logo (detected from green areas)
ORIGINAL_LOGO_SIZE = (765, 602)
ORIGINAL_LEFT_EYE = (302, 263)   # center
ORIGINAL_RIGHT_EYE = (489, 264)  # center
ORIGINAL_EYE_RADIUS = 50         # approximate visible eye area


@dataclass
class EyeRegion:
    """Defines an eye region in the logo."""
    center_x: int
    center_y: int
    radius: int


@dataclass
class LogoConfig:
    """Configuration for logo-eyes carrier."""
    # Scale factor: how much to enlarge the logo for readable QR codes
    # At scale 4x, eyes become ~200px radius which can fit ~400px QR codes
    scale: float = 4.0
    
    # Background color (shown around the logo if needed)
    background_color: Tuple[int, int, int] = (0, 0, 0)
    
    # Brand text override (if you want custom text instead of logo text)
    brand_text: str = None
    
    # Whether to animate (currently just static for readability)
    animate_blink: bool = False
    
    # Show QR codes visibly in eyes (True) or use LSB steganography (False)
    visible_qr: bool = True
    
    # Path to logo file (relative to package or absolute)
    logo_path: Optional[str] = None


class LogoEyesEncoder:
    """
    Encoder that places QR codes in the eyes of the Meow Decoder logo.
    
    Uses the actual branded logo and embeds QR codes in the eye regions.
    The logo is scaled up to ensure QR codes remain readable.
    """
    
    def __init__(self, config: Optional[LogoConfig] = None):
        """
        Initialize logo-eyes encoder.
        
        Args:
            config: Logo configuration (uses defaults if None)
        """
        self.config = config or LogoConfig()
        
        # Load the actual logo
        self.logo = self._load_logo()
        
        # Calculate scaled dimensions
        self.width = int(ORIGINAL_LOGO_SIZE[0] * self.config.scale)
        self.height = int(ORIGINAL_LOGO_SIZE[1] * self.config.scale)
        
        # Scale eye positions
        scale = self.config.scale
        eye_radius = int(ORIGINAL_EYE_RADIUS * scale)
        
        self.left_eye = EyeRegion(
            center_x=int(ORIGINAL_LEFT_EYE[0] * scale),
            center_y=int(ORIGINAL_LEFT_EYE[1] * scale),
            radius=eye_radius
        )
        self.right_eye = EyeRegion(
            center_x=int(ORIGINAL_RIGHT_EYE[0] * scale),
            center_y=int(ORIGINAL_RIGHT_EYE[1] * scale),
            radius=eye_radius
        )
    
    def _load_logo(self) -> Image.Image:
        """Load the Meow Decoder logo."""
        # Try to find the logo in various locations
        possible_paths = [
            self.config.logo_path,
            Path(__file__).parent.parent / "assets" / "meow-decoder-logo.png",
            Path("assets/meow-decoder-logo.png"),
            Path(__file__).parent / "assets" / "meow-decoder-logo.png",
            Path("/workspaces/meow-decoder/assets/meow-decoder-logo.png"),
        ]
        
        for path in possible_paths:
            if path and Path(path).exists():
                logo = Image.open(path).convert('RGBA')
                return logo
        
        # If no logo found, create a simple placeholder
        print("⚠️  Warning: Could not find meow-decoder-logo.png, using placeholder")
        return self._create_placeholder_logo()
    
    def _create_placeholder_logo(self) -> Image.Image:
        """Create a simple placeholder if logo not found."""
        img = Image.new('RGBA', ORIGINAL_LOGO_SIZE, (0, 0, 0, 255))
        draw = ImageDraw.Draw(img)
        
        w, h = ORIGINAL_LOGO_SIZE
        # Simple cat face outline
        draw.ellipse([w//4, h//4, 3*w//4, 3*h//4], outline=(255, 255, 255), width=3)
        # Eyes (circles)
        draw.ellipse([ORIGINAL_LEFT_EYE[0]-30, ORIGINAL_LEFT_EYE[1]-30,
                     ORIGINAL_LEFT_EYE[0]+30, ORIGINAL_LEFT_EYE[1]+30], 
                    outline=(0, 255, 100), width=2)
        draw.ellipse([ORIGINAL_RIGHT_EYE[0]-30, ORIGINAL_RIGHT_EYE[1]-30,
                     ORIGINAL_RIGHT_EYE[0]+30, ORIGINAL_RIGHT_EYE[1]+30], 
                    outline=(0, 255, 100), width=2)
        # Ears
        draw.polygon([(w//4, h//4), (w//4 - 50, h//8), (w//4 + 50, h//4)], 
                    outline=(255, 255, 255))
        draw.polygon([(3*w//4, h//4), (3*w//4 + 50, h//8), (3*w//4 - 50, h//4)], 
                    outline=(255, 255, 255))
        # Text
        draw.text((w//2 - 100, h - 50), "MEOW DECODER", fill=(255, 255, 255))
        
        return img
    
    def _get_scaled_logo(self) -> Image.Image:
        """Get the logo scaled to target size."""
        return self.logo.resize((self.width, self.height), Image.Resampling.LANCZOS)
    
    def generate_frame(self, qr_frame: Image.Image, frame_index: int) -> Image.Image:
        """
        Generate a logo-eyes frame with QR data in the eyes.
        
        Args:
            qr_frame: QR code image to embed
            frame_index: Frame number (for animation)
            
        Returns:
            Logo frame with QR data in eyes
        """
        # Create base image with background
        img = Image.new('RGB', (self.width, self.height), self.config.background_color)
        
        # Get scaled logo
        scaled_logo = self._get_scaled_logo()
        
        # Paste logo onto background (handle alpha)
        if scaled_logo.mode == 'RGBA':
            img.paste(scaled_logo, (0, 0), scaled_logo)
        else:
            img.paste(scaled_logo, (0, 0))
        
        # Embed QR data in eyes
        if self.config.visible_qr:
            img = self._embed_qr_visible(img, qr_frame)
        else:
            img = self._embed_qr_steganographic(img, qr_frame)
        
        return img
    
    def _embed_qr_visible(self, logo: Image.Image, qr_frame: Image.Image) -> Image.Image:
        """
        Embed QR code visibly into the eye regions.
        
        The QR code is resized to fit in each eye and pasted directly.
        """
        # Resize QR to fit in eye region
        eye_diameter = self.left_eye.radius * 2
        qr_size = int(eye_diameter * 0.95)  # 95% of eye diameter
        
        qr_resized = qr_frame.resize((qr_size, qr_size), Image.Resampling.LANCZOS)
        
        # Create a circular mask
        mask = Image.new('L', (qr_size, qr_size), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.ellipse([0, 0, qr_size-1, qr_size-1], fill=255)
        
        # Calculate paste positions (center QR in each eye)
        left_x = self.left_eye.center_x - qr_size // 2
        left_y = self.left_eye.center_y - qr_size // 2
        right_x = self.right_eye.center_x - qr_size // 2
        right_y = self.right_eye.center_y - qr_size // 2
        
        # Convert QR to RGB if needed
        qr_rgb = qr_resized.convert('RGB')
        
        # Paste QR into both eyes
        logo.paste(qr_rgb, (left_x, left_y), mask)
        logo.paste(qr_rgb, (right_x, right_y), mask)
        
        return logo
    
    def _embed_qr_steganographic(self, logo: Image.Image, qr_frame: Image.Image) -> Image.Image:
        """
        Embed QR code using LSB steganography in eye regions.
        
        This is less visible but harder to decode.
        """
        logo_array = np.array(logo)
        
        # Resize QR to fit in eye
        eye_size = self.left_eye.radius * 2
        qr_small = qr_frame.resize((eye_size, eye_size), Image.Resampling.LANCZOS)
        qr_array = np.array(qr_small.convert('L'))  # Grayscale
        
        # Embed in left eye using LSB
        for dy in range(-self.left_eye.radius, self.left_eye.radius):
            for dx in range(-self.left_eye.radius, self.left_eye.radius):
                if dx*dx + dy*dy <= self.left_eye.radius * self.left_eye.radius:
                    x = self.left_eye.center_x + dx
                    y = self.left_eye.center_y + dy
                    qr_x = dx + self.left_eye.radius
                    qr_y = dy + self.left_eye.radius
                    
                    if 0 <= x < logo_array.shape[1] and 0 <= y < logo_array.shape[0]:
                        if 0 <= qr_x < eye_size and 0 <= qr_y < eye_size:
                            # Embed 1 bit from QR into LSB of each RGB channel
                            qr_bit = 1 if qr_array[qr_y, qr_x] > 127 else 0
                            for c in range(3):
                                logo_array[y, x, c] = (logo_array[y, x, c] & 0xFE) | qr_bit
        
        # Embed in right eye using LSB
        for dy in range(-self.right_eye.radius, self.right_eye.radius):
            for dx in range(-self.right_eye.radius, self.right_eye.radius):
                if dx*dx + dy*dy <= self.right_eye.radius * self.right_eye.radius:
                    x = self.right_eye.center_x + dx
                    y = self.right_eye.center_y + dy
                    qr_x = dx + self.right_eye.radius
                    qr_y = dy + self.right_eye.radius
                    
                    if 0 <= x < logo_array.shape[1] and 0 <= y < logo_array.shape[0]:
                        if 0 <= qr_x < eye_size and 0 <= qr_y < eye_size:
                            qr_bit = 1 if qr_array[qr_y, qr_x] > 127 else 0
                            for c in range(3):
                                logo_array[y, x, c] = (logo_array[y, x, c] & 0xFE) | qr_bit
        
        return Image.fromarray(logo_array)


class LogoEyesDecoder:
    """
    Decoder that extracts QR codes from logo-eyes frames.
    """
    
    def __init__(self, config: Optional[LogoConfig] = None):
        """Initialize decoder with same config as encoder."""
        self.config = config or LogoConfig()
        
        # Calculate eye positions (must match encoder)
        scale = self.config.scale
        eye_radius = int(ORIGINAL_EYE_RADIUS * scale)
        
        self.left_eye = EyeRegion(
            center_x=int(ORIGINAL_LEFT_EYE[0] * scale),
            center_y=int(ORIGINAL_LEFT_EYE[1] * scale),
            radius=eye_radius
        )
        self.right_eye = EyeRegion(
            center_x=int(ORIGINAL_RIGHT_EYE[0] * scale),
            center_y=int(ORIGINAL_RIGHT_EYE[1] * scale),
            radius=eye_radius
        )
    
    def extract_qr(self, frame: Image.Image, lsb_bits: int = 2) -> Image.Image:
        """
        Extract QR code from eye regions.
        
        Args:
            frame: Logo-eyes frame
            lsb_bits: Number of LSB bits used for embedding
            
        Returns:
            Extracted QR code image
        """
        frame_array = np.array(frame)
        eye_size = self.left_eye.radius * 2
        
        # Extract from left eye
        left_qr = self._extract_from_region(
            frame_array,
            self.left_eye.center_x - self.left_eye.radius,
            self.left_eye.center_y - self.left_eye.radius,
            eye_size, eye_size, lsb_bits
        )
        
        # Extract from right eye
        right_qr = self._extract_from_region(
            frame_array,
            self.right_eye.center_x - self.right_eye.radius,
            self.right_eye.center_y - self.right_eye.radius,
            eye_size, eye_size, lsb_bits
        )
        
        # Average both eyes (redundancy)
        combined = ((left_qr.astype(np.int16) + right_qr.astype(np.int16)) // 2).astype(np.uint8)
        
        return Image.fromarray(combined)
    
    def _extract_from_region(self, carrier: np.ndarray, x: int, y: int,
                            w: int, h: int, lsb_bits: int) -> np.ndarray:
        """Extract embedded data from a region."""
        # Ensure bounds
        max_y = min(y + h, carrier.shape[0])
        max_x = min(x + w, carrier.shape[1])
        actual_h = max_y - y
        actual_w = max_x - x
        
        if actual_h <= 0 or actual_w <= 0:
            return np.zeros((h, w, 3), dtype=np.uint8)
        
        # Extract LSB bits and shift to top
        lsb_mask = (1 << lsb_bits) - 1
        extracted = (carrier[y:max_y, x:max_x] & lsb_mask) << (8 - lsb_bits)
        
        # Pad if needed
        result = np.zeros((h, w, 3), dtype=np.uint8)
        result[:actual_h, :actual_w] = extracted
        
        return result


def encode_with_logo_eyes(
    qr_frames: List[Image.Image],
    config: Optional[LogoConfig] = None
) -> List[Image.Image]:
    """
    Encode QR frames using logo-eyes carrier.
    
    Args:
        qr_frames: List of QR code images
        config: Optional logo configuration
        
    Returns:
        List of logo-eyes frames with embedded QR data
    """
    encoder = LogoEyesEncoder(config)
    
    return [
        encoder.generate_frame(qr, i)
        for i, qr in enumerate(qr_frames)
    ]


def decode_from_logo_eyes(
    frames: List[Image.Image],
    config: Optional[LogoConfig] = None,
    lsb_bits: int = 2
) -> List[Image.Image]:
    """
    Decode QR frames from logo-eyes carrier.
    
    Args:
        frames: List of logo-eyes frames
        config: Optional logo configuration
        lsb_bits: Number of LSB bits used
        
    Returns:
        List of extracted QR code images
    """
    decoder = LogoEyesDecoder(config)
    
    return [decoder.extract_qr(frame, lsb_bits) for frame in frames]


# Testing
if __name__ == "__main__":
    from meow_decoder.qr_code import QRCodeGenerator
    
    print("🐱 Logo-Eyes Carrier Test (Using Actual Logo)")
    print("=" * 50)
    
    # Create test QR code
    print("\n1. Creating test QR code...")
    qr_gen = QRCodeGenerator(error_correction='M', box_size=10, border=4)
    test_data = b"For God so loved the world, that he gave his only begotten Son"
    qr_image = qr_gen.generate(test_data)
    print(f"   QR size: {qr_image.size}")
    
    # Test encoder with default config (4x scale)
    print("\n2. Testing LogoEyesEncoder with actual logo...")
    config = LogoConfig(scale=4.0, visible_qr=True)
    encoder = LogoEyesEncoder(config)
    
    print(f"   Output size: {encoder.width}x{encoder.height}")
    print(f"   Left eye: ({encoder.left_eye.center_x}, {encoder.left_eye.center_y}) r={encoder.left_eye.radius}")
    print(f"   Right eye: ({encoder.right_eye.center_x}, {encoder.right_eye.center_y}) r={encoder.right_eye.radius}")
    print(f"   Eye diameter: {encoder.left_eye.radius * 2}px")
    print(f"   QR resize: {qr_image.size[0]} -> {int(encoder.left_eye.radius * 2 * 0.95)}")
    
    # Generate frames
    frames = []
    for i in range(3):
        frame = encoder.generate_frame(qr_image, i)
        frames.append(frame)
        print(f"   Frame {i}: {frame.size}")
    
    print("   ✓ Generated 3 logo-eyes frames")
    
    # Save test frame to a temp location (avoid hardcoded /tmp path)
    print("\n3. Saving test frame...")
    import tempfile
    from pathlib import Path

    temp_dir = Path(tempfile.gettempdir())
    temp_path = temp_dir / "logo_eyes_test.png"
    frames[0].save(temp_path)
    print(f"   ✓ Saved to {temp_path}")
    
    print("\n✅ Logo-eyes carrier test complete!")
    print("\nUsage:")
    print("  meow-encode -i secret.pdf -o branded.gif --logo-eyes")
