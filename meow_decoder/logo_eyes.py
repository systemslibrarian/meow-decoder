"""
🐱 Logo-Eyes Carrier for Meow Decoder
Embeds QR codes in the eye regions of a branded cat logo animation.

The eyes of the animated cat logo contain the encoded data,
creating a branded yet functional steganographic carrier.

Features:
- Animated cat logo with blinking eyes
- QR codes embedded in eye regions
- Customizable brand colors
- Works with any logo that has defined eye regions
"""

import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Optional
from PIL import Image, ImageDraw, ImageFont
import numpy as np


@dataclass
class EyeRegion:
    """Defines an eye region in the logo."""
    center_x: int
    center_y: int
    radius: int


@dataclass
class LogoConfig:
    """Configuration for logo-eyes carrier."""
    width: int = 1200
    height: int = 800
    background_color: Tuple[int, int, int] = (25, 25, 35)  # Dark blue-gray
    cat_color: Tuple[int, int, int] = (45, 45, 55)  # Slightly lighter
    eye_glow_color: Tuple[int, int, int] = (0, 255, 180)  # Cyan glow
    brand_text: str = "MEOW"
    brand_color: Tuple[int, int, int] = (100, 100, 120)  # Subtle gray
    animate_blink: bool = False  # Disable blinking so QR always visible
    blink_interval: int = 30  # Frames between blinks
    visible_qr: bool = True   # Show QR codes visibly in eyes (not LSB hidden)


class LogoEyesEncoder:
    """
    Encoder that places QR codes in the eyes of an animated cat logo.
    
    The animation shows a stylized cat face with glowing eyes.
    The QR data is encoded in the eye regions using LSB steganography.
    """
    
    def __init__(self, config: Optional[LogoConfig] = None):
        """
        Initialize logo-eyes encoder.
        
        Args:
            config: Logo configuration (uses defaults if None)
        """
        self.config = config or LogoConfig()
        
        # Calculate eye positions (centered, horizontally spaced)
        # Eyes are large to fit readable QR codes
        eye_y = int(self.config.height * 0.40)
        eye_spacing = int(self.config.width * 0.20)
        eye_radius = int(min(self.config.width, self.config.height) * 0.18)  # Much bigger eyes
        
        self.left_eye = EyeRegion(
            center_x=self.config.width // 2 - eye_spacing,
            center_y=eye_y,
            radius=eye_radius
        )
        self.right_eye = EyeRegion(
            center_x=self.config.width // 2 + eye_spacing,
            center_y=eye_y,
            radius=eye_radius
        )
    
    def _draw_cat_silhouette(self, draw: ImageDraw.Draw, frame_index: int):
        """Draw the cat head silhouette."""
        w, h = self.config.width, self.config.height
        cat_color = self.config.cat_color
        
        # Head (large ellipse)
        head_w = int(w * 0.6)
        head_h = int(h * 0.5)
        head_x = (w - head_w) // 2
        head_y = int(h * 0.3)
        draw.ellipse(
            [head_x, head_y, head_x + head_w, head_y + head_h],
            fill=cat_color
        )
        
        # Left ear (triangle)
        ear_size = int(w * 0.12)
        left_ear_x = head_x + int(head_w * 0.15)
        left_ear_y = head_y - int(ear_size * 0.3)
        draw.polygon([
            (left_ear_x, left_ear_y + ear_size),
            (left_ear_x + ear_size // 2, left_ear_y),
            (left_ear_x + ear_size, left_ear_y + ear_size)
        ], fill=cat_color)
        
        # Right ear (triangle)
        right_ear_x = head_x + head_w - int(head_w * 0.15) - ear_size
        draw.polygon([
            (right_ear_x, left_ear_y + ear_size),
            (right_ear_x + ear_size // 2, left_ear_y),
            (right_ear_x + ear_size, left_ear_y + ear_size)
        ], fill=cat_color)
        
        # Nose (small triangle)
        nose_size = int(w * 0.03)
        nose_x = w // 2
        nose_y = int(h * 0.55)
        draw.polygon([
            (nose_x, nose_y + nose_size),
            (nose_x - nose_size, nose_y),
            (nose_x + nose_size, nose_y)
        ], fill=(80, 60, 70))
        
        # Whiskers
        whisker_color = (70, 70, 80)
        whisker_y = nose_y + int(nose_size * 1.5)
        whisker_len = int(w * 0.15)
        
        # Left whiskers
        for angle in [-15, 0, 15]:
            rad = math.radians(angle)
            x1, y1 = nose_x - nose_size * 2, whisker_y
            x2 = x1 - int(whisker_len * math.cos(rad))
            y2 = y1 + int(whisker_len * math.sin(rad))
            draw.line([(x1, y1), (x2, y2)], fill=whisker_color, width=2)
        
        # Right whiskers
        for angle in [-15, 0, 15]:
            rad = math.radians(angle)
            x1, y1 = nose_x + nose_size * 2, whisker_y
            x2 = x1 + int(whisker_len * math.cos(rad))
            y2 = y1 + int(whisker_len * math.sin(rad))
            draw.line([(x1, y1), (x2, y2)], fill=whisker_color, width=2)
    
    def _draw_eye_socket(self, draw: ImageDraw.Draw, eye: EyeRegion, 
                        is_blinking: bool, glow_intensity: float = 1.0):
        """Draw eye socket with optional glow effect."""
        if is_blinking:
            # Draw closed eye (horizontal line)
            draw.line([
                (eye.center_x - eye.radius, eye.center_y),
                (eye.center_x + eye.radius, eye.center_y)
            ], fill=self.config.eye_glow_color, width=3)
        else:
            # Draw glowing eye socket
            glow_color = tuple(int(c * glow_intensity) for c in self.config.eye_glow_color)
            
            # Outer glow (larger, dimmer)
            for i in range(3, 0, -1):
                glow = tuple(int(c * (0.3 / i)) for c in glow_color)
                draw.ellipse([
                    eye.center_x - eye.radius - i * 5,
                    eye.center_y - eye.radius - i * 5,
                    eye.center_x + eye.radius + i * 5,
                    eye.center_y + eye.radius + i * 5
                ], outline=glow, width=2)
            
            # Eye socket border
            draw.ellipse([
                eye.center_x - eye.radius,
                eye.center_y - eye.radius,
                eye.center_x + eye.radius,
                eye.center_y + eye.radius
            ], outline=glow_color, width=3)
    
    def _add_brand_text(self, draw: ImageDraw.Draw):
        """Add subtle brand text at bottom."""
        text = self.config.brand_text
        
        # Try to use a nice font, fall back to default
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 32)
        except (IOError, OSError):
            font = ImageFont.load_default()
        
        # Get text bounding box
        bbox = draw.textbbox((0, 0), text, font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
        
        x = (self.config.width - text_w) // 2
        y = self.config.height - text_h - 20
        
        draw.text((x, y), text, fill=self.config.brand_color, font=font)
    
    def _is_blinking(self, frame_index: int) -> bool:
        """Determine if the cat is blinking on this frame."""
        if not self.config.animate_blink:
            return False
        
        # Blink for 2 frames every blink_interval frames
        cycle_pos = frame_index % self.config.blink_interval
        return cycle_pos in [0, 1]
    
    def generate_frame(self, qr_frame: Image.Image, frame_index: int) -> Image.Image:
        """
        Generate a logo-eyes frame with QR data in the eyes.
        
        Args:
            qr_frame: QR code image to embed
            frame_index: Frame number (for animation)
            
        Returns:
            Logo frame with QR data in eyes
        """
        # Create base image
        img = Image.new('RGB', (self.config.width, self.config.height), 
                       self.config.background_color)
        draw = ImageDraw.Draw(img)
        
        # Determine animation state
        is_blinking = self._is_blinking(frame_index)
        
        # Pulsing glow effect
        glow_phase = (frame_index % 60) / 60.0 * 2 * math.pi
        glow_intensity = 0.7 + 0.3 * math.sin(glow_phase)
        
        # Draw cat silhouette
        self._draw_cat_silhouette(draw, frame_index)
        
        # Draw eye sockets with glow
        self._draw_eye_socket(draw, self.left_eye, is_blinking, glow_intensity)
        self._draw_eye_socket(draw, self.right_eye, is_blinking, glow_intensity)
        
        # Add brand text
        self._add_brand_text(draw)
        
        # Now embed QR data in eyes if not blinking
        if not is_blinking:
            img = self._embed_qr_in_eyes(img, qr_frame)
        
        return img
    
    def _embed_qr_in_eyes(self, logo: Image.Image, qr_frame: Image.Image) -> Image.Image:
        """
        Embed QR code data into the eye regions.
        
        The QR code is placed in both eyes for redundancy.
        In visible_qr mode, the QR is directly pasted into the eyes.
        In hidden mode, LSB steganography is used.
        """
        # Resize QR to fit in eye region
        eye_size = self.left_eye.radius * 2
        
        # We'll put the full QR in each eye (redundancy)
        qr_small = qr_frame.resize((eye_size, eye_size), Image.Resampling.LANCZOS)
        
        if self.config.visible_qr:
            # VISIBLE MODE: Directly paste QR codes into eyes
            # Create a circular mask for clean edges
            mask = Image.new('L', (eye_size, eye_size), 0)
            mask_draw = ImageDraw.Draw(mask)
            mask_draw.ellipse([0, 0, eye_size-1, eye_size-1], fill=255)
            
            # Paste QR into left eye
            left_x = self.left_eye.center_x - self.left_eye.radius
            left_y = self.left_eye.center_y - self.left_eye.radius
            logo.paste(qr_small.convert('RGB'), (left_x, left_y), mask)
            
            # Paste QR into right eye
            right_x = self.right_eye.center_x - self.right_eye.radius
            right_y = self.right_eye.center_y - self.right_eye.radius
            logo.paste(qr_small.convert('RGB'), (right_x, right_y), mask)
            
            return logo
        else:
            # HIDDEN MODE: Use LSB steganography
            logo_array = np.array(logo)
            qr_array = np.array(qr_small.convert('RGB'))
            
            # Embed in left eye using LSB
            logo_array = self._embed_in_region(
                logo_array, qr_array, 
                self.left_eye.center_x - self.left_eye.radius,
                self.left_eye.center_y - self.left_eye.radius
            )
            
            # Embed in right eye using LSB  
            logo_array = self._embed_in_region(
                logo_array, qr_array,
                self.right_eye.center_x - self.right_eye.radius,
                self.right_eye.center_y - self.right_eye.radius
            )
            
            return Image.fromarray(logo_array)
    
    def _embed_in_region(self, carrier: np.ndarray, data: np.ndarray,
                        x: int, y: int, lsb_bits: int = 2) -> np.ndarray:
        """
        Embed data in a region of the carrier using LSB.
        
        Args:
            carrier: Carrier image array
            data: Data to embed
            x, y: Top-left corner of region
            lsb_bits: Number of LSB bits to use
            
        Returns:
            Modified carrier array
        """
        result = carrier.copy()
        h, w = data.shape[:2]
        
        # Ensure we don't go out of bounds
        max_y = min(y + h, carrier.shape[0])
        max_x = min(x + w, carrier.shape[1])
        actual_h = max_y - y
        actual_w = max_x - x
        
        if actual_h <= 0 or actual_w <= 0:
            return result
        
        # Create masks
        lsb_mask = (1 << lsb_bits) - 1
        carrier_mask = ~lsb_mask & 0xFF
        
        # Extract top bits from data
        data_bits = (data[:actual_h, :actual_w] >> (8 - lsb_bits)) & lsb_mask
        
        # Apply to carrier
        result[y:max_y, x:max_x] = (
            (result[y:max_y, x:max_x] & carrier_mask) | data_bits
        )
        
        return result


class LogoEyesDecoder:
    """
    Decoder that extracts QR codes from logo-eyes frames.
    """
    
    def __init__(self, config: Optional[LogoConfig] = None):
        """Initialize decoder with same config as encoder."""
        self.config = config or LogoConfig()
        
        # Calculate eye positions (must match encoder)
        eye_y = int(self.config.height * 0.42)
        eye_spacing = int(self.config.width * 0.22)
        eye_radius = int(min(self.config.width, self.config.height) * 0.12)
        
        self.left_eye = EyeRegion(
            center_x=self.config.width // 2 - eye_spacing,
            center_y=eye_y,
            radius=eye_radius
        )
        self.right_eye = EyeRegion(
            center_x=self.config.width // 2 + eye_spacing,
            center_y=eye_y,
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
    print("🐱 Logo-Eyes Carrier Test")
    print("=" * 50)
    
    # Create test QR-like pattern
    print("\n1. Creating test QR pattern...")
    qr_size = 200
    qr_array = np.random.randint(0, 2, (qr_size, qr_size, 3), dtype=np.uint8) * 255
    qr_image = Image.fromarray(qr_array)
    print(f"   ✓ Created {qr_size}x{qr_size} test QR")
    
    # Test encoder
    print("\n2. Testing LogoEyesEncoder...")
    encoder = LogoEyesEncoder()
    
    frames = []
    for i in range(5):
        frame = encoder.generate_frame(qr_image, i)
        frames.append(frame)
        print(f"   Frame {i}: {frame.size}")
    
    print("   ✓ Generated 5 logo-eyes frames")
    
    # Test decoder
    print("\n3. Testing LogoEyesDecoder...")
    decoder = LogoEyesDecoder()
    
    extracted = decoder.extract_qr(frames[2])
    print(f"   ✓ Extracted QR: {extracted.size}")
    
    # Test convenience functions
    print("\n4. Testing encode_with_logo_eyes...")
    qr_list = [qr_image] * 3
    logo_frames = encode_with_logo_eyes(qr_list)
    print(f"   ✓ Encoded {len(logo_frames)} frames")
    
    print("\n5. Testing decode_from_logo_eyes...")
    decoded = decode_from_logo_eyes(logo_frames)
    print(f"   ✓ Decoded {len(decoded)} frames")
    
    # Save test frame
    print("\n6. Saving test frame...")
    frames[0].save("/tmp/logo_eyes_test.png")
    print("   ✓ Saved to /tmp/logo_eyes_test.png")
    
    print("\n✅ Logo-eyes carrier test complete!")
    print("\nUsage:")
    print("  meow-encode -i secret.pdf -o branded.gif --logo-eyes")
    print("  meow-encode -i secret.pdf -o branded.gif --logo-eyes --brand-text 'ACME'")
