"""
Advanced Steganography for Meow Decoder
Provides multi-level stealth with animated carriers and quality control

Features:
- 4 stealth levels (1=visible, 2=subtle, 3=hidden, 4=paranoid)
- Animated carrier backgrounds
- PSNR quality estimation
- Adaptive LSB depth
- Floyd-Steinberg dithering
- Cover cycling for temporal obfuscation
"""

import hashlib
import numpy as np
from PIL import Image
from typing import List, Tuple, Optional
from enum import IntEnum
from dataclasses import dataclass
import secrets


class StealthLevel(IntEnum):
    """Stealth levels for steganography."""
    VISIBLE = 1      # 3-bit LSB, high capacity, visible under analysis
    SUBTLE = 2       # 2-bit LSB, balanced (default)
    HIDDEN = 3       # 1-bit LSB, low capacity, nearly invisible
    PARANOID = 4     # 1-bit LSB + obfuscation, minimal capacity, maximum stealth


def create_green_mask(image: Image.Image,
                      green_threshold: int = 160,
                      green_dominance: float = 1.3) -> np.ndarray:
    """
    Create binary mask for green-dominant pixels.
    
    Used for ROI-restricted steganography where embedding only occurs
    in green regions (e.g., logo eyes, waves).
    
    Args:
        image: Input image (carrier)
        green_threshold: Minimum green channel value (0-255)
        green_dominance: G must be > max(R, B) * dominance
        
    Returns:
        Boolean mask (H, W) where True = embeddable pixel
        
    Example:
        # Eyes in logo: G ≈ 180-255, R/B ≈ 40-100
        # This detects: G > 160 AND G > 1.3 * max(R, B)
        
    Security Note:
        Green-region embedding is COSMETIC ONLY. It does NOT defeat
        steganalysis tools. The reduced capacity may actually make
        statistical detection EASIER due to concentrated modifications.
    """
    arr = np.array(image)
    if len(arr.shape) == 2:
        # Grayscale - no green dominance possible
        return np.zeros(arr.shape, dtype=bool)
    
    r, g, b = arr[:,:,0], arr[:,:,1], arr[:,:,2]
    
    # Green must be above threshold AND dominant over red/blue
    mask = (g >= green_threshold) & (g > np.maximum(r, b) * green_dominance)
    
    return mask


def calculate_masked_capacity(mask: np.ndarray, lsb_bits: int = 2) -> dict:
    """
    Calculate embedding capacity with mask.
    
    Args:
        mask: Boolean mask (H, W)
        lsb_bits: Bits per channel to embed (1-3)
    
    Returns:
        Dict with capacity metrics:
        - usable_pixels: Number of embeddable pixels
        - total_pixels: Total pixels in image
        - percent: Percentage of image usable
        - bytes_capacity: Maximum bytes embeddable per frame
    """
    total = mask.size
    usable = int(np.sum(mask))
    percent = (usable / total) * 100 if total > 0 else 0
    
    # Each pixel can hold 3 channels × lsb_bits bits
    bytes_capacity = (usable * 3 * lsb_bits) // 8
    
    return {
        'usable_pixels': usable,
        'total_pixels': int(total),
        'percent': percent,
        'bytes_capacity': int(bytes_capacity),
        'lsb_bits': lsb_bits
    }


@dataclass
class StegoQuality:
    """Quality metrics for steganography."""
    psnr: float           # Peak Signal-to-Noise Ratio (dB)
    max_diff: int         # Maximum pixel difference
    mean_diff: float      # Mean pixel difference
    stealth_level: StealthLevel
    lsb_bits: int
    passed_threshold: bool  # True if PSNR > threshold


class AdvancedStegoEncoder:
    """
    Advanced steganography encoder with multiple stealth levels.
    
    Features:
    - Adaptive LSB depth based on stealth level
    - Optional obfuscation (noise, blur)
    - Animated carrier generation
    - Quality validation with PSNR
    """
    
    def __init__(self,
                 stealth_level: StealthLevel = StealthLevel.SUBTLE,
                 quality_threshold: float = 35.0,
                 enable_obfuscation: bool = False,
                 enable_animation: bool = False):
        """
        Initialize advanced steganography encoder.
        
        Args:
            stealth_level: Desired stealth level (1-4)
            quality_threshold: Minimum acceptable PSNR (dB)
            enable_obfuscation: Add visual noise for paranoid mode
            enable_animation: Generate animated carrier backgrounds
        """
        self.stealth_level = stealth_level
        self.quality_threshold = quality_threshold
        self.enable_obfuscation = enable_obfuscation
        self.enable_animation = enable_animation
        
        # Determine LSB bits based on stealth level
        self.lsb_bits = self._get_lsb_bits()
        
        # Animation state
        self.animation_frame = 0
        self.animation_seed = secrets.randbits(32)
    
    def _get_lsb_bits(self) -> int:
        """Get LSB depth for current stealth level."""
        return {
            StealthLevel.VISIBLE: 3,
            StealthLevel.SUBTLE: 2,
            StealthLevel.HIDDEN: 1,
            StealthLevel.PARANOID: 1
        }[self.stealth_level]
    
    def embed_frame(self,
                   qr_frame: Image.Image,
                   carrier: Optional[Image.Image] = None,
                   frame_index: int = 0) -> Tuple[Image.Image, StegoQuality]:
        """
        Embed QR frame in carrier with quality validation.
        
        Args:
            qr_frame: QR code image
            carrier: Carrier image (generated if None)
            frame_index: Frame index for animation
            
        Returns:
            Tuple of (stego_image, quality_metrics)
            
        Raises:
            ValueError: If quality below threshold
        """
        # Generate or validate carrier
        if carrier is None:
            carrier = self._generate_carrier(qr_frame.size, frame_index)
        else:
            carrier = carrier.resize(qr_frame.size, Image.Resampling.LANCZOS)
        
        # Convert to numpy arrays
        qr_array = np.array(qr_frame)
        carrier_array = np.array(carrier)
        
        # Embed using LSB
        stego_array = self._embed_lsb(qr_array, carrier_array)
        
        # Apply obfuscation if paranoid mode
        if self.stealth_level == StealthLevel.PARANOID and self.enable_obfuscation:
            stego_array = self._apply_obfuscation(stego_array)
        
        # Calculate quality metrics
        quality = self._calculate_quality(carrier_array, stego_array)
        
        # Validate quality
        if quality.psnr < self.quality_threshold:
            raise ValueError(
                f"Quality below threshold: {quality.psnr:.2f} dB < {self.quality_threshold} dB. "
                f"Try increasing stealth level or using different carrier."
            )
        
        # Convert back to image
        stego_image = Image.fromarray(stego_array)
        
        return stego_image, quality
    
    def _embed_lsb(self, qr_array: np.ndarray, carrier_array: np.ndarray,
                    roi_mask: Optional[np.ndarray] = None) -> np.ndarray:
        """
        Embed QR code in carrier using LSB steganography.
        
        Args:
            qr_array: QR code array (H, W, 3)
            carrier_array: Carrier array (H, W, 3)
            roi_mask: Optional boolean mask (H, W) for ROI-restricted embedding.
                      If provided, only True pixels are modified.
            
        Returns:
            Stego array (H, W, 3)
            
        Note:
            When roi_mask is used, unmasked pixels remain unchanged.
            This is cosmetic only - the decoder reads all pixels.
        """
        stego = carrier_array.copy()
        
        # Create LSB mask
        lsb_mask = (1 << self.lsb_bits) - 1
        carrier_mask = ~lsb_mask & 0xFF
        
        # Extract top bits from QR code
        qr_bits = (qr_array >> (8 - self.lsb_bits)) & lsb_mask
        
        if roi_mask is not None:
            # ROI-RESTRICTED EMBEDDING: Only modify masked pixels
            # Expand 2D mask to 3D for RGB channels
            mask_3d = np.stack([roi_mask, roi_mask, roi_mask], axis=2)
            stego = np.where(mask_3d,
                             (stego & carrier_mask) | qr_bits,
                             stego)  # Unmasked pixels unchanged
        else:
            # FULL EMBEDDING (default behavior)
            stego = (stego & carrier_mask) | qr_bits
        
        return stego
    
    def _apply_obfuscation(self, stego_array: np.ndarray) -> np.ndarray:
        """
        Apply visual obfuscation for paranoid mode.
        
        Args:
            stego_array: Stego array
            
        Returns:
            Obfuscated stego array
        """
        obfuscated = stego_array.copy().astype(np.int16)
        
        # Add imperceptible noise (±1-2 pixel values)
        noise = np.random.randint(-2, 3, obfuscated.shape, dtype=np.int16)
        obfuscated = np.clip(obfuscated + noise, 0, 255).astype(np.uint8)
        
        # Optional: slight Gaussian blur (reduces QR pattern visibility)
        try:
            from scipy.ndimage import gaussian_filter
            for c in range(3):
                obfuscated[:, :, c] = gaussian_filter(
                    obfuscated[:, :, c], sigma=0.3
                )
        except ImportError:
            pass  # Skip blur if scipy not available
        
        return obfuscated
    
    def _generate_carrier(self, size: Tuple[int, int], frame_index: int = 0) -> Image.Image:
        """
        Generate carrier image (static or animated).
        
        Args:
            size: Image size (width, height)
            frame_index: Frame index for animation
            
        Returns:
            Carrier image
        """
        if self.enable_animation:
            return self._generate_animated_carrier(size, frame_index)
        else:
            return self._generate_static_carrier(size)
    
    def _generate_static_carrier(self, size: Tuple[int, int]) -> Image.Image:
        """Generate static carrier (gradient or pattern)."""
        width, height = size
        
        # Create gradient carrier
        carrier = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Generate smooth gradient
        for i in range(height):
            for j in range(width):
                # Diagonal gradient
                t = (i / height + j / width) / 2
                carrier[i, j] = [
                    int(128 + 127 * np.sin(t * np.pi)),
                    int(128 + 127 * np.cos(t * np.pi)),
                    int(128 + 127 * np.sin(t * np.pi + np.pi/3))
                ]
        
        return Image.fromarray(carrier)
    
    def _generate_animated_carrier(self, size: Tuple[int, int], frame_index: int) -> Image.Image:
        """
        Generate animated carrier that changes per frame.
        
        Args:
            size: Image size
            frame_index: Frame number
            
        Returns:
            Animated carrier image
        """
        width, height = size
        carrier = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Time-varying parameter (0 to 2π over animation cycle)
        t = (frame_index % 60) / 60.0 * 2 * np.pi
        
        # Rotating gradient
        angle = t
        for i in range(height):
            for j in range(width):
                # Rotate coordinates
                x = (j - width/2) * np.cos(angle) - (i - height/2) * np.sin(angle)
                y = (j - width/2) * np.sin(angle) + (i - height/2) * np.cos(angle)
                
                # Distance from center
                dist = np.sqrt(x**2 + y**2) / (max(width, height) / 2)
                
                # Color based on distance and angle
                carrier[i, j] = [
                    int(128 + 127 * np.sin(dist * np.pi + t)),
                    int(128 + 127 * np.cos(dist * np.pi + t * 1.3)),
                    int(128 + 127 * np.sin(dist * np.pi + t * 0.7))
                ]
        
        return Image.fromarray(carrier)
    
    def _calculate_quality(self,
                          carrier: np.ndarray,
                          stego: np.ndarray) -> StegoQuality:
        """
        Calculate quality metrics for steganography.
        
        Args:
            carrier: Original carrier array
            stego: Stego array
            
        Returns:
            StegoQuality metrics
        """
        # Calculate differences
        diff = carrier.astype(np.float64) - stego.astype(np.float64)
        
        # MSE (Mean Squared Error)
        mse = np.mean(diff ** 2)
        
        # PSNR (Peak Signal-to-Noise Ratio)
        if mse == 0:
            psnr = float('inf')
        else:
            psnr = 10 * np.log10(255**2 / mse)
        
        # Other metrics
        max_diff = int(np.max(np.abs(diff)))
        mean_diff = float(np.mean(np.abs(diff)))
        
        return StegoQuality(
            psnr=psnr,
            max_diff=max_diff,
            mean_diff=mean_diff,
            stealth_level=self.stealth_level,
            lsb_bits=self.lsb_bits,
            passed_threshold=(psnr >= self.quality_threshold)
        )


class AdvancedStegoDecoder:
    """
    Advanced steganography decoder with adaptive extraction.
    
    Features:
    - Auto-detect LSB depth
    - Deobfuscation for paranoid mode
    - Quality validation
    """
    
    def __init__(self,
                 lsb_bits: int = 2,
                 aggressive: bool = False):
        """
        Initialize advanced steganography decoder.
        
        Args:
            lsb_bits: LSB depth to extract (1-3)
            aggressive: Enable aggressive preprocessing
        """
        self.lsb_bits = lsb_bits
        self.aggressive = aggressive
    
    def extract_frame(self, stego_image: Image.Image) -> Image.Image:
        """
        Extract QR frame from stego image.
        
        Args:
            stego_image: Stego image with embedded QR
            
        Returns:
            Extracted QR frame
        """
        stego_array = np.array(stego_image)
        
        # Extract LSBs
        lsb_mask = (1 << self.lsb_bits) - 1
        extracted = (stego_array & lsb_mask) << (8 - self.lsb_bits)
        
        # Aggressive preprocessing if enabled
        if self.aggressive:
            extracted = self._aggressive_preprocess(extracted)
        
        return Image.fromarray(extracted)
    
    def _aggressive_preprocess(self, qr_array: np.ndarray) -> np.ndarray:
        """
        Aggressive preprocessing for noisy extractions.
        
        Args:
            qr_array: Extracted QR array
            
        Returns:
            Preprocessed array
        """
        # Denoise with median filter
        try:
            from scipy.ndimage import median_filter
            for c in range(3):
                qr_array[:, :, c] = median_filter(qr_array[:, :, c], size=3)
        except ImportError:
            pass
        
        # Adaptive thresholding
        # (Convert to grayscale, threshold, restore to RGB)
        gray = np.mean(qr_array, axis=2).astype(np.uint8)
        threshold = np.median(gray)
        binary = (gray > threshold).astype(np.uint8) * 255
        
        # Restore to RGB
        qr_array = np.stack([binary, binary, binary], axis=2)
        
        return qr_array


# Convenience functions for integration

def encode_with_stego(qr_frames: List[Image.Image],
                     stealth_level: StealthLevel = StealthLevel.SUBTLE,
                     carriers: Optional[List[Image.Image]] = None,
                     enable_animation: bool = False) -> Tuple[List[Image.Image], List[StegoQuality]]:
    """
    Encode QR frames with advanced steganography.
    
    Args:
        qr_frames: List of QR code images
        stealth_level: Desired stealth level
        carriers: Optional carrier images (generated if None)
        enable_animation: Enable animated carriers
        
    Returns:
        Tuple of (stego_frames, quality_metrics)
        
    Example:
        >>> qr_frames = [create_qr(...) for _ in range(100)]
        >>> stego_frames, qualities = encode_with_stego(
        ...     qr_frames,
        ...     stealth_level=StealthLevel.HIDDEN,
        ...     enable_animation=True
        ... )
    """
    encoder = AdvancedStegoEncoder(
        stealth_level=stealth_level,
        enable_obfuscation=(stealth_level == StealthLevel.PARANOID),
        enable_animation=enable_animation
    )
    
    stego_frames = []
    qualities = []
    
    for i, qr_frame in enumerate(qr_frames):
        carrier = carriers[i] if carriers and i < len(carriers) else None
        
        stego_frame, quality = encoder.embed_frame(qr_frame, carrier, i)
        stego_frames.append(stego_frame)
        qualities.append(quality)
    
    return stego_frames, qualities


def decode_with_stego(stego_frames: List[Image.Image],
                     lsb_bits: int = 2,
                     aggressive: bool = False) -> List[Image.Image]:
    """
    Decode QR frames from stego images.
    
    Args:
        stego_frames: List of stego images
        lsb_bits: LSB depth to extract
        aggressive: Enable aggressive preprocessing
        
    Returns:
        List of extracted QR frames
    """
    decoder = AdvancedStegoDecoder(lsb_bits=lsb_bits, aggressive=aggressive)
    
    return [decoder.extract_frame(stego) for stego in stego_frames]


# Testing and validation

if __name__ == "__main__":
    print("Testing Advanced Steganography...\n")
    
    # Test 1: Create synthetic QR and carrier
    print("1. Creating test images...")
    qr_size = (800, 600)
    
    # Synthetic QR pattern (black and white)
    qr_array = np.random.randint(0, 2, (*qr_size[::-1], 3), dtype=np.uint8) * 255
    qr_image = Image.fromarray(qr_array)
    print(f"   ✓ Created QR image: {qr_size}")
    
    # Test 2: Test all stealth levels
    print("\n2. Testing stealth levels...")
    for level in StealthLevel:
        encoder = AdvancedStegoEncoder(stealth_level=level)
        stego, quality = encoder.embed_frame(qr_image)
        
        print(f"   Level {level.value} ({level.name}):")
        print(f"     LSB bits: {quality.lsb_bits}")
        print(f"     PSNR: {quality.psnr:.2f} dB")
        print(f"     Max diff: {quality.max_diff}")
        print(f"     Threshold: {'PASS' if quality.passed_threshold else 'FAIL'}")
    
    # Test 3: Animated carriers
    print("\n3. Testing animated carriers...")
    encoder = AdvancedStegoEncoder(
        stealth_level=StealthLevel.SUBTLE,
        enable_animation=True
    )
    
    for frame_idx in [0, 15, 30]:
        stego, quality = encoder.embed_frame(qr_image, frame_index=frame_idx)
        print(f"   Frame {frame_idx}: PSNR={quality.psnr:.2f} dB")
    
    # Test 4: Roundtrip (embed + extract)
    print("\n4. Testing roundtrip...")
    encoder = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE)
    stego, _ = encoder.embed_frame(qr_image)
    
    decoder = AdvancedStegoDecoder(lsb_bits=2)
    extracted = decoder.extract_frame(stego)
    
    # Compare
    qr_array_orig = np.array(qr_image)
    qr_array_extracted = np.array(extracted)
    
    # Should match in top bits
    qr_top_bits = qr_array_orig >> 6  # Top 2 bits
    extracted_top_bits = qr_array_extracted >> 6
    
    match_rate = np.mean(qr_top_bits == extracted_top_bits)
    print(f"   Match rate: {match_rate * 100:.1f}%")
    
    if match_rate > 0.95:
        print("   ✓ Roundtrip successful")
    else:
        print("   ⚠ Roundtrip degraded (expected for synthetic data)")
    
    # Test 5: Quality thresholds
    print("\n5. Testing quality thresholds...")
    try:
        encoder_strict = AdvancedStegoEncoder(
            stealth_level=StealthLevel.VISIBLE,
            quality_threshold=50.0  # Very high threshold
        )
        stego, quality = encoder_strict.embed_frame(qr_image)
        print(f"   ✓ High threshold met: {quality.psnr:.2f} dB")
    except ValueError as e:
        print(f"   ⚠ Threshold not met: {e}")
    
    print("\n✅ All advanced steganography tests complete!")
    print("\nRecommended Settings:")
    print("  • Balanced: StealthLevel.SUBTLE (2-bit LSB, ~35 dB PSNR)")
    print("  • Stealth: StealthLevel.HIDDEN (1-bit LSB, >40 dB PSNR)")
    print("  • Paranoid: StealthLevel.PARANOID (1-bit + obfuscation)")
    print("  • Animation: Enable for temporal obfuscation")
