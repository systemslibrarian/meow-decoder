"""
GIF Handler Module for Meow Decoder
Creates and parses GIF animations containing QR code frames
"""

from PIL import Image
from typing import List, Optional, Tuple
from pathlib import Path
import io


class GIFEncoder:
    """
    GIF encoder for creating animated GIFs from QR code frames.
    """
    
    def __init__(self, fps: int = 2, loop: int = 0):
        """
        Initialize GIF encoder.
        
        Args:
            fps: Frames per second
            loop: Loop count (0 = infinite)
        """
        self.fps = fps
        self.loop = loop
        self.duration = int(1000 / fps)  # Duration in milliseconds
    
    def create_gif(self,
                   frames: List[Image.Image],
                   output_path: Path,
                   optimize: bool = False) -> int:
        """
        Create GIF from frames.
        
        Args:
            frames: List of PIL Images
            output_path: Output GIF path
            optimize: Optimize GIF size (default False for QR readability)
            
        Returns:
            File size in bytes
            
        Note:
            GIF optimization is disabled by default because it can corrupt
            QR code readability through palette quantization and compression.
        """
        if not frames:
            raise ValueError("No frames provided")
        
        # Ensure all frames are same size.
        # Note: We do NOT force bilevel conversion here because it can collapse
        # distinct frames (e.g., grayscale → 1-bit) and reduce frame count.
        # QR frames are already high-contrast; keeping RGB preserves fidelity.
        size = frames[0].size
        normalized_frames = []
        
        for frame in frames:
            if frame.size != size:
                frame = frame.resize(size, Image.Resampling.NEAREST)  # NEAREST for QR (no blur)
            
            # Convert to RGB for GIF.
            if frame.mode != "RGB":
                frame = frame.convert("RGB")
            
            normalized_frames.append(frame)
        
        # Save as GIF
        normalized_frames[0].save(
            output_path,
            save_all=True,
            append_images=normalized_frames[1:],
            duration=self.duration,
            loop=self.loop,
            optimize=optimize
        )
        
        return output_path.stat().st_size
    
    def create_gif_bytes(self,
                        frames: List[Image.Image],
                        optimize: bool = False) -> bytes:
        """
        Create GIF as bytes (in-memory).
        
        Args:
            frames: List of PIL Images
            optimize: Optimize GIF size
            
        Returns:
            GIF as bytes
        """
        if not frames:
            raise ValueError("No frames provided")
        
        # Normalize frames
        size = frames[0].size
        normalized_frames = []
        
        for frame in frames:
            if frame.size != size:
                frame = frame.resize(size, Image.Resampling.LANCZOS)
            
            if frame.mode != "RGB":
                frame = frame.convert("RGB")
            
            normalized_frames.append(frame)
        
        # Save to bytes
        output = io.BytesIO()
        normalized_frames[0].save(
            output,
            format='GIF',
            save_all=True,
            append_images=normalized_frames[1:],
            duration=self.duration,
            loop=self.loop,
            optimize=optimize
        )
        
        return output.getvalue()


class GIFDecoder:
    """
    GIF decoder for extracting frames from GIF animations.
    """
    
    def __init__(self):
        """Initialize GIF decoder."""
        pass
    
    def extract_frames(self, gif_path: Path) -> List[Image.Image]:
        """
        Extract all frames from GIF.
        
        Args:
            gif_path: Path to GIF file
            
        Returns:
            List of PIL Images
        """
        frames = []
        
        with Image.open(gif_path) as img:
            # GIF animations have multiple frames
            try:
                while True:
                    # Copy current frame
                    frame = img.copy().convert("RGB")
                    frames.append(frame)
                    
                    # Move to next frame
                    img.seek(img.tell() + 1)
            except EOFError:
                # End of frames
                pass
        
        return frames
    
    def extract_frames_bytes(self, gif_bytes: bytes) -> List[Image.Image]:
        """
        Extract frames from GIF bytes.
        
        Args:
            gif_bytes: GIF as bytes
            
        Returns:
            List of PIL Images
        """
        frames = []
        
        with Image.open(io.BytesIO(gif_bytes)) as img:
            try:
                while True:
                    frame = img.copy().convert("RGB")
                    frames.append(frame)
                    img.seek(img.tell() + 1)
            except EOFError:
                pass
        
        return frames
    
    def get_frame_count(self, gif_path: Path) -> int:
        """
        Get number of frames in GIF.
        
        Args:
            gif_path: Path to GIF file
            
        Returns:
            Frame count
        """
        with Image.open(gif_path) as img:
            return img.n_frames
    
    def get_frame(self, gif_path: Path, frame_index: int) -> Image.Image:
        """
        Get specific frame from GIF.
        
        Args:
            gif_path: Path to GIF file
            frame_index: Frame index (0-based)
            
        Returns:
            PIL Image of frame
        """
        with Image.open(gif_path) as img:
            if frame_index >= img.n_frames:
                raise IndexError(f"Frame {frame_index} out of range (0-{img.n_frames-1})")
            
            img.seek(frame_index)
            return img.copy().convert("RGB")


class GIFOptimizer:
    """
    Utilities for optimizing GIF size and quality.
    """
    
    @staticmethod
    def optimize_gif(input_path: Path,
                    output_path: Path,
                    colors: int = 256,
                    reduce_size: bool = True) -> Tuple[int, int]:
        """
        Optimize GIF file.
        
        Args:
            input_path: Input GIF path
            output_path: Output GIF path
            colors: Maximum colors (2-256)
            reduce_size: Reduce image dimensions
            
        Returns:
            Tuple of (original_size, optimized_size) in bytes
        """
        original_size = input_path.stat().st_size
        
        # Load GIF
        decoder = GIFDecoder()
        frames = decoder.extract_frames(input_path)
        
        # Reduce size if requested
        if reduce_size:
            new_size = (frames[0].size[0] // 2, frames[0].size[1] // 2)
            frames = [f.resize(new_size, Image.Resampling.LANCZOS) for f in frames]
        
        # Reduce colors
        frames = [
            f.convert('P', palette=Image.ADAPTIVE, colors=colors)
            for f in frames
        ]
        
        # Save optimized
        encoder = GIFEncoder()
        optimized_size = encoder.create_gif(frames, output_path, optimize=True)
        
        return original_size, optimized_size
    
    @staticmethod
    def get_gif_info(gif_path: Path) -> dict:
        """
        Get information about GIF file.
        
        Args:
            gif_path: Path to GIF file
            
        Returns:
            Dictionary with GIF info
        """
        with Image.open(gif_path) as img:
            info = {
                'size': img.size,
                'mode': img.mode,
                'format': img.format,
                'frames': img.n_frames,
                'file_size': gif_path.stat().st_size,
                'duration': img.info.get('duration', None),
                'loop': img.info.get('loop', None)
            }
        
        return info


# Testing
if __name__ == "__main__":
    import tempfile
    
    print("Testing GIF Handler Module...\n")
    
    # Test 1: Create test frames
    print("1. Creating test frames...")
    
    frames = []
    for i in range(10):
        # Create test frame (gradient)
        img = Image.new('RGB', (400, 300))
        pixels = img.load()
        
        for x in range(400):
            for y in range(300):
                # Animated gradient
                r = int((x / 400) * 255)
                g = int((y / 300) * 255)
                b = int(((i / 10) * 255))
                pixels[x, y] = (r, g, b)
        
        frames.append(img)
    
    print(f"   Created {len(frames)} frames ({frames[0].size})")
    
    # Test 2: Create GIF
    print("\n2. Testing GIF creation...")
    
    with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
        gif_path = Path(f.name)
    
    try:
        encoder = GIFEncoder(fps=10, loop=0)
        file_size = encoder.create_gif(frames, gif_path)
        
        print(f"   Created GIF: {file_size:,} bytes")
        print("   ✓ GIF creation works")
        
        # Test 3: Extract frames
        print("\n3. Testing frame extraction...")
        
        decoder = GIFDecoder()
        extracted = decoder.extract_frames(gif_path)
        
        print(f"   Extracted {len(extracted)} frames")
        
        if len(extracted) == len(frames):
            print("   ✓ Frame count matches")
        else:
            print(f"   ✗ Frame count mismatch (expected {len(frames)}, got {len(extracted)})")
        
        # Test 4: Get specific frame
        print("\n4. Testing specific frame extraction...")
        
        frame_5 = decoder.get_frame(gif_path, 5)
        print(f"   Frame 5: {frame_5.size}")
        print("   ✓ Specific frame extraction works")
        
        # Test 5: Get GIF info
        print("\n5. Testing GIF info...")
        
        info = GIFOptimizer.get_gif_info(gif_path)
        print(f"   Size: {info['size']}")
        print(f"   Frames: {info['frames']}")
        print(f"   File size: {info['file_size']:,} bytes")
        print(f"   Duration: {info['duration']}ms")
        print("   ✓ GIF info retrieval works")
        
        # Test 6: Optimize GIF
        print("\n6. Testing GIF optimization...")
        
        with tempfile.NamedTemporaryFile(suffix='_opt.gif', delete=False) as f:
            opt_path = Path(f.name)
        
        try:
            orig_size, opt_size = GIFOptimizer.optimize_gif(
                gif_path, opt_path, colors=128, reduce_size=False
            )
            
            reduction = (1 - opt_size / orig_size) * 100
            print(f"   Original: {orig_size:,} bytes")
            print(f"   Optimized: {opt_size:,} bytes")
            print(f"   Reduction: {reduction:.1f}%")
            print("   ✓ GIF optimization works")
        finally:
            opt_path.unlink()
        
        # Test 7: In-memory GIF
        print("\n7. Testing in-memory GIF...")
        
        gif_bytes = encoder.create_gif_bytes(frames)
        extracted_mem = decoder.extract_frames_bytes(gif_bytes)
        
        print(f"   GIF bytes: {len(gif_bytes):,}")
        print(f"   Extracted: {len(extracted_mem)} frames")
        print("   ✓ In-memory GIF works")
        
    finally:
        gif_path.unlink()
    
    print("\n✅ All GIF handler tests complete!")
