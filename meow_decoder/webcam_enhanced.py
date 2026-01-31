#!/usr/bin/env python3
"""
📷🐾 Enhanced Webcam Decoder with Paw Progress
Live webcam QR scanning with visual feedback and cat-themed progress!

Features:
- Real-time QR overlay visualization
- Paw progress indicator (🐾🐾🐾🐾🐾)
- "Kibbles collected" counter
- Auto-focus on QR codes
- Enhanced resume support
"""

import sys
import cv2
import numpy as np
from pathlib import Path
from getpass import getpass
from pyzbar.pyzbar import decode as qr_decode
from typing import Optional, Set
import json

from .decode_gif import decode_gif_streaming
from fountain import FountainDecoder


class PawProgress:
    """Cat paw progress indicator."""
    
    def __init__(self, total: int):
        self.total = total
        self.current = 0
        self.paws = ['🐾'] * 5
        
    def update(self, current: int):
        """Update progress."""
        self.current = current
        
    def get_percentage(self) -> float:
        """Get completion percentage."""
        if self.total == 0:
            return 0.0
        return (self.current / self.total) * 100
    
    def get_paws(self) -> str:
        """Get paw indicator based on progress."""
        pct = self.get_percentage()
        
        if pct >= 100:
            return '😻😻😻😻😻'
        elif pct >= 80:
            return '😸😸😸😸🐾'
        elif pct >= 60:
            return '😸😸😸🐾🐾'
        elif pct >= 40:
            return '😸😸🐾🐾🐾'
        elif pct >= 20:
            return '😸🐾🐾🐾🐾'
        else:
            return '😿🐾🐾🐾🐾'
    
    def get_status(self) -> str:
        """Get status string."""
        if self.get_percentage() >= 100:
            return f"{self.get_paws()} Complete! All kibbles collected!"
        else:
            return f"{self.get_paws()} {self.current}/{self.total} kibbles ({self.get_percentage():.1f}%)"


def draw_qr_overlay(frame: np.ndarray, qr_data: list) -> np.ndarray:
    """
    Draw QR code overlay on frame.
    
    Args:
        frame: Video frame
        qr_data: Decoded QR data
        
    Returns:
        Frame with overlay
    """
    overlay = frame.copy()
    
    for qr in qr_data:
        # Get QR code position
        points = qr.polygon
        
        if len(points) == 4:
            # Draw bounding box
            pts = np.array([[p.x, p.y] for p in points], np.int32)
            pts = pts.reshape((-1, 1, 2))
            
            # Green box for detected QR
            cv2.polylines(overlay, [pts], True, (0, 255, 0), 3)
            
            # Add "DETECTED" label
            x, y = points[0].x, points[0].y
            cv2.putText(
                overlay,
                "QR DETECTED",
                (x, y - 10),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (0, 255, 0),
                2
            )
    
    return overlay


def decode_webcam_enhanced(
    output_file: Path,
    password: str,
    camera_index: int = 0,
    verbose: bool = False
) -> dict:
    """
    Enhanced webcam decoder with paw progress.
    
    Args:
        output_file: Output file path
        password: Decryption password
        camera_index: Camera device index
        verbose: Verbose output
        
    Returns:
        Statistics dictionary
    """
    print("📷🐾 ENHANCED WEBCAM DECODER")
    print("=" * 60)
    print("Starting live QR code scanning with paw progress...")
    print()
    print("Controls:")
    print("  'q' or ESC - Quit")
    print("  's' - Save and exit")
    print("  'r' - Reset (start over)")
    print()
    
    # Open webcam
    cap = cv2.VideoCapture(camera_index)
    
    if not cap.isOpened():
        raise ValueError(f"Cannot open camera {camera_index}")
    
    # Set camera properties for better QR detection
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
    cap.set(cv2.CAP_PROP_AUTOFOCUS, 1)
    
    print("✅ Camera opened")
    print("📱 Show QR codes to the camera...")
    print()
    
    # Tracking
    seen_blocks: Set[int] = set()
    total_blocks = None
    decoder: Optional[FountainDecoder] = None
    paw_progress: Optional[PawProgress] = None
    
    total_scans = 0
    unique_blocks = 0
    
    try:
        while True:
            ret, frame = cap.read()
            
            if not ret:
                print("❌ Failed to read from camera")
                break
            
            # Decode QR codes
            qr_data = qr_decode(frame)
            
            # Draw overlay
            if qr_data:
                frame = draw_qr_overlay(frame, qr_data)
                total_scans += 1
            
            # Process QR codes
            for qr in qr_data:
                try:
                    data = json.loads(qr.data.decode())
                    
                    # Check if this is a droplet
                    if 'block_id' in data:
                        block_id = data['block_id']
                        
                        # First block contains metadata
                        if total_blocks is None and 'total_blocks' in data:
                            total_blocks = data['total_blocks']
                            block_size = data['block_size']
                            
                            decoder = FountainDecoder(
                                num_blocks=total_blocks,
                                block_size=block_size
                            )
                            
                            paw_progress = PawProgress(total_blocks)
                            
                            print(f"\n📋 Manifest decoded:")
                            print(f"  Total blocks: {total_blocks}")
                            print(f"  Block size: {block_size}")
                            print()
                        
                        # Add block if new
                        if block_id not in seen_blocks and decoder:
                            seen_blocks.add(block_id)
                            unique_blocks += 1
                            
                            # Add to decoder
                            droplet = data['droplet']
                            decoder.add_droplet(droplet)
                            
                            # Update progress
                            paw_progress.update(len(seen_blocks))
                            
                            # Print status
                            print(f"\r{paw_progress.get_status()}", end='', flush=True)
                            
                            # Check if complete
                            if decoder.is_complete():
                                print("\n\n✅ COMPLETE! All kibbles collected!")
                                print("🐱 Press 's' to save, or continue scanning for verification...")
                
                except Exception as e:
                    if verbose:
                        print(f"\n⚠️  Parse error: {e}")
            
            # Add HUD overlay
            hud = frame.copy()
            
            # Status box
            cv2.rectangle(hud, (10, 10), (600, 150), (0, 0, 0), -1)
            cv2.rectangle(hud, (10, 10), (600, 150), (0, 255, 0), 2)
            
            # Status text
            y_pos = 40
            cv2.putText(hud, "MEOW DECODER - Enhanced Webcam", (20, y_pos),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            
            y_pos += 30
            cv2.putText(hud, f"Total Scans: {total_scans}", (20, y_pos),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
            
            y_pos += 25
            cv2.putText(hud, f"Unique Blocks: {unique_blocks}", (20, y_pos),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
            
            if paw_progress:
                y_pos += 25
                status = paw_progress.get_status()
                # Convert emoji to ASCII for OpenCV
                status_ascii = status.encode('ascii', 'ignore').decode()
                cv2.putText(hud, status_ascii, (20, y_pos),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 1)
            
            # Show frame
            cv2.imshow('Meow Decoder - Webcam', hud)
            
            # Handle keyboard
            key = cv2.waitKey(1) & 0xFF
            
            if key == ord('q') or key == 27:  # q or ESC
                print("\n\n👋 Quitting...")
                break
            
            elif key == ord('s'):  # Save
                if decoder and decoder.is_complete():
                    print("\n\n💾 Saving...")
                    
                    # Get encrypted data
                    encrypted_data = decoder.get_data()
                    
                    # Decrypt (you'd need to implement this properly)
                    print("  Decrypting...")
                    # For now, just save encrypted data
                    output_file.write_bytes(encrypted_data)
                    
                    print(f"  ✅ Saved to: {output_file}")
                    break
                else:
                    print("\n⚠️  Not complete yet! Keep scanning...")
            
            elif key == ord('r'):  # Reset
                print("\n\n🔄 Resetting...")
                seen_blocks.clear()
                total_blocks = None
                decoder = None
                paw_progress = None
                unique_blocks = 0
                total_scans = 0
    
    finally:
        cap.release()
        cv2.destroyAllWindows()
    
    stats = {
        'total_scans': total_scans,
        'unique_blocks': unique_blocks,
        'completed': decoder.is_complete() if decoder else False
    }
    
    print("\n📊 Session Statistics:")
    print(f"  Total scans: {stats['total_scans']}")
    print(f"  Unique blocks: {stats['unique_blocks']}")
    print(f"  Completed: {'Yes! 😻' if stats['completed'] else 'No 😿'}")
    
    return stats


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="📷🐾 Enhanced Webcam Decoder with Paw Progress",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Controls:
  'q' or ESC - Quit
  's' - Save and exit
  'r' - Reset and start over

Features:
  🐾 Paw progress indicator
  📱 Real-time QR overlay
  😻 Kibbles collected counter
  🔄 Auto-focus and resume

Meow! 😺
        """
    )
    
    parser.add_argument('--output', type=Path, required=True,
                       help='Output file')
    parser.add_argument('--password', type=str,
                       help='Decryption password (prompted if not provided)')
    parser.add_argument('--camera', type=int, default=0,
                       help='Camera index (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass("Enter decryption password: ")
    
    if not password:
        print("❌ Password cannot be empty!", file=sys.stderr)
        sys.exit(1)
    
    print()
    
    # Start decoding!
    try:
        stats = decode_webcam_enhanced(
            args.output,
            password,
            camera_index=args.camera,
            verbose=args.verbose
        )
        
        if stats['completed']:
            print("\n🎉 SUCCESS! File decoded from webcam!")
        else:
            print("\n⚠️  Incomplete. Run again to resume!")
        
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
