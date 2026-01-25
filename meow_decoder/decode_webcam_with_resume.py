"""
Meow Webcam Decoder with Resume Auto-Detection
Integrated secure resume capability for interrupted decodes
"""

import argparse
import re
import time
import hashlib
import sys
from getpass import getpass
from typing import NoReturn, Optional, Tuple
from collections import deque
from datetime import datetime

import cv2
import numpy as np
from tqdm import tqdm
from colorama import Fore, Style, init

from .crypto import (
    unpack_manifest, decrypt_to_raw, compute_manifest_hmac, 
    pack_manifest, verify_keyfile, Manifest
)
from .fountain import FountainEncoder, FountainDecoder
from .qrpack import b64d, b64e

# Import secured resume capability
try:
    from .resume_secured import ResumeManager, AutoSaveDecoder, create_resumable_decoder
    RESUME_AVAILABLE = True
except ImportError:
    # Fallback to basic resume if secured version not available
    try:
        from .resume import ResumeManager, AutoSaveDecoder, create_resumable_decoder
        RESUME_AVAILABLE = True
        print(f"{Fore.YELLOW}⚠️  Using basic resume (not encrypted). Install cryptography for secure resume.{Style.RESET_ALL}")
    except ImportError:
        RESUME_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

pat_m = re.compile(r"^MEOW\|M\|([A-Za-z0-9+/=]+)$")
pat_d = re.compile(r"^MEOW\|D\|(\d+)\|([A-Za-z0-9+/=]+)$")


def estimate_qr_version(payload: str) -> int:
    """Rough estimate of QR version needed (alphanumeric mode)."""
    bits = len(payload) * 5.5
    if bits < 134:   return 1
    if bits < 154:   return 2
    if bits < 202:   return 5
    if bits < 500:   return 10
    if bits < 1000:  return 15
    if bits < 2000:  return 25
    if bits < 3000:  return 35
    return 40


def format_size(bytes_size: int) -> str:
    """Format byte size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} TB"


def format_time_ago(timestamp_str: str) -> str:
    """Format timestamp as human-readable time ago."""
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
        now = datetime.now()
        delta = now - timestamp
        
        if delta.total_seconds() < 60:
            return f"{int(delta.total_seconds())} seconds ago"
        elif delta.total_seconds() < 3600:
            return f"{int(delta.total_seconds() / 60)} minutes ago"
        elif delta.total_seconds() < 86400:
            return f"{int(delta.total_seconds() / 3600)} hours ago"
        else:
            return f"{int(delta.total_seconds() / 86400)} days ago"
    except:
        return timestamp_str


def print_header():
    """Print colorful header."""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.YELLOW}🐱 Meow Webcam Decoder v2.1 🐱")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def check_for_existing_session(
    manifest: Manifest,
    password: str,
    resume_manager: ResumeManager
) -> Optional[Tuple[FountainDecoder, int]]:
    """
    Check if a resume session exists for this manifest and offer to resume.
    
    Args:
        manifest: File manifest
        password: User password (needed for encrypted state)
        resume_manager: ResumeManager instance
        
    Returns:
        Tuple of (decoder, droplets_seen) if resuming, None otherwise
    """
    try:
        session_id = resume_manager.generate_session_id(manifest)
        state = resume_manager.load_state_with_manifest(session_id, manifest, password)
        
        if state is None:
            return None
        
        # Calculate progress
        solved_count = sum(1 for _, block in state.solved_blocks if block is not None)
        progress = (solved_count / manifest.k_blocks * 100) if manifest.k_blocks > 0 else 0
        
        # Show resume prompt
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.YELLOW}📁 Existing Session Found!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        print(f"  Session ID: {session_id[:20]}...")
        print(f"  Last saved: {format_time_ago(state.timestamp)}")
        print(f"  Progress:   {progress:.1f}% ({solved_count}/{manifest.k_blocks} blocks)")
        print(f"  Droplets:   {state.droplets_seen}")
        print()
        
        response = input(f"{Fore.GREEN}Resume from saved session? [Y/n]: {Style.RESET_ALL}").strip().lower()
        
        if response in ('', 'y', 'yes'):
            print(f"{Fore.GREEN}✓ Resuming from saved session...{Style.RESET_ALL}\n")
            
            # Restore decoder
            decoder, _, droplets_seen = resume_manager.restore_decoder(state)
            return decoder, droplets_seen
        else:
            print(f"{Fore.YELLOW}Starting fresh decode (old session kept for later)...{Style.RESET_ALL}\n")
            return None
            
    except Exception as e:
        # If resume fails (wrong password, corrupted state, etc.), just continue with fresh decode
        if "wrong password" in str(e).lower() or "invalid" in str(e).lower():
            print(f"\n{Fore.YELLOW}⚠️  Saved session exists but password doesn't match.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   Starting fresh decode...{Style.RESET_ALL}\n")
        return None


def detect_glare(frame: np.ndarray, threshold: float = 0.85) -> bool:
    """Detect if frame has excessive glare."""
    if len(frame.shape) == 3:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    else:
        gray = frame
    
    bright_pixels = np.sum(gray > 240)
    total_pixels = gray.size
    bright_ratio = bright_pixels / total_pixels
    
    return bright_ratio > threshold


def calculate_blur_score(frame: np.ndarray) -> float:
    """Calculate blur score using Laplacian variance."""
    if len(frame.shape) == 3:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    else:
        gray = frame
    
    return cv2.Laplacian(gray, cv2.CV_64F).var()


def _variants(frame_bgr: np.ndarray, include_aggressive: bool = False):
    """Generate processing variants to improve QR detection robustness."""
    yield frame_bgr
    
    gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
    yield gray
    
    h, w = gray.shape[:2]
    up = cv2.resize(gray, (int(w * 1.7), int(h * 1.7)), interpolation=cv2.INTER_CUBIC)
    yield up
    
    ad = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                               cv2.THRESH_BINARY, 31, 3)
    yield ad
    
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield otsu
    
    blur = cv2.GaussianBlur(gray, (3, 3), 0)
    _, thr = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield thr
    
    if include_aggressive:
        kernel = np.ones((3, 3), np.uint8)
        morph = cv2.morphologyEx(otsu, cv2.MORPH_CLOSE, kernel)
        yield morph
        
        eq = cv2.equalizeHist(gray)
        yield eq
        
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        cl = clahe.apply(gray)
        yield cl


class WebcamDecoder:
    """Enhanced webcam decoder with statistics and quality tracking."""
    
    def __init__(self, camera_index: int = 0):
        self.camera_index = camera_index
        self.cap = None
        self.detector = cv2.QRCodeDetector()
        
        # Statistics
        self.frames_processed = 0
        self.frames_with_qr = 0
        self.droplets_seen = 0
        self.manifest = None
        self.decoder = None
        self.encoder_tmp = None
        self.seen_seeds = set()
        
        # Quality tracking
        self.recent_detections = deque(maxlen=30)
        self.blur_scores = deque(maxlen=10)
        self.glare_warnings = 0
    
    def open_camera(self) -> None:
        """Open camera with optimal settings."""
        self.cap = cv2.VideoCapture(self.camera_index, cv2.CAP_DSHOW)
        if not self.cap.isOpened():
            raise RuntimeError(f"Could not open webcam (index {self.camera_index})")
        
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        self.cap.set(cv2.CAP_PROP_FPS, 30)
        self.cap.set(cv2.CAP_PROP_AUTOFOCUS, 0)
    
    def close_camera(self) -> None:
        """Clean up camera resources."""
        if self.cap:
            self.cap.release()
        cv2.destroyAllWindows()
    
    def get_detection_rate(self) -> float:
        """Get recent QR detection success rate."""
        if not self.recent_detections:
            return 0.0
        return sum(self.recent_detections) / len(self.recent_detections)
    
    def get_average_blur(self) -> float:
        """Get average blur score."""
        if not self.blur_scores:
            return 0.0
        return sum(self.blur_scores) / len(self.blur_scores)
    
    def process_frame(self, frame: np.ndarray, aggressive: bool = False) -> Optional[str]:
        """Process a frame and try to detect QR code."""
        self.frames_processed += 1
        
        if detect_glare(frame):
            self.glare_warnings += 1
        
        blur = calculate_blur_score(frame)
        self.blur_scores.append(blur)
        
        for variant in _variants(frame, include_aggressive=aggressive):
            text, _, _ = self.detector.detectAndDecode(variant)
            if text:
                self.frames_with_qr += 1
                self.recent_detections.append(1)
                return text
        
        self.recent_detections.append(0)
        return None
    
    def get_stats(self) -> dict:
        """Get decoder statistics."""
        solved = sum(1 for b in self.decoder.solved if b is not None) if self.decoder else 0
        total = self.manifest.k_blocks if self.manifest else 0
        
        return {
            'frames_processed': self.frames_processed,
            'frames_with_qr': self.frames_with_qr,
            'detection_rate': self.get_detection_rate(),
            'average_blur': self.get_average_blur(),
            'glare_warnings': self.glare_warnings,
            'droplets_seen': self.droplets_seen,
            'solved_blocks': solved,
            'total_blocks': total,
            'progress_percent': (solved / total * 100) if total > 0 else 0
        }


def main() -> NoReturn:
    """Main webcam decoder entry point with resume auto-detection."""
    parser = argparse.ArgumentParser(
        description="Meow Webcam Decoder 😼 v2.1 - With Resume Auto-Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic webcam decoding (auto-resumes if session exists)
  meow-decode-webcam --output secret.pdf
  
  # Disable resume capability
  meow-decode-webcam --no-resume --output file.pdf
  
  # With keyfile
  meow-decode-webcam --output data.zip --keyfile my.key
  
  # Aggressive mode for difficult QR codes
  meow-decode-webcam --aggressive --output file.pdf

Resume Feature:
  • Automatically detects existing sessions
  • Prompts to resume interrupted decodes
  • Saves progress every 50 droplets
  • Encrypted state files (secure)
        """
    )
    
    parser.add_argument("--output", default="cat_rebuilt.png", 
                       help="Path to save the reconstructed file")
    parser.add_argument("--camera-index", type=int, default=0, 
                       help="Webcam device index (default: 0)")
    parser.add_argument("--seed", type=int, default=42069, 
                       help="Master seed (must match encoder)")
    parser.add_argument("--metadata", action="store_true",
                       help="Only read and verify manifest (no reconstruction)")
    parser.add_argument("--keyfile", type=str, default=None,
                       help="Path to keyfile (must match encoder)")
    parser.add_argument("--aggressive", action="store_true",
                       help="Use aggressive preprocessing (slower but more robust)")
    parser.add_argument("--skip-frames", type=int, default=1,
                       help="Process every Nth frame (higher = faster, lower detection)")
    parser.add_argument("--resume", action="store_true", default=True,
                       help="Enable resume capability (default: on)")
    parser.add_argument("--no-resume", dest="resume", action="store_false",
                       help="Disable resume capability")
    parser.add_argument("--auto-save-interval", type=int, default=50,
                       help="Auto-save every N droplets (default: 50)")
    parser.add_argument("--quiet", action="store_true",
                       help="Suppress verbose output")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_header()
        
        if not RESUME_AVAILABLE:
            print(f"{Fore.YELLOW}⚠️  Resume capability not available (resume.py not found){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   Progress will not be saved automatically.{Style.RESET_ALL}\n")
            args.resume = False
    
    # Get password
    password = getpass(f"{Fore.GREEN}🔐 Password to DECRYPT: {Style.RESET_ALL}").strip()
    if not password:
        print(f"{Fore.RED}✗ No password → no meow. Try again. 😿{Style.RESET_ALL}")
        sys.exit(1)
    
    # Load keyfile if specified
    keyfile = None
    if args.keyfile:
        try:
            keyfile = verify_keyfile(args.keyfile)
            if not args.quiet:
                print(f"{Fore.GREEN}✓ Keyfile loaded: {args.keyfile} ({len(keyfile)} bytes){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Keyfile error: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Initialize resume manager if enabled
    resume_manager = None
    if args.resume and RESUME_AVAILABLE:
        try:
            resume_manager = ResumeManager()
            if not args.quiet:
                print(f"{Fore.GREEN}✓ Resume capability enabled (auto-save every {args.auto_save_interval} droplets){Style.RESET_ALL}")
        except Exception as e:
            if not args.quiet:
                print(f"{Fore.YELLOW}⚠️  Resume capability initialization failed: {e}{Style.RESET_ALL}")
            resume_manager = None
    
    # Initialize decoder
    decoder = WebcamDecoder(camera_index=args.camera_index)
    
    try:
        decoder.open_camera()
    except Exception as e:
        print(f"{Fore.RED}✗ Failed to open webcam: {e}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Troubleshooting:{Style.RESET_ALL}")
        print("  • Check webcam is connected")
        print("  • Try different --camera-index (0, 1, 2...)")
        print("  • Close other apps using the webcam")
        sys.exit(1)
    
    if not args.quiet:
        print(f"\n{Fore.CYAN}📹 Webcam Mode Active{Style.RESET_ALL}")
        print(f"   Camera index: {args.camera_index}")
        print(f"   Seed: {args.seed}")
        if args.metadata:
            print(f"   {Fore.YELLOW}Mode: METADATA ONLY{Style.RESET_ALL}")
        if args.aggressive:
            print(f"   {Fore.YELLOW}Aggressive preprocessing: ON{Style.RESET_ALL}")
        print()
        print(f"{Fore.YELLOW}📱 Tips:{Style.RESET_ALL}")
        print("   • Fullscreen GIF on phone, max brightness")
        print("   • Fill camera view, steady hold")
        print(f"\n{Fore.CYAN}⌨️  Controls:{Style.RESET_ALL}")
        print("   • 'q' - Quit")
        print("   • 'a' - Toggle aggressive mode")
        print("   • 's' - Show statistics")
        print()
    
    start = time.time()
    aggressive_mode = args.aggressive
    frame_counter = 0
    last_stats_print = time.time()
    
    # Track if we've checked for resume yet
    resume_checked = False
    resumed_from_session = False
    
    try:
        while True:
            ret, frame = decoder.cap.read()
            if not ret:
                time.sleep(0.05)
                continue
            
            frame_counter += 1
            
            if frame_counter % args.skip_frames != 0:
                cv2.imshow("Meow Decoder 😼", frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
                continue
            
            text = decoder.process_frame(frame, aggressive=aggressive_mode)
            
            if text:
                # Check for manifest
                mm = pat_m.match(text)
                if mm and decoder.manifest is None:
                    try:
                        manifest_bytes = b64d(mm.group(1))
                        decoder.manifest = unpack_manifest(manifest_bytes)
                        packed_no_hmac = pack_manifest(decoder.manifest)[:-32]
                        expected_hmac = compute_manifest_hmac(
                            password, decoder.manifest.salt, packed_no_hmac, keyfile
                        )
                        
                        if decoder.manifest.hmac != expected_hmac:
                            decoder.close_camera()
                            print(f"\n{Fore.RED}✗ Manifest HMAC check failed → wrong password or keyfile? 😿{Style.RESET_ALL}")
                            sys.exit(1)
                        
                        if args.metadata:
                            decoder.close_camera()
                            print(f"\n{Fore.GREEN}{'='*70}")
                            print("✅ METADATA MODE – Manifest verified (HMAC passed)")
                            print(f"{'='*70}{Style.RESET_ALL}")
                            print(f"{Fore.CYAN}Original length:{Style.RESET_ALL}   {format_size(decoder.manifest.orig_len)}")
                            print(f"{Fore.CYAN}Blocks (k):{Style.RESET_ALL}        {decoder.manifest.k_blocks}")
                            sys.exit(0)
                        
                        # Check for existing session (only if resume enabled and not checked yet)
                        if resume_manager and not resume_checked:
                            resume_checked = True
                            resume_result = check_for_existing_session(
                                decoder.manifest, password, resume_manager
                            )
                            
                            if resume_result:
                                # Resume from saved session
                                decoder.decoder, decoder.droplets_seen = resume_result
                                decoder.encoder_tmp = FountainEncoder(
                                    b"\x00" * decoder.manifest.cipher_len,
                                    block_size=decoder.manifest.block_size,
                                    seed=args.seed
                                )
                                resumed_from_session = True
                                
                                # Rebuild seen_seeds from resumed decoder
                                # (This is a simplification - in practice you'd save/restore this too)
                                decoder.seen_seeds = set()
                            else:
                                # Start fresh with auto-save
                                if resume_manager:
                                    decoder.decoder = create_resumable_decoder(
                                        decoder.manifest,
                                        auto_save_interval=args.auto_save_interval,
                                        input_source="webcam",
                                        seed=args.seed,
                                        resume_manager=resume_manager
                                    ).decoder
                                else:
                                    decoder.decoder = FountainDecoder(
                                        k=decoder.manifest.k_blocks,
                                        block_size=decoder.manifest.block_size
                                    )
                                
                                decoder.encoder_tmp = FountainEncoder(
                                    b"\x00" * decoder.manifest.cipher_len,
                                    block_size=decoder.manifest.block_size,
                                    seed=args.seed
                                )
                        else:
                            # Resume disabled or already checked - create normal decoder
                            decoder.decoder = FountainDecoder(
                                k=decoder.manifest.k_blocks,
                                block_size=decoder.manifest.block_size
                            )
                            decoder.encoder_tmp = FountainEncoder(
                                b"\x00" * decoder.manifest.cipher_len,
                                block_size=decoder.manifest.block_size,
                                seed=args.seed
                            )
                        
                        if not args.quiet:
                            print(f"\n{Fore.GREEN}✓ Manifest acquired!{Style.RESET_ALL}")
                            print(f"  K={decoder.manifest.k_blocks}, block_size={decoder.manifest.block_size} bytes")
                            if resumed_from_session:
                                solved = sum(1 for b in decoder.decoder.solved if b is not None)
                                print(f"  {Fore.CYAN}Resumed from saved session: {solved}/{decoder.manifest.k_blocks} blocks already solved{Style.RESET_ALL}")
                        
                    except Exception as e:
                        if not args.quiet:
                            print(f"\n{Fore.RED}✗ Manifest parse error: {e}{Style.RESET_ALL}")
                        continue
                
                # Check for droplet
                md = pat_d.match(text)
                if md and decoder.manifest and decoder.decoder and decoder.encoder_tmp:
                    try:
                        droplet_seed = int(md.group(1))
                        if droplet_seed not in decoder.seen_seeds:
                            decoder.seen_seeds.add(droplet_seed)
                            payload = b64d(md.group(2))
                            droplet = decoder.encoder_tmp.make_droplet(droplet_seed)
                            decoder.decoder.add_equation(droplet.idxs, payload)
                            decoder.droplets_seen += 1
                    except Exception as e:
                        if not args.quiet:
                            print(f"{Fore.YELLOW}⚠️  Droplet error (skipping): {e}{Style.RESET_ALL}")
                        continue
            
            # Update display
            now = time.time()
            
            if not args.quiet and now - last_stats_print > 1.0:
                last_stats_print = now
                stats = decoder.get_stats()
                
                if decoder.manifest and decoder.decoder:
                    print(f"\r{Fore.CYAN}Droplets: {stats['droplets_seen']}{Style.RESET_ALL} | "
                          f"{Fore.GREEN}Solved: {stats['solved_blocks']}/{stats['total_blocks']}{Style.RESET_ALL} "
                          f"({stats['progress_percent']:.1f}%) | "
                          f"Detect: {stats['detection_rate']*100:.0f}% | "
                          f"Blur: {stats['average_blur']:.0f}   ",
                          end="")
                else:
                    print(f"\r{Fore.YELLOW}Scanning for manifest...{Style.RESET_ALL} "
                          f"Frames: {stats['frames_processed']}   ",
                          end="")
            
            # On-screen overlay
            overlay_color = (50, 255, 50)
            cv2.putText(frame, "Meow Decoder v2.1 - q=quit, a=aggressive, s=stats",
                       (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, overlay_color, 2)
            
            if decoder.manifest and decoder.decoder:
                stats = decoder.get_stats()
                status = f"Solved: {stats['solved_blocks']}/{stats['total_blocks']} ({stats['progress_percent']:.0f}%)"
                cv2.putText(frame, status, (10, 65),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.8, overlay_color, 2)
            
            cv2.imshow("Meow Decoder 😼", frame)
            
            # Handle keypresses
            key = cv2.waitKey(1) & 0xFF
            if key == ord('q'):
                print(f"\n\n{Fore.YELLOW}Quit by user.{Style.RESET_ALL}")
                break
            elif key == ord('a'):
                aggressive_mode = not aggressive_mode
                mode_str = "ON" if aggressive_mode else "OFF"
                print(f"\n{Fore.CYAN}Aggressive preprocessing: {mode_str}{Style.RESET_ALL}")
            elif key == ord('s'):
                stats = decoder.get_stats()
                print(f"\n{Fore.CYAN}{'='*50}")
                print("Current Statistics:")
                print(f"{'='*50}{Style.RESET_ALL}")
                print(f"Frames processed:  {stats['frames_processed']}")
                print(f"Detection rate:    {stats['detection_rate']*100:.1f}%")
                print(f"Droplets seen:     {stats['droplets_seen']}")
                print(f"Progress:          {stats['progress_percent']:.1f}%")
                print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
            
            # Check if done
            if decoder.manifest and decoder.decoder and decoder.decoder.is_done():
                print(f"\n\n{Fore.GREEN}✓ Enough droplets collected!{Style.RESET_ALL}")
                break
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Interrupted by user{Style.RESET_ALL}")
        decoder.close_camera()
        sys.exit(130)
    
    finally:
        decoder.close_camera()
    
    # Validation
    if decoder.manifest is None or decoder.decoder is None or not decoder.decoder.is_done():
        print(f"\n{Fore.RED}✗ Not enough data captured.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Reconstruct and decrypt
    if not args.quiet:
        print(f"\n{Fore.CYAN}🔄 Reconstructing and decrypting...{Style.RESET_ALL}")
    
    try:
        cipher = decoder.decoder.reconstruct(orig_len=decoder.manifest.cipher_len)
        raw = decrypt_to_raw(cipher, password, decoder.manifest.salt, 
                            decoder.manifest.nonce, keyfile)
        
        # Verify integrity
        if hashlib.sha256(raw).digest() != decoder.manifest.sha256:
            print(f"{Fore.RED}✗ SHA-256 integrity check failed{Style.RESET_ALL}")
            sys.exit(1)
        
        # Save output
        with open(args.output, "wb") as f:
            f.write(raw)
        
        # Success summary
        elapsed = time.time() - start
        stats = decoder.get_stats()
        
        print(f"\n{Fore.GREEN}{'='*70}")
        print("✅ Decoded successfully!")
        print(f"{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Output file:{Style.RESET_ALL}       {args.output}")
        print(f"{Fore.CYAN}Rebuilt size:{Style.RESET_ALL}      {format_size(len(raw))}")
        print(f"{Fore.CYAN}Droplets used:{Style.RESET_ALL}     {stats['droplets_seen']}")
        print(f"{Fore.CYAN}Time taken:{Style.RESET_ALL}        {elapsed:.1f} seconds")
        if resumed_from_session:
            print(f"{Fore.CYAN}Resumed:{Style.RESET_ALL}            Yes (saved significant time!)")
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Your cat data is safe and sound! 😸{Style.RESET_ALL}\n")
        
        # Clean up resume session if successful
        if resume_manager and not args.metadata:
            try:
                session_id = resume_manager.generate_session_id(decoder.manifest)
                resume_manager.delete_session(session_id)
            except:
                pass  # Silently ignore cleanup errors
        
    except Exception as e:
        print(f"{Fore.RED}✗ Reconstruction/decryption failed: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}✗ Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
