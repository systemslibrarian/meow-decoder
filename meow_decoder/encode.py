#!/usr/bin/env python3
"""
Meow Decoder - Main Encoder CLI
Encodes files into GIF animations with QR codes
"""

import sys
import argparse
import struct
from pathlib import Path
from getpass import getpass
from typing import Optional
import time

# Import core modules
from .config import MeowConfig, EncodingConfig
from .crypto import (
    encrypt_file_bytes, compute_manifest_hmac, pack_manifest,
    Manifest, verify_keyfile, compute_duress_hash
)
from .fountain import FountainEncoder, pack_droplet
from .qr_code import QRCodeGenerator
from .gif_handler import GIFEncoder
from .progress import ProgressBar


from typing import List

def encode_file(
    input_path: Path,
    output_path: Path,
    password: str,
    config: Optional[EncodingConfig] = None,
    keyfile: Optional[bytes] = None,
    forward_secrecy: bool = True,
    receiver_public_key: Optional[bytes] = None,
    yubikey: bool = False,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    use_pq: bool = False,
    stego_level: int = 0,
    carrier_images: Optional[List[Path]] = None,
    stego_green: bool = False,
    logo_eyes: bool = False,
    logo_eyes_hidden: bool = False,
    brand_text: Optional[str] = None,
    duress_password: Optional[str] = None,
    verbose: bool = False
) -> dict:
    """
    Encode file into GIF.
    
    Args:
        input_path: Path to input file
        output_path: Path to output GIF
        password: Encryption password
        config: Encoding configuration
        keyfile: Optional keyfile content
        forward_secrecy: Enable forward secrecy (MEOW3, default True)
        receiver_public_key: Optional X25519 public key for forward secrecy (32 bytes)
        use_pq: Enable post-quantum hybrid mode (MEOW4)
        stego_level: Steganography level (0=off, 1-4=stealth levels)
        carrier_images: Optional list of carrier image paths (your cat photos!)
        stego_green: Restrict embedding to green-dominant pixels only (cosmetic)
        logo_eyes: Use logo-eyes carrier (branded animation with data in eyes)
        logo_eyes_hidden: Hide QR codes in logo eyes using LSB steganography (default: visible)
        brand_text: Custom brand text for logo-eyes mode (default: 'MEOW')
        duress_password: Optional duress password (triggers emergency response on decode)
        verbose: Print verbose output
        
    Returns:
        Dictionary with encoding statistics
    """
    if config is None:
        config = EncodingConfig()
    
    # Duress mode requires forward secrecy (to avoid manifest size ambiguity)
    if duress_password:
        if not forward_secrecy:
            raise ValueError("Duress mode requires forward secrecy (do not use --no-forward-secrecy with --duress-password)")
        
        # Ambiguity check: Password-Only + Duress (147 bytes) vs Forward Secrecy (147 bytes)
        # If we don't use PQ and don't use keys, we default to Password-Only mode (even if FS flag is on).
        # This creates a 147-byte manifest which unpack_manifest misinterprets as FS mode.
        if not use_pq and receiver_public_key is None:
             raise ValueError(
                 "Duress mode requires a distinct manifest format. "
                 "Please either:\n"
                 "  1. Provide a receiver public key for Forward Secrecy (--receiver-pubkey)\n"
                 "  2. Enable Post-Quantum mode (--pq)\n"
                 "Standard password-only mode creates a manifest size collision with Duress mode."
             )
    
    # Select crypto mode based on flags
    if use_pq:
        manifest_version = 4  # MEOW4: Hybrid PQ
        if verbose:
            print("Using MEOW4 manifest (Post-Quantum Hybrid)")
    elif forward_secrecy and receiver_public_key:
        manifest_version = 3  # MEOW3: Forward Secrecy with X25519
        if verbose:
            print("Using MEOW3 manifest (Forward Secrecy + X25519)")
    elif forward_secrecy:
        manifest_version = 3  # MEOW3: Password-only (no ephemeral keys)
        if verbose:
            print("Using MEOW3 manifest (Password-Only)")
    else:
        manifest_version = 2  # MEOW2: Base encryption
        if verbose:
            print("Using MEOW2 manifest (Base Encryption)")
    
    start_time = time.time()
    
    # Read input file
    if verbose:
        print(f"Reading input file: {input_path}")
    
    with open(input_path, 'rb') as f:
        raw_data = f.read()
    
    if verbose:
        print(f"  Size: {len(raw_data):,} bytes")
    
    # Encrypt data with forward secrecy support
    if verbose:
        print("Encrypting data with length padding (metadata protection)...")
    
    comp, sha256, salt, nonce, cipher, ephemeral_public_key, encryption_key = encrypt_file_bytes(
        raw_data,
        password,
        keyfile,
        receiver_public_key,
        use_length_padding=True,
        yubikey_slot=yubikey_slot if yubikey else None,
        yubikey_pin=yubikey_pin if yubikey else None
    )
    
    if verbose:
        print(f"  Compressed: {len(comp):,} bytes ({len(comp)/len(raw_data)*100:.1f}%)")
        print(f"  Encrypted: {len(cipher):,} bytes")
        if ephemeral_public_key:
            print(f"  ✅ Forward secrecy: Ephemeral key generated ({len(ephemeral_public_key)} bytes)")
        else:
            print(f"  ℹ️  Forward secrecy: Password-only mode")
    
    # Calculate fountain code parameters
    k_blocks = (len(cipher) + config.block_size - 1) // config.block_size
    num_droplets = int(k_blocks * config.redundancy)
    
    if verbose:
        print(f"\nFountain encoding:")
        print(f"  Block size: {config.block_size} bytes")
        print(f"  Blocks (k): {k_blocks}")
        print(f"  Droplets: {num_droplets} ({config.redundancy:.1f}x redundancy)")
    
    # Compute duress hash if duress password provided
    duress_hash = None
    if duress_password:
        if duress_password == password:
            raise ValueError("Duress password cannot be the same as encryption password")
        duress_hash = compute_duress_hash(duress_password, salt)
        if verbose:
            print(f"  🚨 Duress password configured (emergency response on decode)")
    
    # Create manifest
    manifest = Manifest(
        salt=salt,
        nonce=nonce,
        orig_len=len(raw_data),
        comp_len=len(comp),
        cipher_len=len(cipher),
        sha256=sha256,
        block_size=config.block_size,
        k_blocks=k_blocks,
        hmac=b'\x00' * 32,  # Placeholder
        ephemeral_public_key=ephemeral_public_key,  # Forward secrecy support
        duress_hash=duress_hash  # Duress password support
    )
    
    # Compute HMAC (need to handle variable manifest size)
    # CRITICAL: Manifest format is: MAGIC + salt + nonce + lengths + sha256 + HMAC + ephemeral_key
    # We need to pack WITHOUT hmac field, then compute HMAC, then insert it
    
    # Build packed manifest without HMAC
    from .crypto import MAGIC
    packed_no_hmac = (
        MAGIC +
        manifest.salt +
        manifest.nonce +
        struct.pack(">III", manifest.orig_len, manifest.comp_len, manifest.cipher_len) +
        struct.pack(">HI", manifest.block_size, manifest.k_blocks) +
        manifest.sha256
    )
    
    # Add ephemeral public key if present (AFTER all other fields, BEFORE HMAC)
    if ephemeral_public_key is not None:
        packed_no_hmac += ephemeral_public_key
    
    # Compute HMAC using the encryption key directly (critical for forward secrecy!)
    manifest.hmac = compute_manifest_hmac(
        password, salt, packed_no_hmac, keyfile, encryption_key=encryption_key
    )
    
    # Pack final manifest
    manifest_bytes = pack_manifest(manifest)
    
    if verbose:
        if ephemeral_public_key:
            print(f"  Manifest: {len(manifest_bytes)} bytes (with ephemeral key)")
        else:
            print(f"  Manifest: {len(manifest_bytes)} bytes (password-only)")
    
    # Create fountain encoder
    fountain = FountainEncoder(cipher, k_blocks, config.block_size)
    
    # Generate QR codes with frame MACs for DoS protection
    if verbose:
        print("\nGenerating QR codes with frame MACs...")
    
    # Import frame MAC module
    from .frame_mac import pack_frame_with_mac, FrameMACStats, derive_frame_master_key
    
    # Derive frame MAC master key from the encryption key (binds keyfile + FS)
    # HKDF domain separation ensures independence from other crypto keys
    # Use a mutable buffer for best-effort zeroing after use
    encryption_key_buf = bytearray(encryption_key)
    frame_master_key = derive_frame_master_key(bytes(encryption_key_buf), salt)
    # Best-effort zeroization of encryption key material
    try:
        from .crypto_backend import get_default_backend
        get_default_backend().secure_zero(encryption_key_buf)
    except Exception:
        pass
    # Drop remaining references to key material
    encryption_key = b""
    del encryption_key
    
    mac_stats = FrameMACStats()
    
    qr_generator = QRCodeGenerator(
        error_correction=config.qr_error_correction,
        box_size=config.qr_box_size,
        border=config.qr_border
    )
    
    qr_frames = []
    
    # First frame: manifest (with MAC)
    manifest_with_mac = pack_frame_with_mac(manifest_bytes, frame_master_key, 0, salt)
    manifest_qr = qr_generator.generate(manifest_with_mac)
    qr_frames.append(manifest_qr)
    mac_stats.record_valid()  # Track MAC generation
    
    if verbose:
        print(f"  Frame 0: Manifest ({len(manifest_bytes)} bytes + {len(manifest_with_mac) - len(manifest_bytes)} byte MAC)")
    
    # Remaining frames: droplets (with MACs)
    progress_bar = ProgressBar(num_droplets, desc="Generating Droplets", unit="droplets", disable=not verbose)
    
    for i in progress_bar(range(num_droplets)):
        droplet = fountain.droplet()
        droplet_bytes = pack_droplet(droplet)
        
        # Add MAC to droplet
        droplet_with_mac = pack_frame_with_mac(droplet_bytes, frame_master_key, i + 1, salt)
        
        qr = qr_generator.generate(droplet_with_mac)
        qr_frames.append(qr)
        mac_stats.record_valid()
    
    if verbose:
        print(f"  Total QR codes: {len(qr_frames)} (all with frame MACs)")
        print(f"  QR size: {qr_frames[0].size}")
    
    # Apply logo-eyes carrier if enabled
    if logo_eyes:
        if verbose:
            print(f"\n👁️ Applying logo-eyes carrier...")
        
        from .logo_eyes import encode_with_logo_eyes, LogoConfig
        
        # Configure logo - visible_qr is opposite of logo_eyes_hidden
        logo_config = LogoConfig(
            brand_text=brand_text or "MEOW",
            animate_blink=True,
            visible_qr=not logo_eyes_hidden  # Default: visible QR codes
        )
        
        try:
            qr_frames = encode_with_logo_eyes(qr_frames, config=logo_config)
            
            if verbose:
                print(f"  ✅ Logo-eyes carrier applied")
                print(f"  🐱 Brand: {logo_config.brand_text}")
                if logo_eyes_hidden:
                    print(f"  🥷 QR data hidden in eyes (LSB steganography)")
                else:
                    print(f"  👁️ QR codes visible in animated cat eyes!")
        except Exception as e:
            if verbose:
                print(f"  ⚠️ Logo-eyes failed: {e}")
                print(f"  Falling back to plain QR codes")
    
    # Apply steganography if enabled (and not using logo-eyes)
    elif stego_level > 0:
        if verbose:
            print(f"\n🥷 Applying steganography (level {stego_level})...")
        
        from .stego_advanced import encode_with_stego, StealthLevel, create_green_mask, calculate_masked_capacity
        from PIL import Image
        
        # Map level 1-4 to StealthLevel enum
        stealth_map = {1: StealthLevel.VISIBLE, 2: StealthLevel.SUBTLE, 
                       3: StealthLevel.HIDDEN, 4: StealthLevel.PARANOID}
        stealth = stealth_map.get(stego_level, StealthLevel.SUBTLE)
        
        # Load carrier images if provided (your cat photos!)
        carriers = None
        green_mask = None
        if carrier_images:
            carriers = []
            for img_path in carrier_images:
                try:
                    img = Image.open(img_path).convert('RGB')
                    carriers.append(img)
                    if verbose:
                        print(f"  🐱 Loaded carrier: {img_path.name}")
                except Exception as e:
                    if verbose:
                        print(f"  ⚠️ Skipping {img_path}: {e}")
            
            # Cycle carriers to match frame count
            if carriers:
                while len(carriers) < len(qr_frames):
                    carriers.extend(carriers[:len(qr_frames) - len(carriers)])
                carriers = carriers[:len(qr_frames)]
                if verbose:
                    print(f"  Using {len(set(carrier_images))} custom carrier image(s)")
                
                # Green-region mode: create mask from first carrier
                if stego_green:
                    green_mask = create_green_mask(carriers[0])
                    capacity = calculate_masked_capacity(green_mask, lsb_bits=stealth.value)
                    
                    if verbose:
                        print(f"  🌿 Green-region mode enabled")
                        print(f"     ⚠️ COSMETIC CAMOUFLAGE ONLY - does NOT defeat forensic analysis")
                        print(f"     📊 Capacity: {capacity['percent']:.1f}% embeddable ({capacity['bytes_capacity']:,} bytes/frame)")
                    
                    if capacity['percent'] < 5.0:
                        print(f"  ⚠️ WARNING: Only {capacity['percent']:.1f}% green pixels - encoding may fail!")
                        print(f"     💡 Try a carrier image with more green regions")
        
        # Warn if --stego-green without carriers
        if stego_green and not carriers:
            if verbose:
                print(f"  ⚠️ --stego-green requires --carrier images, ignoring flag")
        
        # Apply steganography
        try:
            qr_frames, qualities = encode_with_stego(
                qr_frames,
                stealth_level=stealth,
                carriers=carriers,
                enable_animation=(carriers is None)  # Animate if no custom carriers
            )
            
            if verbose:
                avg_psnr = sum(q.psnr for q in qualities) / len(qualities)
                print(f"  ✅ Steganography applied (avg PSNR: {avg_psnr:.1f} dB)")
                if carriers:
                    print(f"  🐱 QR codes hidden in your cat photos!")
        except Exception as e:
            if verbose:
                print(f"  ⚠️ Steganography failed: {e}")
                print(f"  Falling back to plain QR codes")
    
    # Create GIF
    if verbose:
        print("\nCreating GIF...")
    
    gif_encoder = GIFEncoder(fps=config.fps, loop=0)
    gif_size = gif_encoder.create_gif(qr_frames, output_path, optimize=(stego_level == 0))
    
    elapsed = time.time() - start_time
    
    if verbose:
        print(f"  Output: {output_path}")
        print(f"  Size: {gif_size:,} bytes")
        print(f"  Duration: {len(qr_frames) / config.fps:.1f} seconds at {config.fps} FPS")
        print(f"\nEncoding complete in {elapsed:.2f} seconds")
    
    # Return statistics
    return {
        'input_size': len(raw_data),
        'compressed_size': len(comp),
        'encrypted_size': len(cipher),
        'output_size': gif_size,
        'compression_ratio': len(comp) / len(raw_data),
        'k_blocks': k_blocks,
        'num_droplets': num_droplets,
        'redundancy': config.redundancy,
        'qr_frames': len(qr_frames),
        'qr_size': qr_frames[0].size,
        'gif_duration': len(qr_frames) / config.fps,
        'elapsed_time': elapsed
    }


def main():
    """Main CLI entry point."""
    
    parser = argparse.ArgumentParser(
        description="Meow Decoder - Encode files into GIF animations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic encoding
  meow-encode --input secret.pdf --output secret.gif

  # With keyfile
  meow-encode --input secret.pdf --keyfile key.bin --output secret.gif

  # High redundancy for poor capture conditions
  meow-encode --input secret.pdf --redundancy 2.0 --output secret.gif

  # Hide QR codes in your cat photos! 🐱
  meow-encode -i secret.pdf -o cats.gif --stego-level 3 --carrier ~/Pictures/cats/*.jpg

  # Maximum stealth with custom carriers
  meow-encode -i secret.pdf -o innocent.gif --stego-level 4 --carrier photo1.jpg photo2.png
        """
    )
    
    # Input/output are required for normal encoding, but NOT for --generate-keys.
    # We enforce requirement after parsing so key generation can run standalone.
    parser.add_argument('-i', '--input', type=Path,
                       help='Input file to encode')
    parser.add_argument('-o', '--output', type=Path,
                       help='Output GIF file')
    
    # Optional arguments
    parser.add_argument('-p', '--password', type=str,
                       help='Encryption password (⚠️  WARNING: May leak in shell history/process list! Use prompt instead.)')
    parser.add_argument('-k', '--keyfile', type=Path,
                       help='Path to keyfile')

    # Hardware-backed key derivation (YubiKey)
    parser.add_argument('--yubikey', action='store_true',
                        help='Use YubiKey PIV for key derivation (Rust backend required)')
    parser.add_argument('--yubikey-slot', type=str, default='9d',
                        help='YubiKey PIV slot (default: 9d)')
    parser.add_argument('--yubikey-pin', type=str, default=None,
                        help='YubiKey PIN (prompted if not provided)')
    
    # Encoding parameters
    parser.add_argument('--block-size', type=int, default=512,
                       help='Fountain code block size (default: 512)')
    parser.add_argument('--redundancy', type=float, default=1.5,
                       help='Redundancy factor (default: 1.5)')
    parser.add_argument('--fps', type=int, default=2,
                       help='GIF frames per second (default: 2, slow for readability)')
    
    # QR code parameters
    parser.add_argument('--qr-error', choices=['L', 'M', 'Q', 'H'], default='M',
                       help='QR error correction level (default: M)')
    parser.add_argument('--qr-box-size', type=int, default=10,
                       help='QR box size in pixels (default: 10)')
    parser.add_argument('--qr-border', type=int, default=4,
                       help='QR border size in boxes (default: 4)')
    
    # Crypto backend selection (SECURITY: Rust is HARD DEFAULT for constant-time)
    parser.add_argument('--crypto-backend', choices=['python', 'rust', 'auto'], default='auto',
                       help='Crypto backend: python, rust, or auto (default: auto, Rust required)')
    parser.add_argument('--legacy-python', '--python-fallback', action='store_true', dest='legacy_python',
                       help='⚠️  LEGACY: Allow Python backend (NOT constant-time, timing attacks possible)')
    
    # Steganography options (hide QR in images)
    parser.add_argument('--stego-level', type=int, choices=[0, 1, 2, 3, 4], default=0,
                       help='Steganography level: 0=off, 1=visible, 2=subtle, 3=hidden, 4=paranoid (default: 0)')
    parser.add_argument('--carrier', '-c', type=Path, nargs='+', dest='carrier_images',
                       help='Custom carrier images (your cat photos!) for steganography. Images cycle through frames.')
    parser.add_argument('--stego-green', action='store_true',
                       help='Embed only in green-dominant pixels (logo eyes/waves). '
                            '⚠️ COSMETIC ONLY: Does NOT defeat steganalysis. '
                            'Reduces capacity to ~10-30%%. Requires --carrier. Test output visually!')
    
    # Logo-eyes mode (branded animation with data in eyes)
    parser.add_argument('--logo-eyes', action='store_true',
                       help='Use logo-eyes carrier: animated cat logo with QR data in eyes (visible by default)')
    parser.add_argument('--logo-eyes-hidden', action='store_true',
                       help='Hide QR codes in logo eyes using LSB steganography (stealthy but harder to decode)')
    parser.add_argument('--brand-text', type=str, default=None,
                       help='Custom brand text for logo-eyes mode (default: MEOW)')
    
    # Security features (Forward Secrecy ON by default!)
    parser.add_argument('--forward-secrecy', action='store_true', default=True,
                       help='Enable forward secrecy (ON by default, MEOW3)')
    parser.add_argument('--no-forward-secrecy', action='store_true',
                       help='Disable forward secrecy (revert to MEOW2)')
    parser.add_argument('--receiver-pubkey', type=Path,
                       help='Path to receiver X25519 public key (32 bytes) for forward secrecy')
    parser.add_argument('--pq', '--post-quantum', action='store_true',
                       help='Enable post-quantum hybrid mode (MEOW4, requires liboqs)')
    
    # Duress mode (coercion resistance)
    parser.add_argument('--duress-password', type=str,
                       help='Duress password that triggers emergency wipe on decode (⚠️ Cannot be same as main password)')
    parser.add_argument('--duress-password-prompt', action='store_true',
                       help='Prompt for duress password interactively (more secure than CLI arg)')
    
    # Key generation
    parser.add_argument('--generate-keys', action='store_true',
                       help='Generate receiver keypair for forward secrecy and exit')
    parser.add_argument('--key-output-dir', type=Path, default=Path('.'),
                       help='Directory for generated keys (default: current directory)')
    
    # Cat modes and fun
    parser.add_argument('--cat-mode', action='store_true',
                       help='Use bundled cat-themed carrier GIF (demo_logo_eyes.gif). '
                            '⚠️ COSMETIC ONLY: Does not hide QR presence from steganalysis.')
    parser.add_argument('--mode', choices=['normal', 'void'], default='normal',
                       help='Encoding mode: normal or void (paranoid stealth)')
    parser.add_argument('--fun', action='store_true',
                       help='Enable cat sound effects (requires playsound)')
    parser.add_argument('--catnip', choices=['tuna', 'salmon', 'chicken', 'beef', 'turkey', 'fish'],
                       help='Catnip flavor for HKDF salt (pure meme, functionally harmless)')
    
    # Output control
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--wipe-source', action='store_true',
                       help='Securely wipe source file after encoding')
    parser.add_argument('--summon-void-cat', action='store_true',
                       help='Summon the void cat (easter egg)')
    
    # High-security mode
    parser.add_argument('--high-security', '--paranoid', action='store_true',
                       help='High-security mode: increased Argon2 memory, post-quantum crypto, secure wipe')
    parser.add_argument('--safety-checklist', action='store_true',
                       help='Show operational security checklist and exit')
    
    args = parser.parse_args()
    
    # CRITICAL: Wire --legacy-python to env var BEFORE any crypto calls
    if args.legacy_python:
        os.environ['MEOW_ALLOW_PYTHON_FALLBACK'] = '1'
        os.environ['MEOW_LEGACY_PYTHON'] = '1'
    
    # Handle key generation (do this first, then exit)
    if args.generate_keys:
        from .x25519_forward_secrecy import generate_receiver_keys_cli
        print("\n🔐 GENERATING RECEIVER KEYPAIR FOR FORWARD SECRECY")
        print("=" * 60)
        try:
            generate_receiver_keys_cli(str(args.key_output_dir))
            print("\n✅ Keys generated successfully!")
            print(f"\n📤 Share the PUBLIC key with senders:")
            print(f"   {args.key_output_dir / 'receiver_public.key'}")
            print(f"\n🔒 Keep the PRIVATE key SECRET:")
            print(f"   {args.key_output_dir / 'receiver_private.pem'}")
            return 0
        except Exception as e:
            print(f"\n❌ Key generation failed: {e}")
            return 1

    # Easter egg: summon void cat (doesn't require input/output)
    if args.summon_void_cat:
        print("""
　／＞　　フ
| 　_　 _ l
／` ミ＿xノ
/　　　 　 |
/　 ヽ　　 ﾉ
│　　|　|　|
／￣|　　|　|　|　＼
| (￣ヽ＿_ヽ_)__)
＼二つ

🐈‍⬛ VOID CAT SUMMONED

All evidence consumed.
Nothing to see here.
😶‍🌫️ Meow.
""")
        sys.exit(0)
    
    # Safety checklist
    if args.safety_checklist:
        try:
            from .high_security import get_safety_checklist
            print(get_safety_checklist())
        except ImportError:
            print("Security checklist module not available.")
        sys.exit(0)
    
    # High-security mode - increased parameters for threat models requiring stronger protection
    if args.high_security:
        try:
            from .high_security import enable_high_security_mode, HighSecurityConfig
            enable_high_security_mode(silent=False)
            hs_config = HighSecurityConfig()
            print("\n🔒 HIGH-SECURITY MODE ENABLED")
            print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"  Argon2id: {hs_config.argon2_memory // 1024} MiB, {hs_config.argon2_iterations} iterations")
            print(f"  Post-Quantum: {hs_config.kyber_variant}")
            print(f"  Secure wipe: {hs_config.secure_wipe_passes} passes")
            print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print("⚠️  Key derivation will take several seconds.\n")
            args.wipe_source = True
        except ImportError:
            print("Warning: High-security module not available, using defaults.")

    # For normal operation, require input/output.
    if args.input is None or args.output is None:
        parser.error("the following arguments are required: -i/--input, -o/--output")
    
    # Cat mode: use bundled carrier if no custom carrier provided
    if args.cat_mode and not args.carrier_images:
        cat_carrier = Path(__file__).parent.parent / 'assets' / 'demo_logo_eyes.gif'
        if cat_carrier.exists():
            args.carrier_images = [cat_carrier]
            if args.stego_level == 0:
                args.stego_level = 2  # Default to subtle stego
            print("🐱 Cat Mode activated! Using bundled cat carrier.")
            print("   ⚠️ Note: Cosmetic camouflage only — QR still detectable under analysis.")
        else:
            print("⚠️ Cat Mode: Bundled carrier not found, proceeding with plain QR codes.")
    
    # Void cat mode
    if args.mode == 'void':
        print("""
🐈‍⬛ VOID CAT MODE ACTIVATED
━━━━━━━━━━━━━━━━━━━━━━━━━
Maximum paranoid stealth engaged.
All evidence will be consumed.
Nothing to see here. 😶‍🌫️
━━━━━━━━━━━━━━━━━━━━━━━━━
""")
        # Force paranoid settings
        args.stego_level = 4  # Maximum stealth
        if not hasattr(args, 'stego_level'):
            print("⚠️  Note: Steganography not implemented yet, but void mode ready!")
        args.verbose = False  # Silence is golden
    
    # Handle forward secrecy flag
    if hasattr(args, 'no_forward_secrecy') and args.no_forward_secrecy:
        args.forward_secrecy = False
        print("\n⚠️  Forward secrecy DISABLED (--no-fs)")
        print("   Using MEOW2 crypto (password-only mode)")
    
    # Load receiver public key for forward secrecy
    receiver_public_key = None
    if args.forward_secrecy and args.receiver_pubkey:
        try:
            with open(args.receiver_pubkey, 'rb') as f:
                receiver_public_key = f.read()
            
            if len(receiver_public_key) != 32:
                print(f"\n❌ Error: Receiver public key must be 32 bytes, got {len(receiver_public_key)}")
                print(f"   Generate keys with: meow-encode --generate-keys")
                sys.exit(1)
            
            print("\n✅ Forward secrecy ENABLED with X25519 ephemeral keys")
            print(f"   🔐 Using receiver public key: {args.receiver_pubkey}")
            print(f"   🔑 Ephemeral keys will be generated per encryption")
            print(f"   ✅ Future password compromise won't decrypt past messages")
        except FileNotFoundError:
            print(f"\n❌ Error: Receiver public key not found: {args.receiver_pubkey}")
            print(f"   Generate keys with: meow-encode --generate-keys")
            sys.exit(1)
    elif args.forward_secrecy and not args.receiver_pubkey:
        print("\n⚠️  Forward secrecy ENABLED but no receiver public key provided")
        print("   Using password-only mode (MEOW3 without FS)")
        print(f"   💡 For true forward secrecy:")
        print(f"      1. Generate keys: meow-encode --generate-keys")
        print(f"      2. Use: --receiver-pubkey receiver_public.key")
    
    # Forward secrecy status
    if args.forward_secrecy:
        if receiver_public_key:
            if args.verbose:
                print("🔄 Forward secrecy: ENABLED (MEOW3 + X25519)")
        else:
            if args.verbose:
                print("🔄 Forward secrecy: CONFIG ON but no receiver key (password-only)")
    else:
        if args.verbose:
            print("ℹ️  Forward secrecy: DISABLED (using MEOW2)")
        
        if args.pq:
            print("🔮 Post-quantum mode: ENABLED (MEOW4) [EXPERIMENTAL]")
        
        if args.catnip:
            print(f"🌿 Catnip flavor: {args.catnip.upper()} (meow!)")
    
    # Show catnip flavor even in non-verbose for fun
    if args.catnip and not args.verbose:
        print(f"🌿 Using {args.catnip} catnip! Meow! 😸")
    
    # Validate input file
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    if not args.input.is_file():
        print(f"Error: Input is not a file: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass("Enter encryption password: ")
        password_confirm = getpass("Confirm password: ")
        
        if password != password_confirm:
            print("Error: Passwords do not match", file=sys.stderr)
            sys.exit(1)
    
    if not password:
        print("Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)
    
    # Cat judge password strength
    try:
        from cat_utils import summon_cat_judge
        judgment = summon_cat_judge(password)
        print(f"\n🐱 Cat Judge: {judgment}\n")
    except ImportError:
        pass  # Cat utils not available
    
    # Load keyfile if specified
    keyfile = None
    if args.keyfile:
        try:
            keyfile = verify_keyfile(str(args.keyfile))
            if args.verbose:
                print(f"Loaded keyfile: {args.keyfile} ({len(keyfile)} bytes)")
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    # YubiKey validation
    if args.yubikey:
        if keyfile is not None:
            print("Error: Cannot combine --yubikey with --keyfile", file=sys.stderr)
            sys.exit(1)
        if receiver_public_key is not None:
            print("Error: YubiKey derivation is not supported with forward secrecy keys", file=sys.stderr)
            sys.exit(1)
        if args.yubikey_pin is None:
            yk_pin = getpass("Enter YubiKey PIN (leave blank if not required): ")
            args.yubikey_pin = yk_pin if yk_pin else None
    
    # Handle duress password
    duress_password = None
    if args.duress_password_prompt:
        duress_password = getpass("Enter duress password (triggers emergency wipe): ")
        if duress_password:
            duress_confirm = getpass("Confirm duress password: ")
            if duress_password != duress_confirm:
                print("Error: Duress passwords do not match", file=sys.stderr)
                sys.exit(1)
            if duress_password == password:
                print("Error: Duress password cannot be same as encryption password", file=sys.stderr)
                sys.exit(1)
            print("🚨 Duress password configured")
    elif args.duress_password:
        duress_password = args.duress_password
        if duress_password == password:
            print("Error: Duress password cannot be same as encryption password", file=sys.stderr)
            sys.exit(1)
        print("🚨 Duress password configured (WARNING: visible in CLI args)")
    
    # Duress mode requires forward secrecy to avoid manifest size ambiguity
    if duress_password and not args.forward_secrecy:
        print("Error: Duress mode requires forward secrecy enabled", file=sys.stderr)
        print("   Do not use --no-forward-secrecy with --duress-password", file=sys.stderr)
        sys.exit(1)
    
    # Create encoding config
    config = EncodingConfig(
        block_size=args.block_size,
        redundancy=args.redundancy,
        qr_error_correction=args.qr_error,
        qr_box_size=args.qr_box_size,
        qr_border=args.qr_border,
        fps=args.fps
    )
    
    # Encode file
    try:
        stats = encode_file(
            args.input,
            args.output,
            password,
            config=config,
            keyfile=keyfile,
            forward_secrecy=args.forward_secrecy,
            receiver_public_key=receiver_public_key,  # Forward secrecy support
            yubikey=args.yubikey,
            yubikey_slot=args.yubikey_slot,
            yubikey_pin=args.yubikey_pin,
            use_pq=args.pq,
            stego_level=args.stego_level,
            carrier_images=args.carrier_images,
            stego_green=args.stego_green,
            logo_eyes=args.logo_eyes,
            logo_eyes_hidden=args.logo_eyes_hidden,
            brand_text=args.brand_text,
            duress_password=duress_password,
            verbose=args.verbose
        )
        
        # Print summary
        if not args.verbose:
            print(f"\n✅ Encoding complete!")
            print(f"  Input: {stats['input_size']:,} bytes")
            print(f"  Output: {stats['output_size']:,} bytes ({stats['qr_frames']} frames)")
            print(f"  Compression: {stats['compression_ratio']*100:.1f}%")
            print(f"  Duration: {stats['gif_duration']:.1f}s at {config.fps} FPS")
            print(f"  Time: {stats['elapsed_time']:.2f}s")
        
        # Wipe source if requested
        if args.wipe_source:
            if args.verbose:
                print(f"\nSecurely wiping source file...")
            
            # Use secure wipe if available (DoD standard)
            try:
                from .high_security import secure_wipe_file
                if args.high_security:
                    # 7-pass DoD wipe for high-security mode
                    success = secure_wipe_file(args.input, passes=7)
                else:
                    # 3-pass wipe for normal users
                    success = secure_wipe_file(args.input, passes=3)
                
                if success:
                    print(f"  ✓ Source file securely wiped: {args.input}")
                else:
                    print(f"  ⚠️  Wipe may have failed - manually verify deletion")
            except ImportError:
                # Fallback to simple overwrite
                file_size = args.input.stat().st_size
                with open(args.input, 'wb') as f:
                    f.write(b'\x00' * file_size)
                args.input.unlink()
                print(f"  ✓ Source file wiped: {args.input}")
        
        print(f"\nOutput saved to: {args.output}")
        
    except Exception as e:
        print(f"\nError during encoding: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
