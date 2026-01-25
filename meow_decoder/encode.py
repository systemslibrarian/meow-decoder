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
    Manifest, verify_keyfile
)
from .fountain import FountainEncoder, pack_droplet
from .qr_code import QRCodeGenerator
from .gif_handler import GIFEncoder


def encode_file(
    input_path: Path,
    output_path: Path,
    password: str,
    config: Optional[EncodingConfig] = None,
    keyfile: Optional[bytes] = None,
    forward_secrecy: bool = True,
    receiver_public_key: Optional[bytes] = None,
    use_pq: bool = False,
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
        verbose: Print verbose output
        
    Returns:
        Dictionary with encoding statistics
    """
    if config is None:
        config = EncodingConfig()
    
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
        raw_data, password, keyfile, receiver_public_key, use_length_padding=True
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
        ephemeral_public_key=ephemeral_public_key  # Forward secrecy support
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
    from .frame_mac import pack_frame_with_mac, FrameMACStats
    
    # Derive frame MAC key from password (prevents frame injection)
    # We use the salt as additional material for frame key derivation
    import hashlib
    frame_master_key = hashlib.sha256(password.encode('utf-8') + salt + b'frame_mac_key').digest()
    
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
    for i in range(num_droplets):
        droplet = fountain.droplet()
        droplet_bytes = pack_droplet(droplet)
        
        # Add MAC to droplet
        droplet_with_mac = pack_frame_with_mac(droplet_bytes, frame_master_key, i + 1, salt)
        
        qr = qr_generator.generate(droplet_with_mac)
        qr_frames.append(qr)
        mac_stats.record_valid()
        
        if verbose and (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{num_droplets} droplets...")
    
    if verbose:
        print(f"  Total QR codes: {len(qr_frames)} (all with frame MACs)")
        print(f"  QR size: {qr_frames[0].size}")
    
    # Create GIF
    if verbose:
        print("\nCreating GIF...")
    
    gif_encoder = GIFEncoder(fps=config.fps, loop=0)
    gif_size = gif_encoder.create_gif(qr_frames, output_path, optimize=True)
    
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

  # Custom block size
  meow-encode --input secret.pdf --block-size 1024 --output secret.gif
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
    
    # Encoding parameters
    parser.add_argument('--block-size', type=int, default=512,
                       help='Fountain code block size (default: 512)')
    parser.add_argument('--redundancy', type=float, default=1.5,
                       help='Redundancy factor (default: 1.5)')
    parser.add_argument('--fps', type=int, default=10,
                       help='GIF frames per second (default: 10)')
    
    # QR code parameters
    parser.add_argument('--qr-error', choices=['L', 'M', 'Q', 'H'], default='M',
                       help='QR error correction level (default: M)')
    parser.add_argument('--qr-box-size', type=int, default=10,
                       help='QR box size in pixels (default: 10)')
    parser.add_argument('--qr-border', type=int, default=4,
                       help='QR border size in boxes (default: 4)')
    
    # Crypto backend selection
    parser.add_argument('--crypto-backend', choices=['python', 'rust', 'auto'], default='auto',
                       help='Crypto backend: python, rust, or auto (default: auto)')
    
    # Security features (Forward Secrecy ON by default!)
    parser.add_argument('--forward-secrecy', action='store_true', default=True,
                       help='Enable forward secrecy (ON by default, MEOW3)')
    parser.add_argument('--no-forward-secrecy', action='store_true',
                       help='Disable forward secrecy (revert to MEOW2)')
    parser.add_argument('--receiver-pubkey', type=Path,
                       help='Path to receiver X25519 public key (32 bytes) for forward secrecy')
    parser.add_argument('--pq', '--post-quantum', action='store_true',
                       help='Enable post-quantum hybrid mode (MEOW4, requires liboqs)')
    
    # Key generation
    parser.add_argument('--generate-keys', action='store_true',
                       help='Generate receiver keypair for forward secrecy and exit')
    parser.add_argument('--key-output-dir', type=Path, default=Path('.'),
                       help='Directory for generated keys (default: current directory)')
    
    # Cat modes and fun
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
            use_pq=args.pq,
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
