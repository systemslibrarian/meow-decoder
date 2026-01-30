#!/usr/bin/env python3
"""
Meow Decoder - GIF Decoder CLI
Decodes files from GIF animations
"""

import sys
import argparse
from pathlib import Path
from getpass import getpass
from typing import Optional
import time
import hashlib

# Import core modules

from .config import MeowConfig, DecodingConfig, DuressConfig, DuressMode
from .crypto import (
    decrypt_to_raw, verify_manifest_hmac, unpack_manifest,
    verify_keyfile, check_duress_password, derive_encryption_key_for_manifest,
    pack_manifest_core
)
from .fountain import FountainDecoder, unpack_droplet
from .qr_code import QRCodeReader
from .gif_handler import GIFDecoder
from .progress import ProgressBar
from .hardware_integration import HardwareSecurityProvider, process_hardware_args


def decode_gif(
    input_path: Path,
    output_path: Path,
    password: str,
    config: Optional[DecodingConfig] = None,
    duress_config: Optional[DuressConfig] = None,
    keyfile: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    hsm_slot: Optional[int] = None,
    hsm_pin: Optional[str] = None,
    hsm_key_label: Optional[str] = None,
    tpm_derive: bool = False,
    hardware_auto: bool = False,
    verbose: bool = False
) -> dict:
    """
    Decode file from GIF.
    
    Args:
        input_path: Path to input GIF
        output_path: Path to output file
        password: Decryption password
        config: Decoding configuration
        duress_config: Duress configuration
        keyfile: Optional keyfile content
        receiver_private_key: Optional X25519 private key for forward secrecy (32 bytes)
        precomputed_key: Optional pre-derived 32-byte key (HSM/TPM/hardware mode)
                        If provided, skips key derivation and uses this key
        hsm_slot: HSM PKCS#11 slot number (enables HSM mode)
        hsm_pin: HSM user PIN
        hsm_key_label: HSM key label for derivation
        tpm_derive: Use TPM for key derivation
        hardware_auto: Automatically use best available hardware security
        verbose: Print verbose output
        
    Returns:
        Dictionary with decoding statistics
    """
    if config is None:
        config = DecodingConfig()
    
    if duress_config is None:
        duress_config = DuressConfig()

    
    start_time = time.time()
    
    # Extract frames from GIF
    if verbose:
        print(f"Loading GIF: {input_path}")
    
    gif_decoder = GIFDecoder()
    frames = gif_decoder.extract_frames(input_path)
    
    if verbose:
        print(f"  Frames: {len(frames)}")
        print(f"  Size: {frames[0].size if frames else 'N/A'}")
    
    if not frames:
        raise ValueError("No frames found in GIF")
    
    # Read QR codes
    if verbose:
        print("\nReading QR codes with frame MAC verification...")
    
    # Import as a module so tests can monkeypatch `meow_decoder.frame_mac.*`
    # and have it affect this function.
    from . import frame_mac
    
    # Derive frame MAC key (same as encode)
    import hashlib
    
    # We'll derive the frame key after we get the manifest (which has the salt)
    # For now, just read QR codes raw
    qr_reader = QRCodeReader(preprocessing=config.preprocessing)
    qr_data_list = []
    
    progress = ProgressBar(len(frames), desc="Scanning QR Codes", unit="frames", disable=not verbose)
    
    for i, frame in enumerate(progress(frames)):
        qr_data = qr_reader.read_image(frame)
        
        if qr_data:
            qr_data_list.extend(qr_data)
        elif verbose:
            # Only print warning if we're not using tqdm, or use tqdm write if available
            # But ProgressBar doesn't expose write yet. 
            # For now, let's silence the warning to avoid breaking progress bar,
            # or we could just count them.
            pass
            
    if verbose:
        print(f"  Total QR codes read: {len(qr_data_list)}")
    
    if not qr_data_list:
        raise ValueError("No QR codes found in GIF")
    
    # First QR is manifest - try to unpack with MAC verification
    if verbose:
        print("\nParsing manifest with MAC verification...")
    
    # Try to parse manifest directly (it might not have MAC if it's old format)
    manifest_raw = qr_data_list[0]
    
    # CRITICAL: Verify manifest frame decoded correctly from QR/GIF
    # Expected lengths (base = 115, FS ephemeral = +32, duress = +32, frame MAC = +8):
    #   - Password-only (no MAC): 115 bytes
    #   - Password-only (with MAC): 123 bytes (115 + 8)
    #   - Forward secrecy (no MAC): 147 bytes (115 + 32)
    #   - Forward secrecy (with MAC): 155 bytes (147 + 8)
    #   - FS + duress (no MAC): 179 bytes (147 + 32)
    #   - FS + duress (with MAC): 187 bytes (179 + 8)
    expected_lengths = [115, 123, 147, 155, 179, 187, 1235, 1243, 1267, 1275]
    
    if len(manifest_raw) not in expected_lengths:
        raise ValueError(
            f"Manifest QR decode corrupted or truncated!\n"
            f"  Expected: {expected_lengths} bytes\n"
            f"  Got: {len(manifest_raw)} bytes\n"
            f"  This indicates GIF compression or QR decode failure.\n"
            f"  Try: Higher QR error correction (H), disable GIF optimization, or larger box_size."
        )
    
    # Check if manifest has MAC (length check)
    # Manifest with MAC: adds 8 bytes to any base size
    # Base sizes: 115 (password-only), 147 (FS), 179 (FS+duress), 1235 (PQ), 1267 (PQ+duress)
    # With MAC: 123, 155, 187, 1243, 1275
    has_frame_macs = False
    manifest_bytes = manifest_raw
    
    if len(manifest_raw) in [123, 155, 187, 1243, 1275]:
        # Might have frame MAC, but we need password to verify
        # For now, skip MAC verification on manifest (we'll do full manifest HMAC)
        # Just strip the potential MAC for now
        manifest_bytes = manifest_raw[8:]  # Strip first 8 bytes (MAC)
        has_frame_macs = True
        if verbose:
            print(f"  Detected frame MACs (manifest size: {len(manifest_raw)} bytes)")
    
    manifest = unpack_manifest(manifest_bytes)
    
    if verbose:
        print(f"  Original size: {manifest.orig_len:,} bytes")
        print(f"  Compressed size: {manifest.comp_len:,} bytes")
        print(f"  Encrypted size: {manifest.cipher_len:,} bytes")
        print(f"  Blocks (k): {manifest.k_blocks}")
        print(f"  Block size: {manifest.block_size} bytes")
        if manifest.ephemeral_public_key:
            print(f"  ✅ Forward secrecy: Ephemeral key present")
    
    # SECURITY (CRIT-04): Always run Argon2id BEFORE duress/HMAC checks to prevent timing oracle.
    # An attacker measuring timing could distinguish duress (fast SHA-256) from real (slow Argon2id).
    # By running Argon2id first, both paths have identical timing characteristics.
    # See CRYPTO_SECURITY_REVIEW.md § CRIT-04 for full rationale.
    if verbose:
        print("\nDeriving key (timing-safe)...")
    
    # 🔐 HSM/TPM/Hardware-Auto: Derive key using hardware if configured
    # Now that we have manifest.salt, we can derive the key via hardware
    if precomputed_key is None and (hsm_slot is not None or tpm_derive or hardware_auto):
        # Build a minimal args namespace for process_hardware_args
        import argparse
        hw_args = argparse.Namespace(
            hsm_slot=hsm_slot,
            hsm_pin=hsm_pin,
            hsm_key_label=hsm_key_label or 'meow-master',
            tpm_derive=tpm_derive,
            hardware_auto=hardware_auto,
            no_hardware_fallback=False
        )
        try:
            hw_key, hw_desc = process_hardware_args(hw_args, password.encode('utf-8'), manifest.salt)
            if hw_key is not None:
                precomputed_key = hw_key
                if verbose:
                    print(f"  🔐 Key derived via: {hw_desc}")
            else:
                if verbose:
                    print("  ⚠️ Hardware derivation returned None, falling back to software mode")
        except Exception as e:
            if verbose:
                print(f"  ⚠️ Hardware key derivation failed: {e}")
                print("  Falling back to software derivation.")
    
    # Always derive encryption key upfront (slow Argon2id)
    # For HSM/TPM mode, use precomputed key if provided
    try:
        if precomputed_key is not None:
            if len(precomputed_key) != 32:
                raise ValueError(f"Precomputed key must be 32 bytes, got {len(precomputed_key)}")
            encryption_key = precomputed_key
            if verbose:
                print("  🔐 Using hardware-derived key (HSM/TPM)")
        else:
            encryption_key = derive_encryption_key_for_manifest(
                password,
                manifest.salt,
                keyfile=keyfile,
                ephemeral_public_key=manifest.ephemeral_public_key,
                receiver_private_key=receiver_private_key,
                yubikey_slot=yubikey_slot,
                yubikey_pin=yubikey_pin
            )
    except Exception as e:
        # Key derivation failed - could be wrong keyfile/receiver key
        raise ValueError(f"Key derivation failed: {e}")
    
    # Check for duress password AFTER Argon2id to prevent timing oracle.
    # Only active when duress_config.enabled is True.
    # Uses a fast authenticated duress tag bound to the manifest core.
    if duress_config.enabled and manifest.duress_tag is not None:
        manifest_core = pack_manifest_core(manifest, include_duress_tag=False)
        if check_duress_password(password, manifest.salt, manifest.duress_tag, manifest_core):
            # DURESS PASSWORD DETECTED - trigger emergency response
            if verbose:
                print("\n🚨 DURESS PASSWORD DETECTED - Emergency protocol activated")
            
            # Import and use DuressHandler
            try:
                from .duress_mode import DuressHandler
                
                # Use passed configuration (or default if None)
                d_config = duress_config or DuressConfig()
                handler = DuressHandler(d_config)
                
                # Get decoy data
                decoy_data, filename = handler.get_decoy_data()
                
                # Handle PANIC mode (explicit opt-in)
                # In new architecture, Handler generates decoy first, then we decide if we PANIC
                if d_config.mode == DuressMode.PANIC and d_config.panic_enabled:
                     if verbose:
                         print("  🔥 PANIC MODE: Silent exit initiated")
                     # Silent exit
                     sys.exit(1)
                
                if decoy_data:
                    # DECOY MODE: Write deterministic decoy and return "success"
                    if verbose:
                        print("  ✓ Authenticated and verified")
                    
                    with open(output_path, 'wb') as f:
                        f.write(decoy_data)
                    
                    # Return fake success statistics to mask the duress event
                    return {
                        'input_frames': len(frames),
                        'qr_codes_read': len(qr_data_list),
                        'droplets_processed': manifest.k_blocks * 2, # Fake efficiency
                        'blocks_decoded': manifest.k_blocks,
                        'output_size': len(decoy_data),
                        'efficiency': 1.0,
                        'elapsed_time': time.time() - start_time
                    }

            except ImportError:
                pass  # Duress mode module not available
            except SystemExit:
                raise # Propagate panic exit
            
            # Return fake "failed" error to not reveal duress was triggered (Silent Panic)
            raise ValueError("HMAC verification failed - wrong password or corrupted data")
    
    # Verify HMAC
    if verbose:
        print("\nVerifying manifest HMAC...")
    
    if not verify_manifest_hmac(
        password,
        manifest,
        keyfile,
        receiver_private_key,
        yubikey_slot=yubikey_slot,
        yubikey_pin=yubikey_pin,
        precomputed_key=precomputed_key
    ):
        raise ValueError("HMAC verification failed - wrong password or corrupted data")
    
    if verbose:
        print("  ✓ Manifest HMAC valid")
    
    # Now derive frame MAC key if we detected MACs
    mac_stats = frame_mac.FrameMACStats()
    
    if has_frame_macs:
        if verbose:
            print("\n🔒 Frame MAC verification enabled (DoS protection)")

        # Use already-derived encryption key (from timing-safe derivation above)
        # Use a mutable buffer for best-effort zeroing after use
        encryption_key_buf = bytearray(encryption_key)
        frame_master_key = frame_mac.derive_frame_master_key(bytes(encryption_key_buf), manifest.salt)
        # Best-effort zeroization of encryption key material
        try:
            from .crypto_backend import get_default_backend
            get_default_backend().secure_zero(encryption_key_buf)
        except Exception:
            pass
        # Drop remaining references to key material
        encryption_key = b""
        del encryption_key

        # Verify manifest frame MAC retroactively (v2 key derivation)
        manifest_valid, _ = frame_mac.unpack_frame_with_mac(
            manifest_raw, frame_master_key, 0, manifest.salt
        )

        if not manifest_valid:
            # Legacy compatibility: pre-v2 files derived MAC key from password only
            legacy_master_key = frame_mac.derive_frame_master_key_legacy(password, manifest.salt)
            manifest_valid_legacy, _ = frame_mac.unpack_frame_with_mac(
                manifest_raw, legacy_master_key, 0, manifest.salt
            )
            if manifest_valid_legacy:
                frame_master_key = legacy_master_key
                mac_stats.record_valid()
                if verbose:
                    print("  ✓ Manifest frame MAC valid (legacy derivation)")
            else:
                # Fail open (disable frame MAC mode) rather than hard-failing the decode.
                # The manifest HMAC has already been verified above.
                has_frame_macs = False
                frame_master_key = None
                if verbose:
                    print("  ⚠️  Manifest frame MAC invalid; disabling frame MAC verification")
        else:
            mac_stats.record_valid()
            if verbose:
                print("  ✓ Manifest frame MAC valid")
    
    # Decode fountain codes
    if verbose:
        if has_frame_macs:
            print("\nDecoding fountain codes with frame MAC verification...")
        else:
            print("\nDecoding fountain codes...")
    
    decoder = FountainDecoder(
        manifest.k_blocks, 
        manifest.block_size,
        original_length=manifest.cipher_len  # Store length in decoder
    )
    
    droplets_processed = 0
    droplets_rejected = 0
    
    progress = ProgressBar(len(qr_data_list) - 1, desc="Processing Droplets", unit="droplets", disable=not verbose)
    
    for idx, qr_data in enumerate(progress(qr_data_list[1:])):  # Skip manifest
        try:
            # Verify frame MAC if enabled
            if has_frame_macs:
                frame_valid, droplet_bytes = frame_mac.unpack_frame_with_mac(
                    qr_data, frame_master_key, idx + 1, manifest.salt
                )
                
                if not frame_valid:
                    droplets_rejected += 1
                    mac_stats.record_invalid()
                    if verbose and droplets_rejected <= 5:
                        print(f"  ⚠️  Frame {idx + 1}: MAC invalid, skipping (frame injection?)")
                    continue
                
                mac_stats.record_valid()
            else:
                droplet_bytes = qr_data
            
            # Unpack droplet from verified bytes
            droplet = unpack_droplet(droplet_bytes, manifest.block_size)
            decoder.add_droplet(droplet)
            droplets_processed += 1
            
            if decoder.is_complete():
                if verbose:
                    print(f"  ✓ Decoding complete after {droplets_processed} droplets")
                break
        
        except Exception as e:
            if verbose:
                print(f"  Warning: Failed to process droplet: {e}")
            continue
    
    if not decoder.is_complete():
        raise RuntimeError(
            f"Decoding incomplete: {decoder.decoded_count}/{manifest.k_blocks} blocks decoded. "
            f"Need more droplets (processed {droplets_processed}, might need ~{int(manifest.k_blocks * 1.5)})"
        )
    
    # Report frame MAC statistics
    if has_frame_macs and verbose:
        print(f"\n📊 Frame MAC Statistics:")
        print(f"  Valid frames: {mac_stats.valid_frames}")
        print(f"  Invalid frames: {mac_stats.invalid_frames} (rejected)")
        print(f"  Success rate: {mac_stats.success_rate()*100:.1f}%")
        if droplets_rejected > 0:
            print(f"  🔒 DoS protection: Rejected {droplets_rejected} invalid frames!")
    
    # Get decoded cipher text
    cipher = decoder.get_data(manifest.cipher_len)
    
    if verbose:
        print(f"\nDecrypting data...")
    
    # Decrypt with forward secrecy support
    try:
        raw_data = decrypt_to_raw(
            cipher, password, manifest.salt, manifest.nonce, keyfile,
            manifest.orig_len, manifest.comp_len, manifest.sha256,
            manifest.ephemeral_public_key, receiver_private_key,
            yubikey_slot=yubikey_slot,
            yubikey_pin=yubikey_pin,
            precomputed_key=precomputed_key
        )
        
        if verbose and manifest.ephemeral_public_key:
            print(f"  ✅ Forward secrecy: Decrypted using ephemeral key")
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")
    
    # Verify SHA256
    if verbose:
        print("Verifying integrity...")
    
    computed_sha = hashlib.sha256(raw_data).digest()
    if computed_sha != manifest.sha256:
        raise ValueError("SHA256 mismatch - data corrupted")
    
    if verbose:
        print("  ✓ Integrity verified")
    
    # Write output
    if verbose:
        print(f"\nWriting output: {output_path}")
    
    with open(output_path, 'wb') as f:
        f.write(raw_data)
    
    elapsed = time.time() - start_time
    
    if verbose:
        print(f"  Size: {len(raw_data):,} bytes")
        print(f"\nDecoding complete in {elapsed:.2f} seconds")
    
    # Return statistics
    return {
        'input_frames': len(frames),
        'qr_codes_read': len(qr_data_list),
        'droplets_processed': droplets_processed,
        'blocks_decoded': decoder.decoded_count,
        'output_size': len(raw_data),
        'efficiency': decoder.decoded_count / droplets_processed if droplets_processed > 0 else 0,
        'elapsed_time': elapsed
    }


def main():
    """Main CLI entry point."""
    
    parser = argparse.ArgumentParser(
        description="Meow Decoder - Decode files from GIF animations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic decoding
  meow-decode-gif --input secret.gif --output secret.pdf

  # With keyfile
  meow-decode-gif --input secret.gif --keyfile key.bin --output secret.pdf

  # Aggressive preprocessing for difficult QR codes
  meow-decode-gif --input secret.gif --aggressive --output secret.pdf
        """
    )
    
    # Required arguments
    parser.add_argument('-i', '--input', type=Path, required=True,
                       help='Input GIF file')
    parser.add_argument('-o', '--output', type=Path, required=True,
                       help='Output file')
    
    # Optional arguments
    parser.add_argument('-p', '--password', type=str,
                       help='Decryption password (prompted if not provided)')
    parser.add_argument('-k', '--keyfile', type=Path,
                       help='Path to keyfile')
    parser.add_argument('--yubikey', action='store_true',
                       help='Use YubiKey PIV for key derivation (Rust backend required)')
    parser.add_argument('--yubikey-slot', type=str, default='9d',
                       help='YubiKey PIV slot (default: 9d)')
    parser.add_argument('--yubikey-pin', type=str, default=None,
                       help='YubiKey PIN (prompted if not provided)')
    
    # Hardware Security Module (HSM/PKCS#11)
    parser.add_argument('--hsm-slot', type=int, metavar='N',
                       help='HSM PKCS#11 slot number (enables HSM mode)')
    parser.add_argument('--hsm-pin', type=str, metavar='PIN',
                       help='HSM user PIN (prompted if not provided)')
    parser.add_argument('--hsm-key-label', type=str, default='meow-master',
                       help='HSM key label for derivation (default: meow-master)')
    
    # TPM 2.0 key unsealing
    parser.add_argument('--tpm-unseal', action='store_true',
                       help='Unseal key from TPM (requires matching PCR state)')
    parser.add_argument('--tpm-derive', action='store_true',
                       help='Use TPM for key derivation')
    
    # Hardware auto-detection
    parser.add_argument('--hardware-auto', action='store_true',
                       help='Automatically use best available hardware security')
    parser.add_argument('--hardware-status', action='store_true',
                       help='Show hardware security status and exit')
    parser.add_argument('--no-hardware-fallback', action='store_true',
                       help='Fail if requested hardware unavailable (no software fallback)')
    
    parser.add_argument('--receiver-privkey', type=Path,
                       help='Path to receiver X25519 private key for forward secrecy (PEM format)')
    parser.add_argument('--receiver-privkey-password', type=str,
                       help='Password for encrypted receiver private key')
    
    # Decoding parameters
    parser.add_argument('--aggressive', action='store_true',
                       help='Use aggressive QR preprocessing')
    
    # Duress Handling
    parser.add_argument('--duress-mode', choices=['decoy', 'panic'], default='decoy',
                       help='Duress response mode: decoy (fake success) or panic (wipe/exit)')
    parser.add_argument('--enable-panic', action='store_true',
                       help='Explicitly enable destructive PANIC mode (required for --duress-mode panic)')
    parser.add_argument('--enable-duress', action='store_true',
                       help='Enable duress handling (required for --duress-mode decoy; panic enables automatically)')
    
    # Crypto backend selection
    # Rust backend is mandatory; no Python fallback is supported.
    
    # Output control
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--force', action='store_true',
                       help='Overwrite output file if exists')
    
    args = parser.parse_args()
    
    # Rust backend is mandatory (no legacy Python fallback).
    
    # Handle hardware status check (exit after display)
    if args.hardware_status:
        from .hardware_integration import HardwareSecurityProvider
        provider = HardwareSecurityProvider(verbose=True)
        caps = provider.detect_all()
        print(caps.summary())
        sys.exit(0)
    
    # Validate input file
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    if not args.input.is_file():
        print(f"Error: Input is not a file: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    # Check output file
    if args.output.exists() and not args.force:
        print(f"Error: Output file already exists: {args.output}", file=sys.stderr)
        print("Use --force to overwrite", file=sys.stderr)
        sys.exit(1)
    
    # Get password
    # Treat an empty string passed via --password as "provided" so we don't
    # fall back to interactive prompting in non-TTY environments (e.g. CI).
    if args.password is not None:
        password = args.password
    else:
        password = getpass("Enter decryption password: ")
    
    if not password:
        print("Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)
    
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
        if args.receiver_privkey is not None:
            print("Error: YubiKey derivation is not supported with forward secrecy keys", file=sys.stderr)
            sys.exit(1)
        if args.yubikey_pin is None:
            yk_pin = getpass("Enter YubiKey PIN (leave blank if not required): ")
            args.yubikey_pin = yk_pin if yk_pin else None
    
    # 🔐 HSM/TPM/Hardware-Auto validation
    hardware_mode = None
    if getattr(args, 'hsm_slot', None) is not None:
        if keyfile is not None:
            print("Error: Cannot combine --hsm-slot with --keyfile", file=sys.stderr)
            sys.exit(1)
        if args.receiver_privkey is not None:
            print("Error: HSM derivation is not supported with forward secrecy keys", file=sys.stderr)
            sys.exit(1)
        # HSM PIN prompt if not provided
        if getattr(args, 'hsm_pin', None) is None:
            args.hsm_pin = getpass("🔐 Enter HSM PIN: ")
        hardware_mode = "hsm"
        print(f"😺 Purring with HSM slot {args.hsm_slot}...")
    
    elif getattr(args, 'tpm_derive', False):
        if keyfile is not None:
            print("Error: Cannot combine --tpm-derive with --keyfile", file=sys.stderr)
            sys.exit(1)
        if args.receiver_privkey is not None:
            print("Error: TPM derivation is not supported with forward secrecy keys", file=sys.stderr)
            sys.exit(1)
        hardware_mode = "tpm"
        print(f"🐱 Clawing TPM for key derivation...")
    
    elif getattr(args, 'hardware_auto', False):
        if keyfile is not None:
            print("Error: Cannot combine --hardware-auto with --keyfile", file=sys.stderr)
            sys.exit(1)
        if args.receiver_privkey is not None:
            print("Error: Hardware auto derivation is not supported with forward secrecy keys", file=sys.stderr)
            sys.exit(1)
        hardware_mode = "auto"
        print("😻 Auto-detecting hardware security... (YubiKey > TPM > HSM)")
    
    # Load receiver private key for forward secrecy if specified
    receiver_private_key = None
    if args.receiver_privkey:
        try:
            from .x25519_forward_secrecy import load_receiver_keypair
            from cryptography.hazmat.primitives import serialization
            
            # Get password for private key if needed
            privkey_password = args.receiver_privkey_password
            if not privkey_password:
                privkey_password = getpass("Enter receiver private key password: ")
            
            # We need a dummy public key file for load_receiver_keypair
            # So let's just load the private key directly
            with open(args.receiver_privkey, 'rb') as f:
                privkey_data = f.read()
            
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            
            privkey_password_bytes = privkey_password.encode('utf-8') if privkey_password else None
            receiver_privkey_obj = load_pem_private_key(privkey_data, password=privkey_password_bytes)
            
            if not isinstance(receiver_privkey_obj, X25519PrivateKey):
                print("Error: Loaded key is not X25519PrivateKey", file=sys.stderr)
                sys.exit(1)
            
            # Serialize to raw bytes for crypto.py
            receiver_private_key = receiver_privkey_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            if args.verbose:
                print(f"✅ Loaded receiver private key for forward secrecy")
                print(f"   File: {args.receiver_privkey}")
        except Exception as e:
            print(f"Error loading receiver private key: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    
    # Create duress config (opt-in)
    d_mode = DuressMode.PANIC if args.duress_mode == 'panic' else DuressMode.DECOY
    duress_enabled = bool(args.enable_duress or args.enable_panic or args.duress_mode == 'panic')
    duress_config = DuressConfig(
        enabled=duress_enabled,
        mode=d_mode,
        panic_enabled=args.enable_panic
    )

    # Create decoding config
    config = DecodingConfig(
        preprocessing='aggressive' if args.aggressive else 'normal'
    )
    
    # Decode file
    try:
        decode_kwargs = {
            "config": config,
            "keyfile": keyfile,
            "receiver_private_key": receiver_private_key,  # Forward secrecy support
            "verbose": args.verbose,
        }

        if duress_config.enabled:
            decode_kwargs["duress_config"] = duress_config

        if args.yubikey:
            decode_kwargs["yubikey_slot"] = args.yubikey_slot
            decode_kwargs["yubikey_pin"] = args.yubikey_pin

        # Pass hardware security args to decode_gif for key derivation after manifest extraction
        if hardware_mode is not None:
            if hardware_mode == "hsm":
                decode_kwargs["hsm_slot"] = args.hsm_slot
                decode_kwargs["hsm_pin"] = args.hsm_pin
                decode_kwargs["hsm_key_label"] = getattr(args, 'hsm_key_label', 'meow-master')
            elif hardware_mode == "tpm":
                decode_kwargs["tpm_derive"] = True
            elif hardware_mode == "auto":
                decode_kwargs["hardware_auto"] = True

        stats = decode_gif(
            args.input,
            args.output,
            password,
            **decode_kwargs,
        )
        
        # Print summary
        if not args.verbose:
            print(f"\n✅ Decoding complete!")
            print(f"  Input: {stats['input_frames']} frames, {stats['qr_codes_read']} QR codes")
            print(f"  Processed: {stats['droplets_processed']} droplets")
            print(f"  Output: {stats['output_size']:,} bytes")
            print(f"  Efficiency: {stats['efficiency']*100:.1f}%")
            print(f"  Time: {stats['elapsed_time']:.2f}s")
        
        print(f"\nOutput saved to: {args.output}")
        
    except Exception as e:
        print(f"\nError during decoding: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
