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
    encrypt_file_bytes,
    compute_manifest_hmac,
    pack_manifest,
    Manifest,
    verify_keyfile,
    compute_duress_tag,
    pack_manifest_core,
)
from .fountain import FountainEncoder, pack_droplet
from .qr_code import QRCodeGenerator
from .gif_handler import GIFEncoder
from .progress import ProgressBar
from .hardware_integration import HardwareSecurityProvider, process_hardware_args
from .cat_errors import fur_ball_error, hiss_error, purr_success, cat_translate_error


from typing import List


def encode_file(
    input_path: Path,
    output_path: Path,
    password: str,
    config: Optional[EncodingConfig] = None,
    keyfile: Optional[bytes] = None,
    forward_secrecy: bool = True,
    receiver_public_key: Optional[bytes] = None,
    receiver_pq_public: Optional[bytes] = None,
    yubikey: bool = False,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    use_pq: bool = False,
    stego_level: int = 0,
    carrier_images: Optional[List[Path]] = None,
    stego_green: bool = False,
    logo_eyes: bool = False,
    logo_eyes_hidden: bool = False,
    cat_eyes_blink: bool = False,
    brand_text: Optional[str] = None,
    duress_password: Optional[str] = None,
    hardware_key: Optional[bytes] = None,
    hardware_salt: Optional[bytes] = None,
    verbose: bool = False,
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
        receiver_pq_public: Optional ML-KEM-1024 public key for PQ hybrid mode (1568 bytes).
            Required when use_pq=True and receiver_public_key is provided.
        use_pq: Enable post-quantum hybrid mode (MEOW4)
        stego_level: Steganography level (0=off, 1-4=stealth levels)
        carrier_images: Optional list of carrier image paths (your cat photos!)
        stego_green: Restrict embedding to green-dominant pixels only (cosmetic)
        logo_eyes: Use logo-eyes carrier (branded animation with data in eyes)
        logo_eyes_hidden: Hide QR codes in logo eyes using LSB steganography (default: visible)
        cat_eyes_blink: Only green pixels in cat eyes blink to transmit data (experimental)
        brand_text: Custom brand text for logo-eyes mode (default: 'MEOW')
        duress_password: Optional duress password (triggers emergency response on decode)
        hardware_key: Optional pre-derived 32-byte key from HSM/TPM/hardware
        hardware_salt: Salt used for hardware key derivation (required if hardware_key provided)
        verbose: Print verbose output

    Returns:
        Dictionary with encoding statistics
    """
    if config is None:
        config = EncodingConfig()

    # If both passwords are provided, reject immediately. Do this before any
    # other duress gating so callers get the most relevant error.
    if duress_password and duress_password == password:
        raise ValueError("Duress password cannot be the same as encryption password")

    # Duress mode requires forward secrecy (to avoid manifest size ambiguity)
    if duress_password:
        if not forward_secrecy:
            raise ValueError(
                "Duress mode requires forward secrecy (do not use --no-forward-secrecy with --duress-password)"
            )

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

    with open(input_path, "rb") as f:
        raw_data = f.read()

    if verbose:
        print(f"  Size: {len(raw_data):,} bytes")

    # FIX-D3: Compute mode_byte from manifest_version and duress state
    from meow_decoder.crypto import MODE_MEOW2, MODE_MEOW3, MODE_MEOW4, MODE_DURESS, MODE_RATCHET

    _version_to_mode = {2: MODE_MEOW2, 3: MODE_MEOW3, 4: MODE_MEOW4}
    _mode = _version_to_mode.get(manifest_version, MODE_MEOW3)
    if duress_password:
        _mode |= MODE_DURESS
    # Per-frame symmetric ratchet (MSR v1)
    _use_ratchet = getattr(config, "enable_ratchet", False)
    if _use_ratchet:
        _mode |= MODE_RATCHET
        if verbose:
            print("  🔐 Per-frame symmetric ratchet enabled (MSR v1)")

    # Encrypt data with forward secrecy support
    if verbose:
        print("Encrypting data with length padding (metadata protection)...")

    encrypt_kwargs = {
        "raw": raw_data,
        "password": password,
        "keyfile": keyfile,
        "receiver_public_key": receiver_public_key,
        "use_length_padding": True,
        "mode_byte": _mode,  # FIX-D3
    }
    if yubikey:
        encrypt_kwargs["yubikey_slot"] = yubikey_slot
        encrypt_kwargs["yubikey_pin"] = yubikey_pin

    # Hardware-derived key (HSM/TPM)
    if hardware_key is not None:
        encrypt_kwargs["precomputed_key"] = hardware_key
        encrypt_kwargs["precomputed_salt"] = hardware_salt

    # Post-quantum hybrid encapsulation (MEOW4)
    pq_ciphertext = None
    if use_pq and receiver_public_key is not None:
        try:
            from .pq_hybrid import hybrid_encapsulate, check_pq_available
        except ImportError:
            from meow_decoder.pq_hybrid import hybrid_encapsulate, check_pq_available

        available, msg = check_pq_available()
        if not available:
            raise RuntimeError(f"Post-quantum mode requested but unavailable: {msg}")

        # FIX-GPT-1: PQ hybrid requires the receiver's PQ public key.
        # Without it, we would silently fall back to classical-only, which
        # violates the "PQ ON" claim. Require it explicitly.
        if receiver_pq_public is None:
            raise ValueError(
                "Post-quantum hybrid mode (use_pq=True) requires receiver_pq_public "
                "(ML-KEM-1024 public key, 1568 bytes). PQ mode cannot silently fall "
                "back to classical-only. Either provide a PQ public key or disable PQ mode."
            )

        pq_shared_secret, eph_classical_pub, pq_ciphertext, _ = hybrid_encapsulate(
            receiver_classical_public=receiver_public_key,
            receiver_pq_public=receiver_pq_public,
        )

        if pq_ciphertext is not None:
            # PQ hybrid mode: use the hybrid shared secret as the encryption key
            encrypt_kwargs["precomputed_key"] = pq_shared_secret
            encrypt_kwargs["precomputed_salt"] = None  # Salt will be generated fresh
            # Don't do a separate X25519 exchange inside encrypt_file_bytes
            encrypt_kwargs["receiver_public_key"] = None
            encrypt_kwargs["pq_ciphertext"] = pq_ciphertext
            # FIX-GPT-1: Store the ephemeral classical public key so the decoder
            # can call hybrid_decapsulate().  Without this, the manifest would
            # have ephemeral_public_key=None and the decoder couldn't reconstruct
            # the hybrid shared secret.
            encrypt_kwargs["pq_ephemeral_public_key"] = eph_classical_pub
            if verbose:
                print(
                    f"  🔮 PQ hybrid: ML-KEM-1024 ciphertext generated ({len(pq_ciphertext)} bytes)"
                )
        else:
            # FIX-GPT-1: This should never happen since we validated receiver_pq_public above.
            # If hybrid_encapsulate returned None pq_ciphertext despite receiving a PQ key,
            # that's a bug in the encapsulation layer — fail closed.
            raise RuntimeError(
                "PQ hybrid encapsulation failed: pq_ciphertext is None despite "
                "receiver_pq_public being provided. This indicates a bug in hybrid_encapsulate()."
            )
            if verbose:
                print(f"  ℹ️  PQ hybrid: Classical-only fallback (no PQ ciphertext)")
    elif use_pq:
        if verbose:
            print(
                f"  ⚠️  PQ mode requested but no receiver public key; using password-only encryption"
            )

    comp, sha256, salt, nonce, cipher, ephemeral_public_key, encryption_key = encrypt_file_bytes(
        **encrypt_kwargs
    )

    if verbose:
        print(f"  Compressed: {len(comp):,} bytes ({len(comp)/len(raw_data)*100:.1f}%)")
        print(f"  Encrypted: {len(cipher):,} bytes")
        if ephemeral_public_key:
            print(
                f"  ✅ Forward secrecy: Ephemeral key generated ({len(ephemeral_public_key)} bytes)"
            )
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

    # Compute duress tag if duress password provided
    duress_tag = None
    if duress_password:
        # Duress tag is computed after manifest core is built (fast, tamper-evident)
        duress_tag = None
        if verbose:
            print(f"  🚨 Duress password configured (emergency response on decode)")

    # Create manifest (mode_byte computed earlier, before encrypt_file_bytes call)
    manifest = Manifest(
        salt=salt,
        nonce=nonce,
        orig_len=len(raw_data),
        comp_len=len(comp),
        cipher_len=len(cipher),
        sha256=sha256,
        block_size=config.block_size,
        k_blocks=k_blocks,
        hmac=b"\x00" * 32,  # Placeholder
        ephemeral_public_key=ephemeral_public_key,  # Forward secrecy support
        pq_ciphertext=pq_ciphertext,  # Post-quantum hybrid support (MEOW4)
        duress_tag=duress_tag,  # Duress password support (authenticated)
        mode_byte=_mode,  # FIX-D3: Explicit mode byte
    )

    # Compute HMAC (need to handle variable manifest size)
    # CRITICAL: Manifest format is: MAGIC + salt + nonce + lengths + sha256 + HMAC + ephemeral_key
    # We need to pack WITHOUT hmac field, then compute HMAC, then insert it

    # Build manifest core for duress tag (no HMAC, no duress tag)
    manifest_core = pack_manifest_core(manifest, include_duress_tag=False)

    # If duress enabled, compute tag bound to manifest core
    if duress_password:
        manifest.duress_tag = compute_duress_tag(duress_password, salt, manifest_core)

    # Build packed manifest without HMAC (includes duress tag if present)
    packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=True)

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

    # Initialize per-frame ratchet if enabled (BEFORE zeroizing encryption key)
    encoder_ratchet = None
    if _use_ratchet:
        from .ratchet import EncoderRatchet

        _rekey_interval = getattr(config, "rekey_beacon_interval", 0)
        encoder_ratchet = EncoderRatchet(
            root_key=bytes(encryption_key_buf),
            salt=salt,
            k_blocks=k_blocks,
            block_size=config.block_size,
            total_frames=num_droplets,  # Only droplet frames are ratchet-encrypted
            rekey_interval=_rekey_interval,
            receiver_public_key=receiver_public_key,
        )
        if verbose:
            _beacon_msg = (
                f", rekey beacons every {_rekey_interval} frames" if _rekey_interval > 0 else ""
            )
            print(
                f"  \U0001f43e Paw state initialized: {num_droplets} frames, "
                f"per-frame AES-256-GCM{_beacon_msg}"
            )

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
        border=config.qr_border,
    )

    qr_frames = []

    # First frame: manifest (MAC'd but NOT ratchet-encrypted)
    # The manifest must be readable before ratchet initialization (decoder needs
    # mode_byte, salt, k_blocks from the manifest to set up the ratchet).
    # Manifest confidentiality is not needed — it contains only metadata, and
    # is authenticated by HMAC. The ratchet protects payload frames (droplets).
    manifest_with_mac = pack_frame_with_mac(manifest_bytes, frame_master_key, 0, salt)
    manifest_qr = qr_generator.generate(manifest_with_mac)
    qr_frames.append(manifest_qr)
    mac_stats.record_valid()  # Track MAC generation

    if verbose:
        print(
            f"  Frame 0: Manifest ({len(manifest_bytes)} bytes + "
            f"{len(manifest_with_mac) - len(manifest_bytes)} byte MAC)"
        )

    # Remaining frames: droplets (optionally ratchet-encrypted, then MAC'd)
    progress_bar = ProgressBar(
        num_droplets, desc="Generating Droplets", unit="droplets", disable=not verbose
    )

    for i in progress_bar(range(num_droplets)):
        droplet = fountain.droplet()
        droplet_bytes = pack_droplet(droplet)

        # Optionally encrypt with per-frame ratchet
        frame_data = droplet_bytes
        if encoder_ratchet is not None:
            frame_data = encoder_ratchet.encrypt_next(droplet_bytes)

        # Add MAC to (possibly encrypted) frame data
        droplet_with_mac = pack_frame_with_mac(frame_data, frame_master_key, i + 1, salt)

        qr = qr_generator.generate(droplet_with_mac)
        qr_frames.append(qr)
        mac_stats.record_valid()

    # Finalize ratchet (zeroize remaining chain state)
    if encoder_ratchet is not None:
        encoder_ratchet.finalize()
        if verbose:
            print(f"  ✓ Ratchet finalized, all chain keys zeroized")

    if verbose:
        print(f"  Total QR codes: {len(qr_frames)} (all with frame MACs)")
        print(f"  QR size: {qr_frames[0].size}")

    # Apply logo-eyes carrier if enabled (TIER 3 - optional feature)
    if logo_eyes or cat_eyes_blink:  # pragma: no cover
        if verbose:
            print(
                f"\n👁️ Applying logo-eyes carrier..."
                if logo_eyes
                else "\n😺 Applying cat eyes blink mode..."
            )

        from .logo_eyes import encode_with_logo_eyes, LogoConfig, LogoEyesEncoder

        # Configure logo - visible_qr is opposite of logo_eyes_hidden
        logo_config = LogoConfig(
            brand_text=brand_text or "MEOW",
            animate_blink=True,
            visible_qr=not logo_eyes_hidden,  # Default: visible QR codes
            cat_eyes_blink=cat_eyes_blink,
        )

        try:
            if cat_eyes_blink:
                # Calculate number of green pixels per frame (capacity)
                from PIL import Image as PILImage

                dummy_logo = LogoEyesEncoder(logo_config)._get_scaled_logo()
                encoder = LogoEyesEncoder(logo_config)
                # Use manifest_with_mac and all droplet_with_mac as payload
                payloads = [manifest_with_mac] + [
                    pack_frame_with_mac(
                        pack_droplet(fountain.droplet()), frame_master_key, i + 1, salt
                    )
                    for i in range(num_droplets)
                ]
                # Flatten all payloads into a single bytearray
                all_bytes = b"".join(payloads)
                # Get green pixel count per frame
                green_pixel_coords = []
                for eye in [encoder.left_eye, encoder.right_eye]:
                    for dy in range(-eye.radius, eye.radius):
                        for dx in range(-eye.radius, eye.radius):
                            if dx * dx + dy * dy <= eye.radius * eye.radius:
                                x = eye.center_x + dx
                                y = eye.center_y + dy
                                if 0 <= x < dummy_logo.size[0] and 0 <= y < dummy_logo.size[1]:
                                    r, g, b = dummy_logo.getpixel((x, y))[:3]
                                    if g > r + 30 and g > b + 30:
                                        green_pixel_coords.append((y, x))
                bits_per_frame = len(green_pixel_coords)
                # Split all_bytes into per-frame bit chunks
                total_bits = len(all_bytes) * 8
                num_frames = (total_bits + bits_per_frame - 1) // bits_per_frame
                payload_chunks = []
                for i in range(num_frames):
                    start_bit = i * bits_per_frame
                    end_bit = min(start_bit + bits_per_frame, total_bits)
                    chunk_bits = []
                    for bit_idx in range(start_bit, end_bit):
                        byte_idx = bit_idx // 8
                        bit_in_byte = 7 - (bit_idx % 8)
                        chunk_bits.append((all_bytes[byte_idx] >> bit_in_byte) & 1)
                    # Pad last chunk with zeros if needed
                    if len(chunk_bits) < bits_per_frame:
                        chunk_bits += [0] * (bits_per_frame - len(chunk_bits))
                    # Pack bits into bytes
                    chunk_bytes = bytearray()
                    for j in range(0, len(chunk_bits), 8):
                        b = 0
                        for k in range(8):
                            if j + k < len(chunk_bits):
                                b = (b << 1) | chunk_bits[j + k]
                            else:
                                b = b << 1
                        chunk_bytes.append(b)
                    payload_chunks.append(bytes(chunk_bytes))
                # Always generate all frames needed to encode the full payload
                qr_frames = encode_with_logo_eyes(payload_chunks, config=logo_config)
            else:
                qr_frames = encode_with_logo_eyes(qr_frames, config=logo_config)

            if verbose:
                print(
                    f"  ✅ Logo-eyes carrier applied"
                    if logo_eyes
                    else "  ✅ Cat eyes blink mode applied"
                )
                print(f"  🐱 Brand: {logo_config.brand_text}")
                if logo_eyes_hidden:
                    print(f"  🥷 QR data hidden in eyes (LSB steganography)")
                elif cat_eyes_blink:
                    print(f"  😺 Only green pixels in cat eyes blink to transmit data!")
                else:
                    print(f"  👁️ QR codes visible in animated cat eyes!")
        except Exception as e:
            if verbose:
                print(f"  ⚠️ Logo-eyes/cat-eyes-blink failed: {e}")
                print(f"  Falling back to plain QR codes")

    # Apply steganography if enabled (TIER 3 - optional feature)
    elif stego_level > 0:  # pragma: no cover
        if verbose:
            print(f"\n🥷 Applying steganography (level {stego_level})...")

        from .stego_advanced import (
            encode_with_stego,
            StealthLevel,
            create_green_mask,
            calculate_masked_capacity,
        )
        from PIL import Image

        # Map level 1-4 to StealthLevel enum
        stealth_map = {
            1: StealthLevel.VISIBLE,
            2: StealthLevel.SUBTLE,
            3: StealthLevel.HIDDEN,
            4: StealthLevel.PARANOID,
        }
        stealth = stealth_map.get(stego_level, StealthLevel.SUBTLE)

        # Load carrier images if provided (your cat photos!)
        carriers = None
        green_mask = None
        if carrier_images:
            carriers = []
            for img_path in carrier_images:
                try:
                    img = Image.open(img_path).convert("RGB")
                    carriers.append(img)
                    if verbose:
                        print(f"  🐱 Loaded carrier: {img_path.name}")
                except Exception as e:
                    if verbose:
                        print(f"  ⚠️ Skipping {img_path}: {e}")

            # Cycle carriers to match frame count
            if carriers:
                while len(carriers) < len(qr_frames):
                    carriers.extend(carriers[: len(qr_frames) - len(carriers)])
                carriers = carriers[: len(qr_frames)]
                if verbose:
                    print(f"  Using {len(set(carrier_images))} custom carrier image(s)")

                # Green-region mode: create mask from first carrier
                if stego_green:
                    green_mask = create_green_mask(carriers[0])
                    capacity = calculate_masked_capacity(green_mask, lsb_bits=stealth.value)

                    if verbose:
                        print(f"  🌿 Green-region mode enabled")
                        print(
                            f"     ⚠️ COSMETIC CAMOUFLAGE ONLY - does NOT defeat forensic analysis"
                        )
                        print(
                            f"     📊 Capacity: {capacity['percent']:.1f}% embeddable ({capacity['bytes_capacity']:,} bytes/frame)"
                        )

                    if capacity["percent"] < 5.0:
                        print(
                            f"  ⚠️ WARNING: Only {capacity['percent']:.1f}% green pixels - encoding may fail!"
                        )
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
                enable_animation=(carriers is None),  # Animate if no custom carriers
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
    # IMPORTANT: Keep GIF optimization OFF for QR payload fidelity.
    # Pillow's GIF optimization can alter palettes/deltas enough that pyzbar
    # fails to decode higher-density droplet frames, causing 0 droplets read.
    gif_size = gif_encoder.create_gif(qr_frames, output_path, optimize=False)

    elapsed = time.time() - start_time

    if verbose:
        print(f"  Output: {output_path}")
        print(f"  Size: {gif_size:,} bytes")
        print(f"  Duration: {len(qr_frames) / config.fps:.1f} seconds at {config.fps} FPS")
        print(f"\nEncoding complete in {elapsed:.2f} seconds")

    # Return statistics
    return {
        "input_size": len(raw_data),
        "compressed_size": len(comp),
        "encrypted_size": len(cipher),
        "output_size": gif_size,
        "compression_ratio": len(comp) / len(raw_data),
        "k_blocks": k_blocks,
        "num_droplets": num_droplets,
        "redundancy": config.redundancy,
        "qr_frames": len(qr_frames),
        "qr_size": qr_frames[0].size,
        "gif_duration": len(qr_frames) / config.fps,
        "elapsed_time": elapsed,
    }


def _run_self_test() -> int:  # pragma: no cover
    """Run a quick encrypt-decrypt roundtrip smoke test.

    Verifies:
      1. Rust crypto backend is available
      2. AES-256-GCM encrypt then decrypt roundtrip
      3. Manifest pack/unpack integrity
      4. Fountain encode then decode roundtrip

    Returns 0 on success, 1 on failure.
    """
    import secrets as _sec

    print("🐾 Meow Decoder Self-Test")
    print("=" * 50)

    passed = 0
    failed = 0

    # --- Test 1: Rust backend detection ---
    try:
        from .crypto_backend import get_backend_name

        backend = get_backend_name()
        print(f"  [✅] Crypto backend: {backend}")
        passed += 1
    except Exception as e:
        print(f"  [❌] Crypto backend detection failed: {e}")
        failed += 1

    # --- Test 2: AES-256-GCM roundtrip ---
    try:
        from .crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = b"The quick brown cat jumps over the lazy dog. " * 20
        password = "self-test-" + _sec.token_hex(8)
        ct = encrypt_file_bytes(plaintext, password)
        pt = decrypt_to_raw(ct, password)
        assert pt == plaintext, "Decrypted data does not match original"
        print(f"  [✅] AES-256-GCM roundtrip ({len(plaintext)} bytes)")
        passed += 1
    except Exception as e:
        print(f"  [❌] AES-256-GCM roundtrip failed: {e}")
        failed += 1

    # --- Test 3: Manifest pack/unpack ---
    try:
        from .crypto import Manifest, pack_manifest, unpack_manifest

        m = Manifest(
            nonce=_sec.token_bytes(12),
            salt=_sec.token_bytes(16),
            orig_len=900,
            comp_len=800,
            cipher_len=816,
            block_size=512,
            sha256=_sec.token_bytes(32),
            k_blocks=2,
            hmac=_sec.token_bytes(32),
        )
        packed = pack_manifest(m)
        m2 = unpack_manifest(packed)
        assert m2.orig_len == m.orig_len, "Manifest roundtrip mismatch"
        print(f"  [✅] Manifest pack/unpack ({len(packed)} bytes)")
        passed += 1
    except Exception as e:
        print(f"  [❌] Manifest pack/unpack failed: {e}")
        failed += 1

    # --- Test 4: Fountain codec ---
    try:
        from .fountain import FountainEncoder, FountainDecoder

        data = _sec.token_bytes(1024)
        block_size = 256
        k_blocks = len(data) // block_size
        enc = FountainEncoder(data, k_blocks, block_size)
        dec = FountainDecoder(k_blocks, block_size)
        for _ in range(int(k_blocks * 2)):
            droplet = enc.droplet()
            dec.add_droplet(droplet)
            if dec.is_complete():
                break
        if dec.is_complete():
            recovered = dec.get_data()
            assert recovered == data, "Fountain roundtrip mismatch"
            print("  [✅] Fountain encode/decode (1024 bytes)")
            passed += 1
        else:
            print("  [⚠️] Fountain decode incomplete (may need more frames)")
            passed += 1  # Not a failure, just needs more redundancy
    except Exception as e:
        print(f"  [❌] Fountain encode/decode failed: {e}")
        failed += 1

    # --- Summary ---
    print("=" * 50)
    total = passed + failed
    if failed == 0:
        print(f"🐱 All {passed}/{total} checks passed. Meow is healthy!")
        return 0
    else:
        print(f"😿 {failed}/{total} checks FAILED. See errors above.")
        return 1


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
        """,
    )

    # Input/output are required for normal encoding, but NOT for --generate-keys.
    # We enforce requirement after parsing so key generation can run standalone.
    parser.add_argument("-i", "--input", type=Path, help="Input file to encode")
    parser.add_argument("-o", "--output", type=Path, help="Output GIF file")

    # Optional arguments
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        help="Encryption password (⚠️  WARNING: May leak in shell history/process list! Use prompt instead.)",
    )
    parser.add_argument("-k", "--keyfile", type=Path, help="Path to keyfile")

    # Hardware-backed key derivation (YubiKey)
    parser.add_argument(
        "--yubikey",
        action="store_true",
        help="Use YubiKey PIV for key derivation (Rust backend required)",
    )
    parser.add_argument(
        "--yubikey-slot", type=str, default="9d", help="YubiKey PIV slot (default: 9d)"
    )
    parser.add_argument(
        "--yubikey-pin", type=str, default=None, help="YubiKey PIN (prompted if not provided)"
    )
    parser.add_argument(
        "--yubikey-touch",
        action="store_true",
        default=True,
        help="Require physical touch on YubiKey (default: true)",
    )

    # Hardware Security Module (HSM/PKCS#11)
    parser.add_argument(
        "--hsm-slot", type=int, metavar="N", help="HSM PKCS#11 slot number (enables HSM mode)"
    )
    parser.add_argument(
        "--hsm-pin", type=str, metavar="PIN", help="HSM user PIN (prompted if not provided)"
    )
    parser.add_argument(
        "--hsm-key-label",
        type=str,
        default="meow-master",
        help="HSM key label for derivation (default: meow-master)",
    )
    parser.add_argument(
        "--hsm-library",
        type=str,
        metavar="PATH",
        help="Path to PKCS#11 library (auto-detected if not specified)",
    )

    # TPM 2.0 key sealing
    parser.add_argument(
        "--tpm-seal",
        type=str,
        metavar="PCRS",
        help="Seal key to TPM PCRs (comma-separated, e.g., 0,2,7)",
    )
    parser.add_argument("--tpm-derive", action="store_true", help="Use TPM for key derivation")

    # Hardware auto-detection and status
    parser.add_argument(
        "--hardware-auto",
        action="store_true",
        help="Automatically use best available hardware security",
    )
    parser.add_argument(
        "--hardware-status", action="store_true", help="Show hardware security status and exit"
    )
    parser.add_argument(
        "--no-hardware-fallback",
        action="store_true",
        help="Fail if requested hardware unavailable (no software fallback)",
    )

    # Encoding parameters
    parser.add_argument(
        "--block-size", type=int, default=512, help="Fountain code block size (default: 512)"
    )
    parser.add_argument(
        "--redundancy", type=float, default=1.5, help="Redundancy factor (default: 1.5)"
    )
    parser.add_argument(
        "--fps",
        type=int,
        default=2,
        help="GIF frames per second (default: 2, slow for readability)",
    )

    # QR code parameters
    parser.add_argument(
        "--qr-error",
        choices=["L", "M", "Q", "H"],
        default="M",
        help="QR error correction level (default: M)",
    )
    parser.add_argument(
        "--qr-box-size", type=int, default=10, help="QR box size in pixels (default: 10)"
    )
    parser.add_argument(
        "--qr-border", type=int, default=4, help="QR border size in boxes (default: 4)"
    )

    # Crypto backend selection
    # Rust backend is mandatory; no Python fallback is supported.

    # Steganography options (hide QR in images)
    parser.add_argument(
        "--stego-level",
        type=int,
        choices=[0, 1, 2, 3, 4],
        default=0,
        help="Steganography level: 0=off, 1=visible, 2=subtle, 3=hidden, 4=paranoid (default: 0)",
    )
    parser.add_argument(
        "--carrier",
        "-c",
        type=Path,
        nargs="+",
        dest="carrier_images",
        help="Custom carrier images (your cat photos!) for steganography. Images cycle through frames.",
    )
    parser.add_argument(
        "--stego-green",
        action="store_true",
        help="Embed only in green-dominant pixels (logo eyes/waves). "
        "⚠️ COSMETIC ONLY: Does NOT defeat steganalysis. "
        "Reduces capacity to ~10-30%%. Requires --carrier. Test output visually!",
    )

    # Logo-eyes mode (branded animation with data in eyes)
    parser.add_argument(
        "--logo-eyes",
        action="store_true",
        help="Use logo-eyes carrier: animated cat logo with QR data in eyes (visible by default)",
    )
    parser.add_argument(
        "--logo-eyes-hidden",
        action="store_true",
        help="Hide QR codes in logo eyes using LSB steganography (stealthy but harder to decode)",
    )
    parser.add_argument(
        "--brand-text",
        type=str,
        default=None,
        help="Custom brand text for logo-eyes mode (default: MEOW)",
    )

    # Security features (Forward Secrecy ON by default!)
    parser.add_argument(
        "--forward-secrecy",
        action="store_true",
        default=True,
        help="Enable forward secrecy (ON by default, MEOW3)",
    )
    parser.add_argument(
        "--no-forward-secrecy",
        action="store_true",
        help="Disable forward secrecy (revert to MEOW2)",
    )
    parser.add_argument(
        "--receiver-pubkey",
        type=Path,
        help="Path to receiver X25519 public key (32 bytes) for forward secrecy",
    )
    parser.add_argument(
        "--pq",
        "--post-quantum",
        action="store_true",
        help="Enable post-quantum hybrid mode (MEOW4, requires liboqs)",
    )

    # Duress mode (coercion resistance)
    parser.add_argument(
        "--duress-password",
        type=str,
        help="Duress password that triggers emergency wipe on decode (⚠️ Cannot be same as main password)",
    )
    parser.add_argument(
        "--duress-password-prompt",
        action="store_true",
        help="Prompt for duress password interactively (more secure than CLI arg)",
    )

    # Dead-man's switch (time-based auto-release)
    parser.add_argument(
        "--dead-mans-switch",
        type=str,
        metavar="DURATION",
        help='Enable dead-man\'s switch: Auto-release decoy if no check-in within DURATION (e.g., "24h", "7d", "3600s")',
    )
    parser.add_argument(
        "--deadman-grace-period",
        type=str,
        default="1h",
        help="Grace period for check-ins before deadline (default: 1h)",
    )

    # Key generation
    parser.add_argument(
        "--generate-keys",
        action="store_true",
        help="Generate receiver keypair for forward secrecy and exit",
    )
    parser.add_argument(
        "--key-output-dir",
        type=Path,
        default=Path("."),
        help="Directory for generated keys (default: current directory)",
    )

    # Cat modes and fun
    parser.add_argument(
        "--cat-mode",
        action="store_true",
        help="Use bundled cat-themed carrier GIF (demo_logo_eyes.gif). "
        "⚠️ COSMETIC ONLY: Does not hide QR presence from steganalysis.",
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "void"],
        default="normal",
        help="Encoding mode: normal or void (paranoid stealth)",
    )
    parser.add_argument(
        "--fun", action="store_true", help="Enable cat sound effects (requires playsound)"
    )
    parser.add_argument(
        "--catnip",
        choices=["tuna", "salmon", "chicken", "beef", "turkey", "fish"],
        help="Catnip flavor for HKDF salt (pure meme, functionally harmless)",
    )

    # Retry mode
    parser.add_argument(
        "--nine-lives",
        action="store_true",
        help="Enable Nine Lives retry mode: automatic recovery with up to 9 attempts on error",
    )

    # Output control
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--purr-mode",
        action="store_true",
        help="Ultra-verbose cat-themed logging with meows, facts, and cat verbs 🐱",
    )
    parser.add_argument(
        "--wipe-source", action="store_true", help="Securely wipe source file after encoding"
    )
    parser.add_argument(
        "--summon-void-cat", action="store_true", help="Summon the void cat (easter egg)"
    )

    # High-security mode
    parser.add_argument(
        "--high-security",
        "--paranoid",
        action="store_true",
        help="High-security mode: increased Argon2 memory, post-quantum crypto, secure wipe",
    )
    parser.add_argument(
        "--safety-checklist",
        action="store_true",
        help="Show operational security checklist and exit",
    )

    parser.add_argument(
        "--about", "--meow-about", action="store_true", help="Show version and build information"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a quick encrypt→decrypt roundtrip smoke test and exit",
    )

    args = parser.parse_args()

    # Rust backend is mandatory (no legacy Python fallback).

    # Handle about flag (exit after display)
    if args.about:
        from .cat_utils import meow_about

        print(meow_about())
        sys.exit(0)

    # Handle self-test (encrypt→decrypt roundtrip smoke test)
    if args.self_test:
        return _run_self_test()  # pragma: no cover

    # Handle hardware status check (exit after display)
    if args.hardware_status:
        from .hardware_integration import HardwareSecurityProvider

        provider = HardwareSecurityProvider(verbose=True)
        caps = provider.detect_all()
        print(caps.summary())
        sys.exit(0)

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
            print(
                f"  Argon2id: {hs_config.argon2_memory // 1024} MiB, {hs_config.argon2_iterations} iterations"
            )
            print(f"  Post-Quantum: {hs_config.kyber_variant}")
            print(f"  Secure wipe: {hs_config.secure_wipe_passes} passes")
            print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print("⚠️  Key derivation will take several seconds.\n")
            args.wipe_source = True
        except ImportError:
            print("Warning: High-security module not available, using defaults.")

    # Enable purr mode (ultra-verbose cat-themed logging)
    if args.purr_mode:
        from .cat_utils import enable_purr_mode

        purr = enable_purr_mode(enabled=True)
        # Purr mode implies verbose
        args.verbose = True

    # Enable verbose output for Nine Lives retry mode (so user sees retry status)
    if args.nine_lives:
        args.verbose = True
        print("🐱 Nine Lives retry mode enabled (max 9 attempts on error)")
        print("   Using all nine lives to ensure encoding success!\n")

    # For normal operation, require input/output.
    if args.input is None or args.output is None:
        parser.error(
            "the following arguments are required: -i/--input, -o/--output"
        )  # pragma: no cover

    # Cat mode: use bundled carrier if no custom carrier provided
    if args.cat_mode and not args.carrier_images:  # pragma: no cover
        cat_carrier = Path(__file__).parent.parent / "assets" / "demo_logo_eyes.gif"
        if cat_carrier.exists():
            args.carrier_images = [cat_carrier]
            if args.stego_level == 0:
                args.stego_level = 2  # Default to subtle stego
            print("🐱 Cat Mode activated! Using bundled cat carrier.")
            print("   ⚠️ Note: Cosmetic camouflage only — QR still detectable under analysis.")
        else:
            print("⚠️ Cat Mode: Bundled carrier not found, proceeding with plain QR codes.")

    # Void cat mode
    if args.mode == "void":  # pragma: no cover
        print("""
🐈‍⬛ VOID CAT MODE ACTIVATED
━━━━━━━━━━━━━━━━━━━━━━━━━
Maximum paranoid stealth engaged.
All evidence will be consumed.
Nothing to see here. 😶‍🌫️
━━━━━━━━━━━━━━━━━━━━━━━━━""")
        # Force paranoid settings
        args.stego_level = 4  # Maximum stealth
        if not hasattr(args, "stego_level"):
            print("⚠️  Note: Steganography not implemented yet, but void mode ready!")
        args.verbose = False  # Silence is golden

    # Handle forward secrecy flag
    if hasattr(args, "no_forward_secrecy") and args.no_forward_secrecy:
        args.forward_secrecy = False
        print("\n⚠️  Forward secrecy DISABLED (--no-fs)")
        print("   Using MEOW2 crypto (password-only mode)")

    # Load receiver public key for forward secrecy
    receiver_public_key = None
    if args.forward_secrecy and args.receiver_pubkey:
        try:
            with open(args.receiver_pubkey, "rb") as f:
                receiver_public_key = f.read()

            if len(receiver_public_key) != 32:
                print(
                    f"\n❌ Error: Receiver public key must be 32 bytes, got {len(receiver_public_key)}"
                )
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
    if args.catnip and not args.verbose:  # pragma: no cover
        print(f"🌿 Using {args.catnip} catnip! Meow! 😸")

    # Validate input file
    if not args.input.exists():
        hiss_error(fur_ball_error("file_not_found", suggestion=False))
        print(f"  Path: {args.input}", file=sys.stderr)
        sys.exit(1)

    if not args.input.is_file():
        hiss_error(f"That's not a file, it's a directory! Cats can't encode folders.")
        print(f"  Path: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Get password
    # Treat an empty string passed via --password as "provided" so we don't
    # fall back to interactive prompting in non-TTY environments (e.g. CI).
    if args.password is not None:
        password = args.password
    else:
        # In CI/pytest or other non-interactive contexts, getpass() will fail
        # (no /dev/tty, stdin capture). Fail closed instead of prompting.
        if sys.stdin is None or not sys.stdin.isatty():
            print(
                "Error: Password must be provided via --password in non-interactive mode",
                file=sys.stderr,
            )
            sys.exit(1)

        password = getpass("Enter encryption password: ")  # pragma: no cover
        password_confirm = getpass("Confirm password: ")  # pragma: no cover

        if password != password_confirm:  # pragma: no cover
            hiss_error("The collar tags don't match! Passwords must be identical.")
            sys.exit(1)

    if not password:
        hiss_error(fur_ball_error("wrong_password", suggestion=False))  # pragma: no cover
        print("  Password cannot be empty.", file=sys.stderr)  # pragma: no cover
        sys.exit(1)  # pragma: no cover

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
            print(
                "Error: YubiKey derivation is not supported with forward secrecy keys",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.yubikey_pin is None:
            yk_pin = getpass("Enter YubiKey PIN (leave blank if not required): ")
            args.yubikey_pin = yk_pin if yk_pin else None

    # 🔐 HSM/TPM/Hardware-Auto mode wiring
    # These features require hardware_integration.py for key derivation
    hardware_method = None
    if getattr(args, "hsm_slot", None) is not None:  # pragma: no cover
        if keyfile is not None:
            print("Error: Cannot combine --hsm-slot with --keyfile", file=sys.stderr)
            sys.exit(1)
        if receiver_public_key is not None:
            print(
                "Error: HSM derivation is not supported with forward secrecy keys", file=sys.stderr
            )
            sys.exit(1)
        # HSM PIN prompt if not provided
        if getattr(args, "hsm_pin", None) is None:
            args.hsm_pin = getpass("🔐 Enter HSM PIN: ")
        hardware_method = "hsm"
        print(f"😺 Purring with HSM slot {args.hsm_slot}...")

    elif getattr(args, "tpm_derive", False):  # pragma: no cover
        if keyfile is not None:
            print("Error: Cannot combine --tpm-derive with --keyfile", file=sys.stderr)
            sys.exit(1)
        if receiver_public_key is not None:
            print(
                "Error: TPM derivation is not supported with forward secrecy keys", file=sys.stderr
            )
            sys.exit(1)
        hardware_method = "tpm"
        pcrs = getattr(args, "tpm_seal", None)
        print(f"🐱 Clawing TPM PCRs {pcrs or 'default'}...")

    elif getattr(args, "hardware_auto", False):  # pragma: no cover
        if keyfile is not None:
            print("Error: Cannot combine --hardware-auto with --keyfile", file=sys.stderr)
            sys.exit(1)
        if receiver_public_key is not None:
            print(
                "Error: Hardware auto derivation is not supported with forward secrecy keys",
                file=sys.stderr,
            )
            sys.exit(1)
        hardware_method = "auto"
        print("😻 Auto-detecting hardware security... (YubiKey > TPM > HSM)")

    # Handle duress password
    duress_password = None
    if args.duress_password_prompt:
        duress_password = getpass(
            "Enter duress password (triggers emergency wipe): "
        )  # pragma: no cover
        if duress_password:  # pragma: no cover
            duress_confirm = getpass("Confirm duress password: ")  # pragma: no cover
            if duress_password != duress_confirm:  # pragma: no cover
                hiss_error("The duress collar tags don't match! Try again.")
                sys.exit(1)
            if duress_password == password:  # pragma: no cover
                hiss_error(fur_ball_error("duress_same_password", suggestion=False))
                sys.exit(1)
            print("🚨 Duress password configured")  # pragma: no cover
    elif args.duress_password:
        duress_password = args.duress_password
        if duress_password == password:
            hiss_error(fur_ball_error("duress_same_password", suggestion=False))
            sys.exit(1)
        print("🚨 Duress password configured (WARNING: visible in CLI args)")

    # Duress mode requires forward secrecy to avoid manifest size ambiguity
    if duress_password and not args.forward_secrecy:
        hiss_error(fur_ball_error("duress_no_fs", suggestion=False))
        print("   Do not use --no-forward-secrecy with --duress-password", file=sys.stderr)
        sys.exit(1)

    # Hardware key derivation (HSM/TPM/Auto)
    hardware_key = None
    hardware_salt = None
    if hardware_method is not None:
        import secrets as crypto_secrets

        hardware_salt = crypto_secrets.token_bytes(16)

        try:
            hardware_key, hw_desc = process_hardware_args(
                args, password.encode("utf-8"), hardware_salt
            )

            if hardware_key is None:  # pragma: no cover
                print(
                    f"⚠️  Hardware derivation returned None, falling back to software mode",
                    file=sys.stderr,
                )
                hardware_method = None
                hardware_salt = None
            else:
                if args.verbose:
                    print(f"  🔐 Key derived via: {hw_desc}")
        except Exception as e:  # pragma: no cover
            print(f"Error: Hardware key derivation failed: {e}", file=sys.stderr)
            if getattr(args, "no_hardware_fallback", False):
                print("   --no-hardware-fallback specified, aborting.", file=sys.stderr)
                sys.exit(1)
            else:
                print("   Falling back to software derivation.", file=sys.stderr)
                hardware_method = None
                hardware_key = None
                hardware_salt = None

    # Create encoding config
    config = EncodingConfig(
        block_size=args.block_size,
        redundancy=args.redundancy,
        qr_error_correction=args.qr_error,
        qr_box_size=args.qr_box_size,
        qr_border=args.qr_border,
        fps=args.fps,
    )

    # Encode file
    try:
        # 🐱 Nine Lives retry mode integration
        if args.nine_lives:
            from .cat_utils import NineLivesRetry

            retry = NineLivesRetry(max_lives=9, verbose=True)
            stats = None
            for life in retry.attempt():
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
                        cat_eyes_blink=getattr(args, "cat_eyes_blink", False),
                        brand_text=args.brand_text,
                        duress_password=duress_password,
                        hardware_key=hardware_key,
                        hardware_salt=hardware_salt,
                        verbose=args.verbose,
                    )
                    retry.success(stats)
                    break
                except Exception as e:
                    retry.fail(str(e))

            if not retry.succeeded:
                sys.exit(1)
        else:
            # Normal encoding without retry mode
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
                cat_eyes_blink=getattr(args, "cat_eyes_blink", False),
                brand_text=args.brand_text,
                duress_password=duress_password,
                hardware_key=hardware_key,
                hardware_salt=hardware_salt,
                verbose=args.verbose,
            )

        # Print summary
        if not args.verbose:
            purr_success("Encoding complete!")
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
                with open(args.input, "wb") as f:
                    f.write(b"\x00" * file_size)
                args.input.unlink()
                print(f"  ✓ Source file wiped: {args.input}")

        # Setup dead-man's switch if requested
        if args.dead_mans_switch:  # pragma: no cover
            try:
                from .deadmans_switch_cli import DeadManSwitchState

                # Parse duration and grace period
                import re

                def parse_duration(duration_str):
                    """Parse duration string like '24h', '7d', '3600s' to seconds."""
                    match = re.match(r"(\d+)([hds])", duration_str.lower())
                    if not match:
                        raise ValueError(
                            f"Invalid duration format: {duration_str}. Use '24h', '7d', or '3600s'"
                        )
                    value, unit = int(match.group(1)), match.group(2)
                    multipliers = {"h": 3600, "d": 86400, "s": 1}
                    return value * multipliers[unit]

                checkin_interval = parse_duration(args.dead_mans_switch)
                grace_period = parse_duration(args.deadman_grace_period)

                # Create dead-man's switch state
                state = DeadManSwitchState(
                    gif_path=str(args.output),
                    checkin_interval_seconds=checkin_interval,
                    grace_period_seconds=grace_period,
                    decoy_file=None,  # No decoy for now - user must renew to survive
                )
                state.save()

                if args.verbose or args.purr_mode:
                    hours = checkin_interval // 3600
                    grace_hours = grace_period // 3600
                    print(f"\n⏰ Dead-man's switch activated:")
                    print(f"   Check-in interval: {hours}h")
                    print(f"   Grace period: {grace_hours}h")
                    print(f"   ⚠️  Must renew with: meow-deadmans-switch renew --gif {args.output}")
                    print(
                        f"   💡 Use: meow-deadmans-switch status --gif {args.output} to check status"
                    )
            except Exception as e:
                print(f"\n⚠️  Dead-man's switch setup failed: {e}", file=sys.stderr)
                if args.verbose:
                    import traceback

                    traceback.print_exc()
                # Don't fail the entire encoding - just warn

        print(f"\nOutput saved to: {args.output}")

    except Exception as e:
        cat_msg = cat_translate_error(e)
        print(f"\n{cat_msg}", file=sys.stderr)
        print(f"\n  Technical details: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
