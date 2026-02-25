#!/usr/bin/env python3
"""
Meow Decoder - GIF Decoder CLI
Decodes files from GIF animations
"""

import sys
import argparse
import struct
import os
from pathlib import Path
from getpass import getpass
from typing import Optional
import time

# Import core modules

from .config import MeowConfig, DecodingConfig, DuressConfig, DuressMode
from .crypto import (
    decrypt_to_raw_production,
    verify_manifest_hmac_production,
    derive_encryption_key_for_manifest_handle,
    unpack_manifest,
    verify_keyfile,
    check_duress_password,
    pack_manifest_core,
    validate_decode_profile,
    PROFILE_PQ_EXPERIMENTAL,
    PROFILE_LEGACY,
)
from .crypto_backend import get_handle_backend
from .fountain import FountainDecoder, unpack_droplet
from .qr_code import QRCodeReader
from .gif_handler import GIFDecoder
from .progress import ProgressBar

# hardware_integration is lazy-imported where needed to avoid pulling in
# cryptography at module-import time (see Step 2 of crypto migration).
from .cat_errors import fur_ball_error, hiss_error, purr_success, cat_translate_error
from .secure_keyboard import MouseGesturePassword, secure_password_input
from .tamper_report import TamperReport

MANIFEST_SIG_CHUNK_MAGIC = b"MSGC"
MANIFEST_SIG_BLOB_MAGIC = b"MSGB"
MANIFEST_SIG_VERSION = 1


def decode_gif(
    input_path: Path,
    output_path: Path,
    password: str,
    config: Optional[DecodingConfig] = None,
    duress_config: Optional[DuressConfig] = None,
    keyfile: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    receiver_pq_keypair=None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    hsm_slot: Optional[int] = None,
    hsm_pin: Optional[str] = None,
    hsm_key_label: Optional[str] = None,
    tpm_derive: bool = False,
    hardware_auto: bool = False,
    verbose: bool = False,
    tamper_report: Optional[TamperReport] = None,
    allow_experimental: bool = False,
    allow_legacy: bool = False,
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
        receiver_pq_keypair: Optional HybridKeyPair from pq_hybrid for PQ decapsulation.
            Required when the manifest contains pq_ciphertext (MEOW4 mode).
        precomputed_key: Optional pre-derived 32-byte key (HSM/TPM/hardware mode)
                        If provided, skips key derivation and uses this key
        hsm_slot: HSM PKCS#11 slot number (enables HSM mode)
        hsm_pin: HSM user PIN
        hsm_key_label: HSM key label for derivation
        tpm_derive: Use TPM for key derivation
        hardware_auto: Automatically use best available hardware security
        verbose: Print verbose output
        tamper_report: Optional TamperReport to populate with per-frame MAC results

    Returns:
        Dictionary with decoding statistics
    """
    if config is None:
        config = DecodingConfig()

    if duress_config is None:
        duress_config = DuressConfig()

    start_time = time.time()

    # Check for dead-man's switch (auto-release on deadline)
    try:  # pragma: no cover
        from .deadmans_switch_cli import DeadManSwitchState

        deadman_state_file = Path(input_path).parent / f".{Path(input_path).stem}.deadman.json"
        if deadman_state_file.exists():
            try:
                deadman_state = DeadManSwitchState.load(str(input_path))

                if deadman_state.is_deadline_passed():
                    if verbose:
                        print("\n⏰ DEAD-MAN'S SWITCH ACTIVATED!")
                        print(
                            f"   Deadline passed on: {deadman_state.state.get('next_deadline', 'unknown')}"
                        )
                        print(f"   Releasing decoy file instead of real data")

                    # Trigger decoy release
                    deadman_state.trigger()

                    # If a decoy file was configured, copy it to output
                    decoy_file = deadman_state.state.get("decoy_file")
                    if decoy_file and Path(decoy_file).exists():
                        with open(decoy_file, "rb") as f:
                            decoy_data = f.read()
                        with open(output_path, "wb") as f:
                            f.write(decoy_data)

                        if verbose:
                            print(
                                f"   Decoy file ({len(decoy_data):,} bytes) written to: {output_path}"
                            )

                        return {
                            "input_frames": 0,
                            "qr_codes_read": 0,
                            "droplets_processed": 0,
                            "blocks_decoded": 0,
                            "output_size": len(decoy_data),
                            "efficiency": 0.0,
                            "elapsed_time": time.time() - start_time,
                            "deadman_triggered": True,
                        }
            except Exception as e:
                if verbose:
                    print(f"⚠️  Dead-man's switch check failed: {e}")
                # Continue with normal decoding
    except ImportError:
        pass  # Dead-man's switch module not available

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

    # We'll derive the frame key after we get the manifest (which has the salt)
    # For now, just read QR codes raw
    qr_reader = QRCodeReader(preprocessing=config.preprocessing)
    qr_data_list = []
    # Track the original GIF frame index for each QR data entry.
    # Critical for frame MAC verification when stego extraction skips frames.
    qr_frame_indices = []

    progress = ProgressBar(
        len(frames), desc="Scanning QR Codes", unit="frames", disable=not verbose
    )

    for i, frame in enumerate(progress(frames)):
        qr_data = qr_reader.read_image(frame)

        if qr_data:
            for qd in qr_data:
                qr_data_list.append(qd)
                qr_frame_indices.append(i)
        elif verbose:
            # Only print warning if we're not using tqdm, or use tqdm write if available
            # But ProgressBar doesn't expose write yet.
            # For now, let's silence the warning to avoid breaking progress bar,
            # or we could just count them.
            pass

    if verbose:
        print(f"  Total QR codes read: {len(qr_data_list)}")

    if not qr_data_list:
        # --- Stego fallback: try LSB extraction at multiple depths ---
        if verbose:
            print("  ⚠️  No QR codes found directly; trying stego LSB extraction...")
        try:
            from .stego_advanced import decode_with_stego

            for lsb_bits in (2, 1, 3):
                extracted_frames = decode_with_stego(frames, lsb_bits=lsb_bits)
                for frame_idx, extracted in enumerate(extracted_frames):
                    qr_data = qr_reader.read_image(extracted)
                    if qr_data:
                        for qd in qr_data:
                            qr_data_list.append(qd)
                            qr_frame_indices.append(frame_idx)
                if qr_data_list:
                    if verbose:
                        print(
                            f"  ✅ Stego extraction succeeded (LSB depth={lsb_bits}): "
                            f"{len(qr_data_list)} QR codes recovered"
                        )
                    break
        except Exception as e:
            if verbose:
                print(f"  ⚠️  Stego extraction failed: {e}")

    if not qr_data_list:
        raise ValueError("No QR codes found in GIF")

    # First QR is manifest - try to unpack with MAC verification
    if verbose:
        print("\nParsing manifest with MAC verification...")

    # Try to parse manifest directly (it might not have MAC if it's old format)
    manifest_raw = qr_data_list[0]

    # CRITICAL: Verify manifest frame decoded correctly from QR/GIF
    # Legacy base (mode_byte=0): 115 bytes
    # New base (mode_byte!=0, FIX-D3): 116 bytes (+1 for mode_byte)
    # Optional trailers: ephemeral = +32, duress = +32, frame MAC = +8
    # PQ ciphertext: ML-KEM-768 = +1088, ML-KEM-1024 = +1568
    #
    # Legacy (mode_byte=0, backward compat):
    #   115, 123(+MAC), 147(+eph), 155(+eph+MAC), 179(+eph+dur), 187(+eph+dur+MAC)
    # New (mode_byte!=0):
    #   116, 124(+MAC), 148(+eph), 156(+eph+MAC), 180(+eph+dur), 188(+eph+dur+MAC)
    # PQ ML-KEM-768 (new only): 1236, 1244(+MAC), 1268(+dur), 1276(+dur+MAC)
    # PQ ML-KEM-1024 (new only): 1716, 1724(+MAC), 1748(+dur), 1756(+dur+MAC)
    # Legacy PQ ML-KEM-768: 1235, 1243, 1267, 1275
    expected_lengths = [
        # Legacy (no mode_byte)
        115,
        123,
        147,
        155,
        179,
        187,
        # New (with mode_byte, FIX-D3)
        116,
        124,
        148,
        156,
        180,
        188,
        # PQ ML-KEM-768 (legacy / new)
        1235,
        1243,
        1267,
        1275,
        1236,
        1244,
        1268,
        1276,
        # PQ ML-KEM-1024 (new)
        1716,
        1724,
        1748,
        1756,
    ]

    if len(manifest_raw) not in expected_lengths:
        raise ValueError(
            f"Manifest QR decode corrupted or truncated!\n"
            f"  Expected one of {sorted(expected_lengths)} bytes\n"
            f"  Got: {len(manifest_raw)} bytes\n"
            f"  This indicates GIF compression or QR decode failure.\n"
            f"  Try: Higher QR error correction (H), disable GIF optimization, or larger box_size."
        )

    # Check if manifest has MAC (length check)
    # Manifest with MAC: adds 8 bytes to any base size
    # MAC sizes (legacy + new): password-only, FS, FS+duress, PQ variants
    has_frame_macs = False
    manifest_bytes = manifest_raw

    mac_sizes = [123, 155, 187, 124, 156, 188, 1243, 1275, 1244, 1276, 1724, 1756]
    if len(manifest_raw) in mac_sizes:
        # Might have frame MAC, but we need password to verify
        # For now, skip MAC verification on manifest (we'll do full manifest HMAC)
        # Just strip the potential MAC for now
        manifest_bytes = manifest_raw[8:]  # Strip first 8 bytes (MAC)
        has_frame_macs = True
        if verbose:
            print(f"  Detected frame MACs (manifest size: {len(manifest_raw)} bytes)")

    manifest = unpack_manifest(manifest_bytes)

    # PROFILE ENFORCEMENT: validate crypto_profile before any crypto operations.
    # Fail closed on unknown/unsupported profiles.
    validate_decode_profile(
        manifest.crypto_profile,
        allow_experimental=allow_experimental,
        allow_legacy=allow_legacy,
    )

    if verbose:
        print(f"  Crypto profile: {manifest.crypto_profile}")
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
    if precomputed_key is None and (
        hsm_slot is not None or tpm_derive or hardware_auto
    ):  # pragma: no cover
        # Build a minimal args namespace for process_hardware_args
        import argparse

        hw_args = argparse.Namespace(
            hsm_slot=hsm_slot,
            hsm_pin=hsm_pin,
            hsm_key_label=hsm_key_label or "meow-master",
            tpm_derive=tpm_derive,
            hardware_auto=hardware_auto,
            no_hardware_fallback=False,
        )
        try:
            from .hardware_integration import process_hardware_args

            hw_key, hw_desc = process_hardware_args(
                hw_args, password.encode("utf-8"), manifest.salt
            )
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
    # Key stays as opaque Rust handle — NEVER enters Python memory.
    hb = get_handle_backend()
    try:
        key_handle = derive_encryption_key_for_manifest_handle(
            password,
            manifest.salt,
            keyfile=keyfile,
            ephemeral_public_key=manifest.ephemeral_public_key,
            receiver_private_key=receiver_private_key,
            yubikey_slot=yubikey_slot,
            yubikey_pin=yubikey_pin,
            precomputed_key=precomputed_key,
            pq_ciphertext=manifest.pq_ciphertext,
        )
        if verbose and precomputed_key is not None:
            print("  🔐 Using hardware-derived key (HSM/TPM)")
    except Exception as e:
        # Key derivation failed - could be wrong keyfile/receiver key
        raise ValueError(f"Key derivation failed: {e}")

    # Check for duress password AFTER Argon2id to prevent timing oracle.
    # Only active when duress_config.enabled is True.
    # Uses a fast authenticated duress tag bound to the manifest core.
    if duress_config.enabled and manifest.duress_tag is not None:  # pragma: no cover
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

                    with open(output_path, "wb") as f:
                        f.write(decoy_data)

                    # Return fake success statistics to mask the duress event
                    return {
                        "input_frames": len(frames),
                        "qr_codes_read": len(qr_data_list),
                        "droplets_processed": manifest.k_blocks * 2,  # Fake efficiency
                        "blocks_decoded": manifest.k_blocks,
                        "output_size": len(decoy_data),
                        "efficiency": 1.0,
                        "elapsed_time": time.time() - start_time,
                    }

            except ImportError:
                pass  # Duress mode module not available
            except SystemExit:
                raise  # Propagate panic exit

            # Return fake "failed" error to not reveal duress was triggered (Silent Panic)
            raise ValueError("HMAC verification failed - wrong password or corrupted data")

    # Verify HMAC using handle-based API (key never enters Python)
    if verbose:
        print("\nVerifying manifest HMAC...")

    from .crypto import compute_manifest_hmac_from_handle, pack_manifest_core as _pack_core

    packed_no_hmac = _pack_core(manifest, include_duress_tag=True)
    expected_hmac = compute_manifest_hmac_from_handle(key_handle, manifest.salt, packed_no_hmac)
    try:
        from .constant_time import constant_time_compare, equalize_timing

        _hmac_ok = constant_time_compare(expected_hmac, manifest.hmac)
        equalize_timing(0.001, 0.005)
    except ImportError:
        import secrets as _secrets

        _hmac_ok = _secrets.compare_digest(expected_hmac, manifest.hmac)

    if not _hmac_ok:
        hb.drop(key_handle)
        raise ValueError("HMAC verification failed - wrong password or corrupted data")

    if verbose:
        print("  ✓ Manifest HMAC valid")

    # Now derive frame MAC key if we detected MACs
    mac_stats = frame_mac.FrameMACStats()

    # Detect ratchet mode from manifest mode_byte
    from meow_decoder.crypto import MODE_RATCHET

    _has_ratchet = bool(manifest.mode_byte & MODE_RATCHET)
    decoder_ratchet = None
    _ratchet_deferred = False
    _ratchet_params: dict = {}

    if has_frame_macs:
        if verbose:
            print("\n🔒 Frame MAC verification enabled (DoS protection)")

        # Derive frame MAC master key from handle (key never enters Python)
        frame_master_key_handle = frame_mac.derive_frame_master_key_handle(
            key_handle, manifest.salt
        )

        # Ratchet initialization is DEFERRED until we know how many signature
        # metadata frames exist.  The encoder binds total_frames=num_droplets
        # in the ratchet AAD, so the decoder must use the same value.
        # GIF layout: [manifest][sig_0..sig_n][droplet_0..droplet_m]
        # total_droplet_frames = len(frames) - 1 (manifest) - n_sig_frames
        # n_sig_frames is only known after MAC-verifying the first few frames.
        _ratchet_deferred = False
        if _has_ratchet:
            _ratchet_deferred = True
            _rekey_interval = getattr(config, "rekey_beacon_interval", 0) if config else 0
            # Build PQBeaconKeyPair for ratchet beacons from HybridKeyPair (ML-KEM-1024 only).
            # Only wire when the public key is 1568 bytes (ML-KEM-1024 / paranoid mode);
            # ML-KEM-768 keys are used for FS hybrid encryption but the ratchet
            # beacon implementation is specific to ML-KEM-1024.
            _ratchet_pq_keypair = None
            if (
                receiver_pq_keypair is not None
                and getattr(receiver_pq_keypair, "pq_public", None) is not None
                and len(receiver_pq_keypair.pq_public) == 1568  # ML-KEM-1024 key size
                and getattr(receiver_pq_keypair, "_pq_secret_bytes", None) is not None
            ):
                from .pq_ratchet_beacon import PQBeaconKeyPair as _PQBeaconKP

                _ratchet_pq_keypair = _PQBeaconKP(
                    secret_key=receiver_pq_keypair._pq_secret_bytes,
                    public_key=receiver_pq_keypair.pq_public,
                )
            _ratchet_params = dict(
                root_key=key_handle,
                salt=manifest.salt,
                k_blocks=manifest.k_blocks,
                block_size=manifest.block_size,
                rekey_interval=_rekey_interval,
                receiver_private_key=receiver_private_key,
                receiver_pq_keypair=_ratchet_pq_keypair,  # PQ ratchet beacon (ML-KEM-1024 only)
            )

        # Verify manifest frame MAC retroactively (v2 key derivation)
        manifest_valid, _ = frame_mac.unpack_frame_with_mac(
            manifest_raw, frame_master_key_handle, 0, manifest.salt
        )

        if not manifest_valid:
            # Legacy compatibility: pre-v2 files derived MAC key from password only
            legacy_master_key = frame_mac.derive_frame_master_key_legacy(password, manifest.salt)
            manifest_valid_legacy, _ = frame_mac.unpack_frame_with_mac(
                manifest_raw, legacy_master_key, 0, manifest.salt
            )
            if manifest_valid_legacy:  # pragma: no cover
                # Drop the handle-derived key and use legacy bytes key instead
                hb.drop(frame_master_key_handle)
                frame_master_key_handle = hb.import_key(legacy_master_key)
                mac_stats.record_valid()
                if tamper_report is not None:
                    tamper_report.record(0, True, "legacy derivation")
                if verbose:
                    print("  ✓ Manifest frame MAC valid (legacy derivation)")
            else:
                # FIX-E1: Frame MAC invalid — fail closed to prevent tampering.
                # The old behavior silently disabled frame MAC verification,
                # allowing an attacker to strip MACs and inject modified frames.
                hb.drop(frame_master_key_handle)
                hb.drop(key_handle)
                if tamper_report is not None:
                    tamper_report.record(0, False, "manifest MAC invalid")
                raise ValueError(
                    "Frame MAC verification failed: manifest frame MAC is invalid. "
                    "This may indicate tampering or corruption."
                )
        else:
            mac_stats.record_valid()
            if tamper_report is not None:  # pragma: no cover
                tamper_report.record(0, True)
            if verbose:
                print("  ✓ Manifest frame MAC valid")

    # Drop the encryption key handle — ratchet and frame MAC own their own
    # derived handles.  key_handle is no longer needed.
    # If ratchet init is deferred, keep key_handle alive until then.
    if not _ratchet_deferred:
        hb.drop(key_handle)
        del key_handle

    # Decode fountain codes
    if verbose:
        if has_frame_macs:
            print("\nDecoding fountain codes with frame MAC verification...")
        else:
            print("\nDecoding fountain codes...")

    decoder = FountainDecoder(
        manifest.k_blocks,
        manifest.block_size,
        original_length=manifest.cipher_len,  # Store length in decoder
    )

    _signing_mode = os.environ.get("MEOW_MANIFEST_SIGNING", "on").lower()
    _disabled_modes = {"0", "false", "no", "off", "disabled"}
    _signing_enabled = _signing_mode not in _disabled_modes

    droplets_processed = 0
    droplets_rejected = 0
    sig_chunks = {}
    sig_total_parts = None
    sig_parts_seen = 0

    progress = ProgressBar(
        len(qr_data_list) - 1, desc="Processing Droplets", unit="droplets", disable=not verbose
    )

    for idx, qr_data in enumerate(progress(qr_data_list[1:])):  # Skip manifest
        try:
            # Use tracked GIF frame index for MAC verification.
            # When stego extraction skips unreadable frames, sequential idx+1
            # doesn't match the original GIF frame index, causing MAC failures.
            actual_frame_idx = qr_frame_indices[idx + 1] if qr_frame_indices else idx + 1

            # Verify frame MAC if enabled
            if has_frame_macs:
                frame_valid, droplet_bytes = frame_mac.unpack_frame_with_mac(
                    qr_data, frame_master_key_handle, actual_frame_idx, manifest.salt
                )

                if not frame_valid:  # pragma: no cover
                    droplets_rejected += 1
                    mac_stats.record_invalid()
                    if tamper_report is not None:
                        tamper_report.record(actual_frame_idx, False, "MAC mismatch")
                    if verbose and droplets_rejected <= 5:
                        print(
                            f"  ⚠️  Frame {actual_frame_idx}: MAC invalid, skipping (frame injection?)"
                        )
                    continue

                mac_stats.record_valid()
                if tamper_report is not None:  # pragma: no cover
                    tamper_report.record(idx + 1, True)
            else:
                droplet_bytes = qr_data

            # Optional manifest-signature metadata chunk (MAC-protected, not ratchet-encrypted)
            if len(droplet_bytes) >= 7 and droplet_bytes[:4] == MANIFEST_SIG_CHUNK_MAGIC:
                _ver = droplet_bytes[4]
                _total = droplet_bytes[5]
                _idx = droplet_bytes[6]
                if _ver != MANIFEST_SIG_VERSION or _total == 0 or _idx >= _total:
                    raise ValueError("Invalid manifest signature chunk header")
                if sig_total_parts is None:
                    sig_total_parts = _total
                elif sig_total_parts != _total:
                    raise ValueError("Inconsistent manifest signature chunk total")
                if _idx not in sig_chunks:
                    sig_chunks[_idx] = droplet_bytes[7:]
                    sig_parts_seen += 1
                if verbose:
                    print(f"  ✍️ Manifest signature chunk {_idx + 1}/{_total} received")
                continue

            # Ratchet-decrypt the frame if ratchet mode is active
            # Lazy ratchet init: now we know how many sig frames were seen
            if _ratchet_deferred and decoder_ratchet is None:
                from .ratchet import DecoderRatchet

                total_droplet_frames = len(frames) - 1 - sig_parts_seen
                decoder_ratchet = DecoderRatchet(
                    **_ratchet_params,
                    total_frames=total_droplet_frames,
                )
                _ratchet_deferred = False
                # Now safe to drop key_handle
                hb.drop(_ratchet_params["root_key"])
                if verbose:
                    _beacon_msg = (
                        f", rekey beacons every {_ratchet_params['rekey_interval']} frames"
                        if _ratchet_params.get("rekey_interval", 0) > 0
                        else ""
                    )
                    _pq_beacon_msg = (
                        " + ML-KEM-1024 PQ beacons"
                        if _ratchet_params.get("receiver_pq_keypair") is not None
                        else ""
                    )
                    print(
                        f"  🐾 Paw state decryption enabled "
                        f"(MSR v1, {total_droplet_frames} frames{_beacon_msg}{_pq_beacon_msg})"
                    )
            if decoder_ratchet is not None:
                try:
                    droplet_bytes = decoder_ratchet.decrypt(droplet_bytes)
                except ValueError as ve:
                    droplets_rejected += 1
                    if verbose and droplets_rejected <= 5:
                        print(f"  ⚠️  Frame {idx + 1}: Ratchet decrypt failed: {ve}")
                    continue

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

    # Clean up key_handle if ratchet was deferred but never initialized
    # (e.g. all frames were signature chunks or decoding failed early)
    if _ratchet_deferred and decoder_ratchet is None:
        hb.drop(_ratchet_params["root_key"])
        _ratchet_deferred = False

    # Verify manifest signature if signature chunks were present.
    if sig_total_parts is not None:
        if sig_parts_seen != sig_total_parts:
            raise ValueError("Manifest signature chunks incomplete — possible tampering/corruption")

        sig_blob = b"".join(sig_chunks[i] for i in range(sig_total_parts))
        if (
            len(sig_blob) < 9
            or sig_blob[:4] != MANIFEST_SIG_BLOB_MAGIC
            or sig_blob[4] != MANIFEST_SIG_VERSION
        ):
            raise ValueError("Invalid manifest signature blob format")

        pk_len, sig_len = struct.unpack(">HH", sig_blob[5:9])
        if len(sig_blob) < 9 + pk_len + sig_len:
            raise ValueError("Truncated manifest signature blob")

        public_key = sig_blob[9 : 9 + pk_len]
        signature_bytes = sig_blob[9 + pk_len : 9 + pk_len + sig_len]

        from .manifest_signing import ManifestSignature, verify_manifest_signature

        signature = ManifestSignature.from_bytes(signature_bytes)
        verify_manifest_signature(public_key, manifest_bytes, signature, context=b"manifest-v1")
        if verbose:
            print("  ✓ Manifest signature verified")
    else:
        _mode_hint = getattr(manifest, "mode_byte", 0)
        _legacy_hint = (
            " (legacy/compatibility stream)" if (_has_ratchet or _mode_hint < 0x05) else ""
        )
        if not _signing_enabled:
            print(
                "⚠️  Unsigned manifest accepted (signing disabled by policy) — vulnerable to forgery. "
                "Re-encode with signing enabled for production/high-risk use."
                f"{_legacy_hint}",
                file=sys.stderr,
            )
        else:
            # FIX: Fail-closed — reject unsigned manifests when signing is enabled.
            # Previously this was warn-only, allowing an attacker to strip signatures
            # and have the decoder silently accept tampered content.
            raise ValueError(
                "Unsigned manifest rejected (signing is mandatory). "
                "This GIF has no cryptographic signature — possible tampering or "
                "legacy encoder. Set MEOW_MANIFEST_SIGNING=off to accept unsigned "
                "manifests at your own risk."
                f"{_legacy_hint}"
            )

    # Finalize ratchet (bury keys in litter)
    if decoder_ratchet is not None:
        decoder_ratchet.finalize()
        if verbose:
            print("  ✓ Paw state finalized, all whisker keys buried in litter")

    # Drop frame MAC master key handle
    if has_frame_macs:
        hb.drop(frame_master_key_handle)
        del frame_master_key_handle
    # key_handle already dropped — was only needed for HMAC, frame MAC, ratchet init

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
        # FIX-GPT-1: PQ hybrid decapsulation (MEOW4).
        # When the manifest carries pq_ciphertext, the encoder used
        # hybrid_encapsulate_handle() to derive the encryption key.  The
        # decoder must call hybrid_decapsulate_handle() to reconstruct the
        # same key as an opaque Rust handle — zero secret bytes in Python.
        pq_precomputed_key = precomputed_key  # default: whatever the caller passed
        pq_precomputed_key_handle = None  # handle-based PQ path
        pq_private_key = receiver_private_key  # default: X25519 private for FS

        if manifest.pq_ciphertext is not None:
            if receiver_pq_keypair is None:
                raise ValueError(
                    "Manifest contains PQ ciphertext (MEOW4/MEOW5 mode) but no "
                    "receiver_pq_keypair was provided.  Cannot decrypt without "
                    "the receiver's ML-KEM + X25519 hybrid keypair.  Use "
                    "--receiver-pq-pubkey and --receiver-pq-secret to provide "
                    "the PQ keypair generated with --generate-pq-keys."
                )
            if manifest.ephemeral_public_key is None:
                raise ValueError(
                    "Manifest contains PQ ciphertext but no ephemeral public key. "
                    "The manifest may be corrupt or was encoded with a buggy version."
                )
            try:
                from .pq_hybrid import hybrid_decapsulate_handle
            except ImportError:
                from meow_decoder.pq_hybrid import hybrid_decapsulate_handle

            pq_precomputed_key_handle = hybrid_decapsulate_handle(
                ephemeral_classical_public=manifest.ephemeral_public_key,
                pq_ciphertext=manifest.pq_ciphertext,
                receiver_keypair=receiver_pq_keypair,
            )
            # Handle path: no raw bytes to pass, clear the legacy path
            pq_precomputed_key = None
            # In PQ hybrid mode, the X25519 exchange already happened inside
            # hybrid_decapsulate_handle; don't trigger a second one.
            pq_private_key = None

            if verbose:
                _pq_variant = "ML-KEM-768" if len(manifest.pq_ciphertext) == 1088 else "ML-KEM-1024"
                print(
                    f"  🔮 PQ hybrid: Decapsulated {_pq_variant} ciphertext "
                    f"({len(manifest.pq_ciphertext)} bytes)"
                )

        raw_data = decrypt_to_raw_production(
            cipher,
            password,
            manifest.salt,
            manifest.nonce,
            keyfile,
            manifest.orig_len,
            manifest.comp_len,
            manifest.sha256,
            manifest.ephemeral_public_key,
            pq_private_key,
            yubikey_slot=yubikey_slot,
            yubikey_pin=yubikey_pin,
            precomputed_key=pq_precomputed_key,
            pq_ciphertext=manifest.pq_ciphertext,
            mode_byte=manifest.mode_byte,
            precomputed_key_handle=pq_precomputed_key_handle,
        )

        # Drop PQ handle after decryption (we own it)
        if pq_precomputed_key_handle is not None:
            from .crypto_backend import get_handle_backend as _ghb

            _ghb().drop(pq_precomputed_key_handle)
            pq_precomputed_key_handle = None  # prevent double-drop

        if verbose and manifest.ephemeral_public_key:
            print(f"  ✅ Forward secrecy: Decrypted using ephemeral key")
    except Exception as e:
        # Drop PQ handle even on error
        if pq_precomputed_key_handle is not None:
            try:
                from .crypto_backend import get_handle_backend as _ghb2

                _ghb2().drop(pq_precomputed_key_handle)
            except Exception:
                pass
        raise RuntimeError(f"Decryption failed: {e}")

    # Verify SHA256
    if verbose:
        print("Verifying integrity...")

    from . import crypto_backend

    computed_sha = crypto_backend.get_default_backend().sha256(raw_data)
    if computed_sha != manifest.sha256:
        raise ValueError("SHA256 mismatch - data corrupted")

    if verbose:
        print("  ✓ Integrity verified")

    # Write output
    if verbose:
        print(f"\nWriting output: {output_path}")

    with open(output_path, "wb") as f:
        f.write(raw_data)

    elapsed = time.time() - start_time

    if verbose:
        print(f"  Size: {len(raw_data):,} bytes")
        print(f"\nDecoding complete in {elapsed:.2f} seconds")

    # Return statistics
    return {
        "input_frames": len(frames),
        "qr_codes_read": len(qr_data_list),
        "droplets_processed": droplets_processed,
        "blocks_decoded": decoder.decoded_count,
        "output_size": len(raw_data),
        "efficiency": decoder.decoded_count / droplets_processed if droplets_processed > 0 else 0,
        "elapsed_time": elapsed,
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
        """,
    )

    # Required arguments
    parser.add_argument("-i", "--input", type=Path, required=False, help="Input GIF file")
    parser.add_argument("-o", "--output", type=Path, required=False, help="Output file")

    # Optional arguments
    parser.add_argument(
        "-p", "--password", type=str, help="Decryption password (prompted if not provided)"
    )
    parser.add_argument(
        "--password-mode",
        choices=["standard", "secure-keyboard", "mouse-gesture"],
        default="standard",
        help="Interactive password mode when --password is omitted (default: standard)",
    )
    parser.add_argument("-k", "--keyfile", type=Path, help="Path to keyfile")
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

    # TPM 2.0 key unsealing
    parser.add_argument(
        "--tpm-unseal",
        action="store_true",
        help="Unseal key from TPM (requires matching PCR state)",
    )
    parser.add_argument("--tpm-derive", action="store_true", help="Use TPM for key derivation")

    # Hardware auto-detection
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

    parser.add_argument(
        "--receiver-privkey",
        type=Path,
        help="Path to receiver X25519 private key for forward secrecy (PEM format)",
    )
    parser.add_argument(
        "--receiver-privkey-password", type=str, help="Password for encrypted receiver private key"
    )
    parser.add_argument(
        "--receiver-pq-pubkey",
        type=Path,
        help="Path to receiver ML-KEM public key for PQ hybrid decryption (raw bytes)",
    )
    parser.add_argument(
        "--receiver-pq-secret",
        type=Path,
        help="Path to receiver ML-KEM secret key for PQ hybrid decryption (raw bytes)",
    )

    # Decoding parameters
    parser.add_argument("--aggressive", action="store_true", help="Use aggressive QR preprocessing")

    # Profile enforcement
    parser.add_argument(
        "--allow-experimental",
        action="store_true",
        help="Accept experimental crypto profiles (e.g. PQ hybrid) on decode",
    )
    parser.add_argument(
        "--allow-legacy",
        action="store_true",
        help="Accept legacy manifests without explicit mode byte",
    )

    # Duress Handling
    parser.add_argument(
        "--duress-mode",
        choices=["decoy", "panic"],
        default="decoy",
        help="Duress response mode: decoy (fake success) or panic (wipe/exit)",
    )
    parser.add_argument(
        "--enable-panic",
        action="store_true",
        help="Explicitly enable destructive PANIC mode (required for --duress-mode panic)",
    )
    parser.add_argument(
        "--enable-duress",
        action="store_true",
        help="Enable duress handling (required for --duress-mode decoy; panic enables automatically)",
    )

    # Crypto backend selection
    # Rust backend is mandatory; no Python fallback is supported.

    # Output control
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--purr-mode",
        action="store_true",
        help="Ultra-verbose cat-themed logging with meows, facts, and cat verbs 🐱",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite output file if exists")
    parser.add_argument(
        "--nine-lives",
        action="store_true",
        help="Enable Nine Lives retry mode: automatic recovery with up to 9 attempts on error",
    )

    parser.add_argument(
        "--tamper-report",
        action="store_true",
        help="Show frame-by-frame MAC verification timeline after decoding",
    )
    parser.add_argument(
        "--tamper-report-json",
        type=Path,
        default=None,
        help="Write tamper report as JSON to the given file",
    )

    # ── Mobile Bridge Mode ───────────────────────────────────────────────────
    parser.add_argument(
        "--mobile-bridge",
        action="store_true",
        help="Enable mobile bridge mode: accept QR frames via JSON protocol",
    )
    parser.add_argument(
        "--bridge-mode",
        choices=["stdin", "websocket", "file"],
        default="stdin",
        help="Bridge transport: stdin (pipe), websocket (server), or file (default: stdin)",
    )
    parser.add_argument(
        "--bridge-port",
        type=int,
        default=8765,
        help="WebSocket server port for bridge mode (default: 8765)",
    )
    parser.add_argument(
        "--input-frames",
        type=Path,
        metavar="FILE",
        help="Read captured frames from JSON file (alternative to --input GIF)",
    )
    parser.add_argument(
        "--output-request",
        type=Path,
        metavar="FILE",
        help="Write capture request JSON for mobile app (then exit)",
    )

    parser.add_argument(
        "--about", "--meow-about", action="store_true", help="Show version and build information"
    )

    args = parser.parse_args()

    # Rust backend is mandatory (no legacy Python fallback).

    # Handle about flag (exit after display)
    if args.about:
        from .cat_utils import meow_about

        print(meow_about())
        sys.exit(0)

    # Handle hardware status check (exit after display)
    if args.hardware_status:
        from .hardware_integration import HardwareSecurityProvider

        provider = HardwareSecurityProvider(verbose=True)
        caps = provider.detect_all()
        print(caps.summary())
        sys.exit(0)

    # Enable purr mode (ultra-verbose cat-themed logging)
    if args.purr_mode:
        from .cat_utils import enable_purr_mode

        enable_purr_mode(enabled=True)
        # Purr mode implies verbose
        args.verbose = True

        # Enable verbose output for Nine Lives retry mode
        if args.nine_lives:
            args.verbose = True
            print("🐱 Nine Lives retry mode enabled (max 9 attempts on error)")
            print("   Using all nine lives to ensure decoding success!\n")

    # Handle mobile bridge mode
    if args.mobile_bridge or args.input_frames or args.output_request:
        from .mobile_bridge import handle_mobile_bridge

        def decode_frames_callback(frames: list[bytes], decode_args):
            """Decode raw QR frame bytes using fountain decoder."""
            # This is a simplified callback - full implementation would
            # integrate with the fountain decoder directly
            try:
                from .fountain import FountainDecoder
                from .crypto import decrypt_to_raw_production

                # Process frames through fountain decoder
                decoder = FountainDecoder()
                for frame_data in frames:
                    decoder.add_droplet(frame_data)

                if decoder.is_complete():
                    encrypted = decoder.get_decoded()
                    plaintext = decrypt_to_raw_production(
                        encrypted,
                        decode_args.password,
                        salt=decode_args.salt,
                        nonce=decode_args.nonce,
                    )
                    decode_args.output.write_bytes(plaintext)
                    return True
                return False
            except Exception as e:
                if getattr(decode_args, "verbose", False):
                    print(f"Decode error: {e}")
                return False

        handle_mobile_bridge(args, decode_frames_callback)
        sys.exit(0)

    # For normal operation, require input/output
    if not args.about and not args.hardware_status:
        if args.input is None or args.output is None:
            parser.error("the following arguments are required: -i/--input, -o/--output")

    # Validate input file
    if not args.input.exists():
        hiss_error(fur_ball_error("file_not_found", suggestion=False))
        print(f"  Path: {args.input}", file=sys.stderr)
        sys.exit(1)

    if not args.input.is_file():
        hiss_error(f"That's not a file! The cat can't decode a directory.")
        print(f"  Path: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Check output file
    if args.output.exists() and not args.force:
        hiss_error(fur_ball_error("output_exists", suggestion=False))
        print(f"  Path: {args.output}", file=sys.stderr)
        print("  Use --force to overwrite", file=sys.stderr)
        sys.exit(1)

    # Get password
    # Treat an empty string passed via --password as "provided" so we don't
    # fall back to interactive prompting in non-TTY environments (e.g. CI).
    if args.password is not None:
        password = args.password
    else:
        if args.password_mode == "standard":
            password = getpass("Enter decryption password: ")
        elif args.password_mode == "secure-keyboard":
            password = secure_password_input("Enter decryption password: ", use_gui=True)
            if password is None:
                hiss_error("Password entry was cancelled.")
                sys.exit(1)
        else:
            gesture = MouseGesturePassword(grid_size=5)
            try:
                password = gesture.collect_interactive("Draw decryption gesture password")
            except Exception as e:
                print(f"Error: Failed to collect gesture password: {e}", file=sys.stderr)
                sys.exit(1)

    if not password:
        hiss_error(fur_ball_error("wrong_password", suggestion=False))
        print("  Password cannot be empty.", file=sys.stderr)
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
            print(
                "Error: YubiKey derivation is not supported with forward secrecy keys",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.yubikey_pin is None:
            yk_pin = getpass("Enter YubiKey PIN (leave blank if not required): ")
            args.yubikey_pin = yk_pin if yk_pin else None

    # 🔐 HSM/TPM/Hardware-Auto validation
    hardware_mode = None
    if getattr(args, "hsm_slot", None) is not None:
        if keyfile is not None:
            print("Error: Cannot combine --hsm-slot with --keyfile", file=sys.stderr)
            sys.exit(1)
        if args.receiver_privkey is not None:
            print(
                "Error: HSM derivation is not supported with forward secrecy keys", file=sys.stderr
            )
            sys.exit(1)
        # HSM PIN prompt if not provided
        if getattr(args, "hsm_pin", None) is None:
            args.hsm_pin = getpass("🔐 Enter HSM PIN: ")
        hardware_mode = "hsm"
        print(f"😺 Purring with HSM slot {args.hsm_slot}...")

    elif getattr(args, "tpm_derive", False):
        if keyfile is not None:
            print("Error: Cannot combine --tpm-derive with --keyfile", file=sys.stderr)
            sys.exit(1)
        if args.receiver_privkey is not None:
            print(
                "Error: TPM derivation is not supported with forward secrecy keys", file=sys.stderr
            )
            sys.exit(1)
        hardware_mode = "tpm"
        print(f"🐱 Clawing TPM for key derivation...")

    elif getattr(args, "hardware_auto", False):
        if keyfile is not None:
            print("Error: Cannot combine --hardware-auto with --keyfile", file=sys.stderr)
            sys.exit(1)
        if args.receiver_privkey is not None:
            print(
                "Error: Hardware auto derivation is not supported with forward secrecy keys",
                file=sys.stderr,
            )
            sys.exit(1)
        hardware_mode = "auto"
        print("😻 Auto-detecting hardware security... (YubiKey > TPM > HSM)")

    # Load receiver private key for forward secrecy if specified
    receiver_private_key = None
    if args.receiver_privkey:
        try:
            from .x25519_forward_secrecy import load_x25519_private_key_pem

            # Get password for private key if needed
            privkey_password = args.receiver_privkey_password
            if not privkey_password:
                privkey_password = getpass("Enter receiver private key password: ")

            # Load the private key using helper
            with open(args.receiver_privkey, "rb") as f:
                privkey_data = f.read()

            receiver_private_key = load_x25519_private_key_pem(privkey_data, privkey_password)

            if args.verbose:
                print(f"✅ Loaded receiver private key for forward secrecy")
                print(f"   File: {args.receiver_privkey}")
        except Exception as e:
            print(f"Error loading receiver private key: {e}", file=sys.stderr)
            if args.verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    # Load PQ hybrid keypair if specified
    receiver_pq_keypair = None
    pq_pub_path = getattr(args, "receiver_pq_pubkey", None)
    pq_secret_path = getattr(args, "receiver_pq_secret", None)
    if pq_pub_path or pq_secret_path:
        if not pq_pub_path or not pq_secret_path:
            print(
                "Error: Both --receiver-pq-pubkey and --receiver-pq-secret are required "
                "for PQ hybrid decryption.",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            from .pq_hybrid import (
                HybridKeyPair,
                LIBOQS_AVAILABLE,
                PRODUCTION_MODE,
                _RUST_PQ_AVAILABLE,
            )

            if not LIBOQS_AVAILABLE:
                if PRODUCTION_MODE:
                    print(
                        "Error: PQ hybrid requested but Rust PQ backend not available. "
                        "Rebuild with: cd rust_crypto && maturin develop --release --features pq",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "Error: PQ backend not available. Install liboqs-python or "
                        "rebuild Rust with --features pq",
                        file=sys.stderr,
                    )
                sys.exit(1)

            with open(pq_pub_path, "rb") as f:
                pq_pub_bytes = f.read()
            with open(pq_secret_path, "rb") as f:
                pq_secret_bytes = f.read()

            # Determine variant from public key size
            if len(pq_pub_bytes) == 1184:
                pq_algorithm = "ML-KEM-768"
                paranoid = False
            elif len(pq_pub_bytes) == 1568:
                pq_algorithm = "ML-KEM-1024"
                paranoid = True
            else:
                print(
                    f"Error: Unexpected ML-KEM public key size: {len(pq_pub_bytes)} bytes. "
                    f"Expected 1184 (ML-KEM-768) or 1568 (ML-KEM-1024).",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Reconstruct HybridKeyPair with loaded keys
            receiver_pq_keypair = HybridKeyPair(use_pq=False, paranoid=paranoid)

            if _RUST_PQ_AVAILABLE:
                # PQ via Rust backend — no oqs needed
                receiver_pq_keypair._pq_secret_bytes = pq_secret_bytes
            else:
                raise RuntimeError(
                    "PQ hybrid decryption requires Rust PQ backend. "
                    "Python oqs fallback has been removed (Rule #4: no silent downgrade). "
                    "Rebuild with: cd rust_crypto && maturin develop --release --features pq"
                )
            receiver_pq_keypair.pq_public = pq_pub_bytes

            # Use the already-loaded X25519 private key if available
            if receiver_private_key is not None:
                # Set raw bytes directly (HybridKeyPair uses bytes internally)
                receiver_pq_keypair._classical_private_bytes = receiver_private_key
                # Derive public key from private key
                from . import crypto_backend

                backend = crypto_backend.get_default_backend()
                receiver_pq_keypair._classical_public_bytes = backend.x25519_public_from_private(
                    receiver_private_key
                )

            if args.verbose:
                print(f"✅ Loaded PQ hybrid keypair ({pq_algorithm})")
                print(f"   Public key:  {pq_pub_path} ({len(pq_pub_bytes)} bytes)")
                print(f"   Secret key:  {pq_secret_path} ({len(pq_secret_bytes)} bytes)")
        except Exception as e:
            print(f"Error loading PQ keypair: {e}", file=sys.stderr)
            if args.verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    # Create duress config (opt-in)
    d_mode = DuressMode.PANIC if args.duress_mode == "panic" else DuressMode.DECOY
    duress_enabled = bool(args.enable_duress or args.enable_panic or args.duress_mode == "panic")
    duress_config = DuressConfig(
        enabled=duress_enabled, mode=d_mode, panic_enabled=args.enable_panic
    )

    # Create decoding config
    config = DecodingConfig(preprocessing="aggressive" if args.aggressive else "normal")

    # Decode file
    try:
        # Create tamper report if requested
        t_report = None
        if getattr(args, "tamper_report", False) or getattr(
            args, "tamper_report_json", None
        ):  # pragma: no cover
            t_report = TamperReport()

        decode_kwargs = {
            "config": config,
            "keyfile": keyfile,
            "receiver_private_key": receiver_private_key,  # Forward secrecy support
            "receiver_pq_keypair": receiver_pq_keypair,  # PQ hybrid support (MEOW4/MEOW5)
            "verbose": args.verbose,
            "tamper_report": t_report,
            "allow_experimental": getattr(args, "allow_experimental", False),
            "allow_legacy": getattr(args, "allow_legacy", False),
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
                decode_kwargs["hsm_key_label"] = getattr(args, "hsm_key_label", "meow-master")
            elif hardware_mode == "tpm":
                decode_kwargs["tpm_derive"] = True
            elif hardware_mode == "auto":
                decode_kwargs["hardware_auto"] = True

        # 🐱 Nine Lives retry mode integration
        if args.nine_lives:
            from .cat_utils import NineLivesRetry

            retry = NineLivesRetry(max_lives=9, verbose=True)
            stats = None
            for life in retry.attempt():
                try:
                    stats = decode_gif(
                        args.input,
                        args.output,
                        password,
                        **decode_kwargs,
                    )
                    retry.success(stats)
                    break
                except Exception as e:
                    retry.fail(str(e))

            if not retry.succeeded:
                sys.exit(1)
        else:
            # Normal decoding without retry mode
            stats = decode_gif(
                args.input,
                args.output,
                password,
                **decode_kwargs,
            )

        # Print summary
        if not args.verbose:
            purr_success("Decoding complete!")
            print(f"  Input: {stats['input_frames']} frames, {stats['qr_codes_read']} QR codes")
            print(f"  Processed: {stats['droplets_processed']} droplets")
            print(f"  Output: {stats['output_size']:,} bytes")
            print(f"  Efficiency: {stats['efficiency']*100:.1f}%")
            print(f"  Time: {stats['elapsed_time']:.2f}s")

        print(f"\nOutput saved to: {args.output}")

        # Display tamper report if requested
        if t_report is not None:  # pragma: no cover
            if getattr(args, "tamper_report", False):
                print()
                print(t_report.ascii_timeline())
            if getattr(args, "tamper_report_json", None):
                json_path = args.tamper_report_json
                json_path.parent.mkdir(parents=True, exist_ok=True)
                json_path.write_text(t_report.to_json())
                print(f"\nTamper report saved to: {json_path}")

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
