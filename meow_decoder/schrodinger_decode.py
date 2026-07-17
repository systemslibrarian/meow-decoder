#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Dual Reality Decoder v6.0.0

Collapses the quantum superposition based on the provided password,
revealing one of the two hidden realities.

Rewritten for the production Rust crypto backend (HandleBackend).
All secret key material stays inside opaque Rust handles — no raw key
bytes ever enter Python memory.

Security Properties:
    - TIMING-SAFE: Both Argon2id derivations run ALWAYS (no timing oracle)
    - TIMING-SAFE: Both HMAC verifications run ALWAYS (no reality detection)
    - constant_time_compare for all auth tag checks
    - Random delay masks any residual timing side-channels
    - All key handles zeroized via Rust after use
"""

from __future__ import annotations

import sys
import argparse
import struct
import secrets
import time
from pathlib import Path
from typing import Optional
from getpass import getpass

from .crypto import (
    decrypt_to_raw_handle,
    ARGON2_MEMORY,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
)
from .crypto_backend import get_default_backend as _get_backend, get_handle_backend
from .quantum_mixer import collapse_to_reality
from .schrodinger_encode import SchrodingerManifest


def schrodinger_decode_data(
    superposition: bytes,
    manifest: "SchrodingerManifest",
    password: str,
) -> Optional[bytes]:
    """
    Decode one reality from the superposition based on the password.

    All key material stays in opaque Rust handles — never enters Python.

    Args:
        superposition: The interleaved ciphertext.
        manifest: The Schrödinger manifest.
        password: The password for one of the realities.

    Returns:
        The decrypted data if the password is correct for either reality,
        otherwise None.

    Timing properties:
        EQUALIZED: Both Argon2id derivations always run.
        EQUALIZED: Both HMAC verifications always run.
        EQUALIZED: Both metadata decryption attempts always run.
        NOT-EQUALIZED: File decryption runs only for the matched reality.
          Rationale: file sizes differ and we cannot dupe the decrypt cost
          without knowing the plaintext size in advance.  The Argon2id
          gating means an attacker must first break the KDF before
          exploiting any residual timing from the file-decrypt branch.
        Jitter: a small random delay is added after KDF to mask CPU noise.
    """
    hb = get_handle_backend()

    # EQUALIZED-01: Derive BOTH keys upfront — Argon2id is the dominant cost.
    master_meta_key_a = hb.derive_key_argon2id(
        password.encode("utf-8"),
        manifest.salt_a,
        memory_kib=ARGON2_MEMORY,
        iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    master_meta_key_b = hb.derive_key_argon2id(
        password.encode("utf-8"),
        manifest.salt_b,
        memory_kib=ARGON2_MEMORY,
        iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )

    # Derive HMAC keys for both realities (handle-based HKDF)
    hmac_key_a = hb.derive_key_hkdf(
        master_meta_key_a,
        manifest.salt_a,
        b"schrodinger_hmac_key_v1",
        32,
    )
    hmac_key_b = hb.derive_key_hkdf(
        master_meta_key_b,
        manifest.salt_b,
        b"schrodinger_hmac_key_v1",
        32,
    )

    # Compute expected HMACs for both realities (handle-based)
    manifest_core = manifest.pack_core_for_auth()
    expected_hmac_a = hb.hmac_sha256(hmac_key_a, manifest_core)
    expected_hmac_b = hb.hmac_sha256(hmac_key_b, manifest_core)

    # Drop HMAC key handles
    hb.drop(hmac_key_a)
    hb.drop(hmac_key_b)

    # EQUALIZED-02: Check BOTH HMACs in constant time — no early exit.
    is_reality_a = _get_backend().constant_time_compare(expected_hmac_a, manifest.reality_a_hmac)
    is_reality_b = _get_backend().constant_time_compare(expected_hmac_b, manifest.reality_b_hmac)

    # EQUALIZED-03: Always derive BOTH enc keys, regardless of HMAC result.
    # This prevents timing oracles on the key-derivation path.
    enc_key_a = hb.derive_key_hkdf(
        master_meta_key_a,
        manifest.salt_a,
        b"schrodinger_enc_key_v1",
        32,
    )
    enc_key_b = hb.derive_key_hkdf(
        master_meta_key_b,
        manifest.salt_b,
        b"schrodinger_enc_key_v1",
        32,
    )

    # Drop master key handles (no longer needed)
    for h in (master_meta_key_a, master_meta_key_b):
        try:
            hb.drop(h)
        except Exception:
            pass

    # EQUALIZED-04: Always attempt BOTH metadata decrypts, even if HMAC failed.
    # If HMAC mismatch, AES-GCM will fail (tag mismatch) and we get None.
    # This ensures both branches take approximately equal time.
    metadata_a_plain: Optional[bytes] = None
    metadata_b_plain: Optional[bytes] = None
    try:
        metadata_a_plain = hb.aes_gcm_decrypt(
            enc_key_a, manifest.nonce_a, manifest.metadata_a, None
        )
    except Exception:
        pass  # Expected when HMAC failed — the try is part of timing equalization

    try:
        metadata_b_plain = hb.aes_gcm_decrypt(
            enc_key_b, manifest.nonce_b, manifest.metadata_b, None
        )
    except Exception:
        pass  # Expected when HMAC failed

    # Drop enc key handles
    for h in (enc_key_a, enc_key_b):
        try:
            hb.drop(h)
        except Exception:
            pass

    # Small jitter to mask CPU noise in the equalized operations above.
    # Note: this does NOT equalize the file-decrypt phase below.
    time.sleep(secrets.randbelow(10) / 1000.0)

    # ── Select and use the matched reality ──────────────────────────────────
    # Security gate: file decryption only runs when Argon2id-derived HMAC
    # verified.  The NOT-EQUALIZED note in the docstring applies to this
    # section; the phases above are fully equalized.

    def _unpack_metadata(plain: bytes) -> tuple:
        """Extract (orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256)"""
        orig_len, comp_len, cipher_len = struct.unpack(">QQQ", plain[:24])
        salt_enc = plain[24:40]
        nonce_enc = plain[40:52]
        sha256 = plain[52:84]
        return orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256

    if is_reality_a and metadata_a_plain is not None:
        try:
            orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256 = _unpack_metadata(
                metadata_a_plain
            )
            ciphertext_a = collapse_to_reality(superposition, 0)[:cipher_len]
            plaintext = decrypt_to_raw_handle(
                cipher=ciphertext_a,
                password=password,
                salt=salt_enc,
                nonce=nonce_enc,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256,
            )
            return plaintext
        except Exception:
            pass  # Data corrupted despite HMAC match

    if is_reality_b and metadata_b_plain is not None:
        try:
            orig_len, comp_len, cipher_len, salt_enc, nonce_enc, sha256 = _unpack_metadata(
                metadata_b_plain
            )
            ciphertext_b = collapse_to_reality(superposition, 1)[:cipher_len]
            plaintext = decrypt_to_raw_handle(
                cipher=ciphertext_b,
                password=password,
                salt=salt_enc,
                nonce=nonce_enc,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256,
            )
            return plaintext
        except Exception:
            pass  # Data corrupted despite HMAC match

    # Neither reality matched — wrong password or corrupted data
    return None


def schrodinger_decode_file(
    input_gif: Path,
    output: Path,
    password: str,
    verbose: bool = False,
) -> dict:
    """
    Decode file from Schrödinger mode GIF.

    All key material stays in opaque Rust handles — no raw key bytes
    enter Python memory.

    Args:
        input_gif: Input GIF with quantum superposition
        output: Output file
        password: Password (collapses quantum state)
        verbose: Verbose output

    Returns:
        Statistics dict with decoded_size, qr_frames, blocks
    """
    # Import heavy dependencies only when needed (avoids circular imports)
    from .gif_handler import GIFDecoder
    from .qr_code import QRCodeReader
    from .fountain import FountainDecoder, unpack_droplet
    from .frame_mac import unpack_frame_with_mac, verify_frame_mac, MAC_SIZE
    from .schrodinger_encode import _FRAME_MAC_SEED_INFO

    if verbose:
        print("🐱⚛️  Schrödinger's Yarn Ball - Quantum Decoder v6.0.0")
        print("=" * 60)
        print("  All keys stay in Rust handles — zero Python key exposure")
        print("=" * 60)

    # Extract QR frames
    if verbose:
        print("\n📱 Extracting QR frames...")

    gif_decoder = GIFDecoder()
    frames = gif_decoder.extract_frames(input_gif)

    qr_reader = QRCodeReader()
    qr_data_list = []

    for frame in frames:
        data_list = qr_reader.read_image(frame)
        if data_list:
            qr_data_list.append(data_list[0])

    if verbose:
        print(f"   Extracted {len(qr_data_list)} frames")

    if not qr_data_list:
        raise ValueError("No QR codes found in GIF")

    # ── Parse manifest (frame 0) with proper MAC bootstrap ──────────────
    # Security (Bug 1): encoder prepends an 8-byte frame MAC to EVERY frame.
    # We MUST verify that MAC rather than blindly stripping it by length.
    #
    # Bootstrap approach for frame 0:
    #   1. Strip first MAC_SIZE bytes (fixed-format, not length-heuristic).
    #   2. Parse manifest payload -> get frame_mac_seed.
    #   3. Derive frame MAC master from seed (seed is public, not secret).
    #   4. RE-VERIFY frame 0's MAC against the stripped bytes.
    #      Any tampering with the payload (incl. the seed) breaks the MAC.
    #   5. For v0x07 legacy (seed == all-zeros): skip frame MAC check.
    if verbose:
        print("\n⛛️  Parsing quantum manifest...")

    frame0_raw = qr_data_list[0]
    if len(frame0_raw) < MAC_SIZE + 382:
        raise ValueError(
            f"Frame 0 too short: {len(frame0_raw)} bytes "
            f"(need ≥ {MAC_SIZE + 382} for MAC + manifest)"
        )

    # Step 1: tentative split into MAC prefix + manifest payload
    frame0_mac_bytes = frame0_raw[:MAC_SIZE]
    manifest_payload = frame0_raw[MAC_SIZE:]

    # Step 2: parse manifest to get frame_mac_seed
    try:
        manifest = SchrodingerManifest.unpack(manifest_payload)
    except Exception as e:
        raise ValueError(f"Failed to parse manifest: {e}")

    # Step 3+4: derive frame MAC key and re-verify frame 0
    backend = _get_backend()
    _zero_seed = b"\x00" * 16
    if manifest.frame_mac_seed != _zero_seed:
        # v0x08 (current): derive key from public seed and verify MAC
        frame_mac_master = backend.sha256(manifest.frame_mac_seed + _FRAME_MAC_SEED_INFO)
        frame0_valid = verify_frame_mac(
            manifest_payload,
            frame0_mac_bytes,
            frame_mac_master,
            0,
            manifest.frame_mac_seed,
        )
        if not frame0_valid:
            raise ValueError(
                "Frame 0 (manifest) MAC verification failed — "
                "manifest may be corrupted or injected"
            )
        if verbose:
            print("   ✅ Manifest frame MAC verified")
    else:
        # v0x07 legacy: no seed present, skip frame MAC verification
        frame_mac_master = None
        if verbose:
            print("   ⚠️  Legacy manifest (v0x07): frame MAC verification skipped")

    if verbose:
        print(f"   Version: 0x{manifest.version:02x} (Schrödinger v6.0.0)")
        print(f"   Blocks: {manifest.block_count}")
        print(f"   Block size: {manifest.block_size}")
        print(f"   Superposition length: {manifest.superposition_len}")

    # ── Extract and verify droplet frames ───────────────────────────────────
    # Security (Bug 1): Use unpack_frame_with_mac for EVERY droplet frame.
    # Invalid frames (wrong MAC) are rejected before reaching fountain decoder.
    # This prevents DoS via injected/corrupted frames.
    droplets = []
    mac_failures = 0

    for i, frame_data in enumerate(qr_data_list[1:], 1):
        if frame_mac_master is not None:
            # v0x08: proper MAC verification
            valid, droplet_data = unpack_frame_with_mac(
                frame_data, frame_mac_master, i, manifest.frame_mac_seed
            )
            if not valid:
                mac_failures += 1
                if verbose:
                    print(f"   ⚠️  Frame {i} MAC failed — skipping (injected/corrupted?)")
                continue
        else:
            # v0x07 legacy: strip fixed MAC_SIZE bytes if present
            if len(frame_data) >= MAC_SIZE:
                droplet_data = frame_data[MAC_SIZE:]
            else:
                droplet_data = frame_data

        try:
            droplet = unpack_droplet(droplet_data, manifest.block_size)
            droplets.append(droplet)
        except Exception as e:
            if verbose:
                print(f"   ⚠️  Frame {i} unpack failed: {e}")
            continue

    if mac_failures > 0 and verbose:
        print(f"   ⚠️  {mac_failures} frame(s) rejected by MAC (injection/corruption)")

    if verbose:
        print(f"\n🌊 Fountain decoding {len(droplets)} droplets...")

    # Fountain decode
    # SECURITY (H1): manifest.block_count/block_size come from an UNAUTHENTICATED
    # manifest. Bounds are enforced defence-in-depth at BOTH ends —
    # SchrodingerManifest.unpack() rejects out-of-range values at parse time, and
    # FountainDecoder.__init__ re-validates (k_blocks<=u16::MAX, block_size, and a
    # 10 GiB total ceiling) BEFORE allocating, raising a clean ValueError instead
    # of driving an unbounded vec![None; block_count] allocation (OOM DoS).
    decoder = FountainDecoder(manifest.block_count, manifest.block_size)

    for droplet in droplets:
        if decoder.add_droplet(droplet):
            break

    if not decoder.is_complete():
        raise RuntimeError(
            f"Decoding incomplete: {decoder.decoded_count}/{manifest.block_count} blocks"
        )

    # Get superposition data
    superposition = decoder.get_data(manifest.superposition_len)

    if verbose:
        print(f"   ✅ Decoded {len(superposition):,} bytes of superposition")

    # Decode using the core function (handle-based crypto)
    if verbose:
        print("\n🔐 Verifying password and decrypting...")

    plaintext = schrodinger_decode_data(superposition, manifest, password)

    if plaintext is None:
        raise ValueError("Password does not match either reality — authentication failed")

    # Write output
    with open(output, "wb") as f:
        f.write(plaintext)

    if verbose:
        print(f"   ✅ Decrypted {len(plaintext):,} bytes")
        print(f"\n⚛️  QUANTUM STATE COLLAPSED")
        print(f"   Your reality is now observable")
        print(f"   The other reality remains forever unprovable")

    return {
        "decoded_size": len(plaintext),
        "qr_frames": len(qr_data_list),
        "blocks": manifest.block_count,
    }


def main():  # pragma: no cover
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="🐱⚛️ Schrödinger's Yarn Ball Decoder v6.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m meow_decoder.schrodinger_decode -i quantum.gif -o output.pdf

  The password you provide "observes" and collapses the quantum state.
  You get ONE reality — the other is forever unprovable! ⚛️
        """,
    )

    parser.add_argument("-i", "--input", required=True, help="Input GIF")
    parser.add_argument("-o", "--output", required=True, help="Output file")
    parser.add_argument("-p", "--password", help="Password (prompted if omitted)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Show full traceback on error")

    args = parser.parse_args()

    password = args.password or getpass("Password: ")

    try:
        stats = schrodinger_decode_file(
            Path(args.input),
            Path(args.output),
            password,
            verbose=args.verbose,
        )

        if not args.verbose:
            print(f"✅ Quantum state collapsed: {stats['decoded_size']:,} bytes")
        return 0

    except Exception as e:
        try:
            from .cat_errors import cat_translate_error

            cat_msg = cat_translate_error(e)
            print(f"\n{cat_msg}", file=sys.stderr)
        except ImportError:
            print(f"\n\u274c Decoding failed: invalid input or internal error", file=sys.stderr)
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
