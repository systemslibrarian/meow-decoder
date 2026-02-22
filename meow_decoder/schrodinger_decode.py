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
    manifest: SchrodingerManifest,
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

    Security:
        - TIMING-SAFE: Both Argon2id derivations run ALWAYS to prevent timing oracle
        - TIMING-SAFE: Both HMAC verifications run ALWAYS to prevent reality detection
        - Uses constant_time_compare for auth tag checks
        - Random delay added to mask any residual timing differences
    """
    hb = get_handle_backend()

    # SECURITY (TIMING-01): Derive BOTH keys upfront to prevent timing oracle.
    # Argon2id is the dominant cost — must always run for both salts.
    master_meta_key_a = hb.derive_key_argon2id(
        password.encode("utf-8"), manifest.salt_a,
        memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    master_meta_key_b = hb.derive_key_argon2id(
        password.encode("utf-8"), manifest.salt_b,
        memory_kib=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS,
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

    # SECURITY (TIMING-02): Check BOTH HMACs to avoid early-exit timing leak.
    is_reality_a = _get_backend().constant_time_compare(
        expected_hmac_a, manifest.reality_a_hmac
    )
    is_reality_b = _get_backend().constant_time_compare(
        expected_hmac_b, manifest.reality_b_hmac
    )

    # Random delay to mask any residual timing differences (1-10ms)
    time.sleep(secrets.randbelow(10) / 1000.0)

    # Now branch based on which reality matched (if any)
    if is_reality_a:
        try:
            # Derive encryption key for Reality A (handle-based)
            enc_key_a = hb.derive_key_hkdf(
                master_meta_key_a,
                manifest.salt_a,
                b"schrodinger_enc_key_v1",
                32,
            )

            # Decrypt metadata (handle-based AES-GCM)
            metadata_a_plain = hb.aes_gcm_decrypt(
                enc_key_a, manifest.nonce_a, manifest.metadata_a, None
            )
            hb.drop(enc_key_a)

            # Unpack metadata:
            # orig_len(8) + comp_len(8) + cipher_len(8) + salt_enc(16) +
            # nonce_enc(12) + sha256(32) + pad(4) = 88 bytes
            orig_len, comp_len, cipher_len = struct.unpack(
                ">QQQ", metadata_a_plain[:24]
            )
            salt_enc = metadata_a_plain[24:40]
            nonce_enc = metadata_a_plain[40:52]
            sha256 = metadata_a_plain[52:84]

            # Collapse superposition to get ciphertext A (even blocks)
            ciphertext_a = collapse_to_reality(superposition, 0)
            ciphertext_a = ciphertext_a[:cipher_len]

            # Decrypt the actual file data via handle-based API
            plaintext = decrypt_to_raw_handle(
                cipher=ciphertext_a,
                password=password,
                salt=salt_enc,
                nonce=nonce_enc,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256,
            )

            # Drop master key handles before returning
            for h in (master_meta_key_a, master_meta_key_b):
                try:
                    hb.drop(h)
                except Exception:
                    pass

            return plaintext
        except Exception:
            # Decryption failed despite HMAC match — data corrupted
            pass

    if is_reality_b:
        try:
            # Derive encryption key for Reality B (handle-based)
            enc_key_b = hb.derive_key_hkdf(
                master_meta_key_b,
                manifest.salt_b,
                b"schrodinger_enc_key_v1",
                32,
            )

            # Decrypt metadata (handle-based AES-GCM)
            metadata_b_plain = hb.aes_gcm_decrypt(
                enc_key_b, manifest.nonce_b, manifest.metadata_b, None
            )
            hb.drop(enc_key_b)

            # Unpack metadata
            orig_len, comp_len, cipher_len = struct.unpack(
                ">QQQ", metadata_b_plain[:24]
            )
            salt_enc = metadata_b_plain[24:40]
            nonce_enc = metadata_b_plain[40:52]
            sha256 = metadata_b_plain[52:84]

            # Collapse superposition to get ciphertext B (odd blocks)
            ciphertext_b = collapse_to_reality(superposition, 1)
            ciphertext_b = ciphertext_b[:cipher_len]

            # Decrypt the actual file data via handle-based API
            plaintext = decrypt_to_raw_handle(
                cipher=ciphertext_b,
                password=password,
                salt=salt_enc,
                nonce=nonce_enc,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256,
            )

            # Drop master key handles before returning
            for h in (master_meta_key_a, master_meta_key_b):
                try:
                    hb.drop(h)
                except Exception:
                    pass

            return plaintext
        except Exception:
            # Decryption failed despite HMAC match — data corrupted
            pass

    # Drop master key handles (zeroize in Rust)
    for h in (master_meta_key_a, master_meta_key_b):
        try:
            hb.drop(h)
        except Exception:
            pass

    # Neither password worked
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
    from .frame_mac import unpack_frame_with_mac

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

    # Parse manifest (frame 0)
    if verbose:
        print("\n⚛️  Parsing quantum manifest...")

    manifest_raw = qr_data_list[0]

    # Strip frame MAC if present (first 8 bytes)
    if len(manifest_raw) > 400:
        manifest_raw = manifest_raw[8:]

    try:
        manifest = SchrodingerManifest.unpack(manifest_raw)
    except Exception as e:
        raise ValueError(f"Failed to parse manifest: {e}")

    if verbose:
        print(f"   Version: 0x{manifest.version:02x} (Schrödinger v6.0.0)")
        print(f"   Blocks: {manifest.block_count}")
        print(f"   Block size: {manifest.block_size}")
        print(f"   Superposition length: {manifest.superposition_len}")

    # Extract and reassemble droplets
    droplets = []

    for i, frame_data in enumerate(qr_data_list[1:], 1):
        # Skip frame MAC (first 8 bytes) if present
        if len(frame_data) > manifest.block_size + 20:
            droplet_data = frame_data[8:]
        else:
            droplet_data = frame_data

        try:
            droplet = unpack_droplet(droplet_data, manifest.block_size)
            droplets.append(droplet)
        except Exception as e:
            if verbose:
                print(f"   ⚠️  Frame {i} unpack failed: {e}")
            continue

    if verbose:
        print(f"\n🌊 Fountain decoding {len(droplets)} droplets...")

    # Fountain decode
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
        raise ValueError(
            "Password does not match either reality — authentication failed"
        )

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
            print(f"\n❌ Decoding failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
