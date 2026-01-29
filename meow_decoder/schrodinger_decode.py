#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Dual Reality Decoder

This decoder collapses the quantum superposition based on the provided password,
revealing one of the two hidden realities.
"""
from __future__ import annotations

import sys
import argparse
import struct
import hashlib
import hmac
from pathlib import Path
from typing import Tuple, Optional
from getpass import getpass

from .crypto import decrypt_to_raw, derive_key
from .quantum_mixer import collapse_to_reality
from .schrodinger_encode import SchrodingerManifest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import secrets


def schrodinger_decode_data(
    superposition: bytes,
    manifest: SchrodingerManifest,
    password: str,
) -> Optional[bytes]:
    """
    Decode one reality from the superposition based on the password.

    Args:
        superposition: The interleaved ciphertext.
        manifest: The Schrödinger manifest.
        password: The password for one of the realities.

    Returns:
        The decrypted data if the password is correct for either reality,
        otherwise None.
    """
    # Try to decode Reality A
    try:
        # Derive master metadata key using Argon2id
        master_meta_key_a = derive_key(password, manifest.salt_a)

        # Derive separate keys for encryption and HMAC
        hkdf_hmac_a = HKDF(algorithm=hashes.SHA256(), length=32, salt=manifest.salt_a, info=b"schrodinger_hmac_key_v1")
        hmac_key_a = hkdf_hmac_a.derive(master_meta_key_a)

        # Verify HMAC for Reality A
        manifest_core = manifest.pack_core_for_auth()
        expected_hmac_a = hmac.new(hmac_key_a, manifest_core, hashlib.sha256).digest()

        if secrets.compare_digest(expected_hmac_a, manifest.reality_a_hmac):
            # HMAC is valid, this is Reality A
            hkdf_enc_a = HKDF(algorithm=hashes.SHA256(), length=32, salt=manifest.salt_a, info=b"schrodinger_enc_key_v1")
            enc_key_a = hkdf_enc_a.derive(master_meta_key_a)

            # Decrypt metadata
            aesgcm_a = AESGCM(enc_key_a)
            # The encoder pads the PLAINTEXT metadata to 88 bytes, then AES-GCM encrypts it.
            # AES-GCM returns ciphertext+tag with a fixed length of 104 bytes (88 + 16).
            # Do not truncate here, or tag verification will fail.
            metadata_a_plain = aesgcm_a.decrypt(manifest.nonce_a, manifest.metadata_a, None)


            # Unpack metadata
            orig_len, comp_len, cipher_len = struct.unpack('>QQQ', metadata_a_plain[:24])
            salt_enc = metadata_a_plain[24:40]
            nonce_enc = metadata_a_plain[40:52]
            sha256 = metadata_a_plain[52:84]

            # Collapse superposition to get ciphertext A
            ciphertext_a = collapse_to_reality(superposition, 0)
            
            # The stored cipher_len is for the *unpadded* ciphertext.
            # We need to truncate the collapsed data to that length.
            ciphertext_a = ciphertext_a[:cipher_len]

            # Decrypt the actual file data
            return decrypt_to_raw(
                cipher=ciphertext_a,
                password=password,
                salt=salt_enc,
                nonce=nonce_enc,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256,
            )
    except Exception:
        # This password is not for Reality A, or data is corrupt.
        # We'll try Reality B next.
        pass

    # Try to decode Reality B
    try:
        # Derive master metadata key using Argon2id
        master_meta_key_b = derive_key(password, manifest.salt_b)

        # Derive separate keys for encryption and HMAC
        hkdf_hmac_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=manifest.salt_b, info=b"schrodinger_hmac_key_v1")
        hmac_key_b = hkdf_hmac_b.derive(master_meta_key_b)

        # Verify HMAC for Reality B
        manifest_core = manifest.pack_core_for_auth()
        expected_hmac_b = hmac.new(hmac_key_b, manifest_core, hashlib.sha256).digest()

        if secrets.compare_digest(expected_hmac_b, manifest.reality_b_hmac):
            # HMAC is valid, this is Reality B
            hkdf_enc_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=manifest.salt_b, info=b"schrodinger_enc_key_v1")
            enc_key_b = hkdf_enc_b.derive(master_meta_key_b)

            # Decrypt metadata
            aesgcm_b = AESGCM(enc_key_b)
            metadata_b_plain = aesgcm_b.decrypt(manifest.nonce_b, manifest.metadata_b, None)

            # Unpack metadata
            orig_len, comp_len, cipher_len = struct.unpack('>QQQ', metadata_b_plain[:24])
            salt_enc = metadata_b_plain[24:40]
            nonce_enc = metadata_b_plain[40:52]
            sha256 = metadata_b_plain[52:84]

            # Collapse superposition to get ciphertext B
            ciphertext_b = collapse_to_reality(superposition, 1)
            
            # Truncate to original length
            ciphertext_b = ciphertext_b[:cipher_len]

            # Decrypt the actual file data
            return decrypt_to_raw(
                cipher=ciphertext_b,
                password=password,
                salt=salt_enc,
                nonce=nonce_enc,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256,
            )
    except Exception:
        # This password is not for Reality B either.
        pass

    # If neither password worked
    return None


def schrodinger_decode_file(
    input_gif: Path,
    output: Path,
    password: str,
    verbose: bool = False
) -> dict:
    """
    Decode file from Schrödinger mode GIF.
    
    Args:
        input_gif: Input GIF with quantum superposition
        output: Output file
        password: Password (collapses quantum state)
        verbose: Verbose output
        
    Returns:
        Statistics dict
    """
    # Import heavy dependencies only when needed to avoid circular imports
    from .gif_handler import GIFDecoder
    from .qr_code import QRCodeReader
    from .fountain import FountainDecoder, unpack_droplet
    from .frame_mac import unpack_frame_with_mac, derive_frame_master_key
    
    if verbose:
        print("🐱⚛️  Schrödinger's Yarn Ball - Quantum Decoder v5.5.0")
        print("=" * 60)
        print('"And once you look… you\'ve already chosen your reality."')
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
    
    # Parse manifest
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
        print(f"   Version: 0x{manifest.version:02x} (Schrödinger v5.5.0)")
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
    
    # Decode using the core function
    if verbose:
        print(f"\n🔐 Verifying password and decrypting...")
    
    plaintext = schrodinger_decode_data(superposition, manifest, password)
    
    if plaintext is None:
        raise ValueError("Password does not match either reality - authentication failed")
    
    # Write output
    with open(output, 'wb') as f:
        f.write(plaintext)
    
    if verbose:
        print(f"   ✅ Decrypted {len(plaintext):,} bytes")
        print(f"\n⚛️  QUANTUM STATE COLLAPSED")
        print(f"   Your reality is now observable")
        print(f"   The other reality remains forever unprovable")
        print(f"   Lost in the quantum foam... 🌊")
    
    return {
        'decoded_size': len(plaintext),
        'qr_frames': len(qr_data_list),
        'blocks': manifest.block_count
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='🐱⚛️ Schrödinger\'s Yarn Ball Decoder v5.5.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Decode (auto-detect reality):
  python -m meow_decoder.schrodinger_decode -i quantum.gif -o output.pdf
  
  # The password you provide "observes" and collapses the quantum state!
  # You get ONE reality - the other is forever unprovable! ⚛️
        '''
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input GIF')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    parser.add_argument('-p', '--password', help='Password (prompted if omitted)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Get password
    password = args.password or getpass("Password: ")
    
    # Decode
    try:
        stats = schrodinger_decode_file(
            Path(args.input),
            Path(args.output),
            password,
            verbose=args.verbose
        )
        
        if not args.verbose:
            print(f"✅ Quantum state collapsed: {stats['decoded_size']:,} bytes")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
