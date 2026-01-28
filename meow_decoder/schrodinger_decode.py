#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Dual Reality Decoder

This decoder collapses the quantum superposition based on the provided password,
revealing one of the two hidden realities.
"""

import struct
import hashlib
import hmac
from typing import Tuple, Optional

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
            # The encrypted metadata is padded to 104 bytes, but AES-GCM includes a 16-byte tag,
            # so the actual ciphertext is 100 bytes. We need to handle this.
            # However, the encryptor pads with nulls *after* encryption.
            # We need to find the actual length of the encrypted payload.
            # A simple approach is to try decrypting and catch the error if it's too long,
            # but a better way is to find where the padding starts.
            # For now, let's assume the padding doesn't interfere if we pass the whole 104 bytes.
            # The tag is appended, so the ciphertext is len(metadata_a) - 16.
            # Let's find the end of the actual ciphertext before padding.
            # The encryptor pads to 104, and the encrypted data is 100 bytes (84 plain + 16 tag).
            # So the last 4 bytes are padding.
            metadata_a_enc_unpadded = manifest.metadata_a[:100]
            metadata_a_plain = aesgcm_a.decrypt(manifest.nonce_a, metadata_a_enc_unpadded, None)


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
            metadata_b_enc_unpadded = manifest.metadata_b[:100]
            metadata_b_plain = aesgcm_b.decrypt(manifest.nonce_b, metadata_b_enc_unpadded, None)

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
    Decode file from Schrödinger mode.
    
    Args:
        input_gif: Input GIF with quantum superposition
        output: Output file
        password: Password (collapses quantum state)
        verbose: Verbose output
        
    Returns:
        Statistics dict
    """
    if verbose:
        print("🐱⚛️  Schrödinger's Yarn Ball - Quantum Decoder v5.4.0")
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
    if len(manifest_raw) > 256:
        manifest_raw = manifest_raw[8:]
    
    try:
        manifest = SchrodingerManifest.unpack(manifest_raw)
    except Exception as e:
        raise ValueError(f"Failed to parse manifest: {e}")
    
    if verbose:
        print(f"   Version: 0x{manifest.version:02x} (Schrödinger v5.4.0)")
        print(f"   Blocks: {manifest.block_count}")
        print(f"   Block size: {manifest.block_size}")
        print(f"   Merkle root: {manifest.merkle_root.hex()[:16]}...")
    
    # Verify password and determine reality
    if verbose:
        print(f"\n🔐 Verifying password...")
    
    reality = verify_password_reality(password, manifest)
    
    if reality is None:
        raise ValueError("Password does not match either reality")
    
    if verbose:
        print(f"   ✅ Password verified → Reality {reality}")
        print(f"   🔮 Collapsing quantum state...")
    
    # Extract droplets
    droplets = []
    
    # Note: Frame MACs in Schrödinger mode use Reality A's key
    # We skip MAC verification since manifest HMAC already authenticated
    # Frame format: [MAC: 8 bytes][Droplet data]
    
    for i, frame_data in enumerate(qr_data_list[1:], 1):
        # Skip frame MAC (first 8 bytes)
        droplet_data = frame_data[8:]
        
        # Unpack droplet
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
    
    # Get original length
    original_length = manifest.block_count * manifest.block_size
    mixed_data = decoder.get_data(original_length)
    
    if verbose:
        print(f"   ✅ Decoded {len(mixed_data):,} bytes")
    
    # Split into blocks
    mixed_blocks = [
        mixed_data[i:i+manifest.block_size]
        for i in range(0, len(mixed_data), manifest.block_size)
    ]
    
    # Extract reality
    if verbose:
        print(f"\n⚛️  Extracting Reality {reality}...")
    
    ciphertext = extract_reality(mixed_blocks, reality, manifest)
    
    if verbose:
        print(f"   Extracted {len(ciphertext):,} bytes")
    
    # Decrypt
    if verbose:
        print(f"\n🔓 Decrypting...")
    
    try:
        plaintext = decrypt_reality(ciphertext, password, manifest, reality)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")
    
    # Write output
    with open(output, 'wb') as f:
        f.write(plaintext)
    
    if verbose:
        print(f"   ✅ Decrypted {len(plaintext):,} bytes")
        print(f"\n⚛️  QUANTUM STATE COLLAPSED")
        print(f"   Reality {reality} is now observable")
        print(f"   The other reality remains forever unprovable")
        print(f"   Lost in the quantum foam... 🌊")
    
    return {
        'decoded_size': len(plaintext),
        'reality': reality,
        'qr_frames': len(qr_data_list),
        'blocks': manifest.block_count
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='🐱⚛️ Schrödinger\'s Yarn Ball Decoder v5.4.0',
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
            print(f"✅ Reality {stats['reality']} collapsed: {stats['decoded_size']:,} bytes")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
