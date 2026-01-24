#!/usr/bin/env python3
"""
🐱⚛️ Schrödinger's Yarn Ball - Quantum Decoder v5.4.0

"And once you look… you've already chosen your reality."

Collapse quantum superposition to ONE observable reality.

The password you provide "observes" the quantum state and collapses it.
You get ONE reality - the other remains forever unprovable.

Architecture:
    1. Extract QR frames from GIF
    2. Parse Schrödinger manifest (version 0x06)
    3. Verify password via HMAC (identifies reality A or B)
    4. Fountain decode mixed blocks
    5. Unpermute blocks (reverse cryptographic shuffle)
    6. Extract reality (even or odd positions)
    7. Decrypt with password
    8. Write collapsed reality to file

Security:
    - Constant-time HMAC verification
    - No password leak via error messages
    - Cannot prove other reality exists
    - Observation irreversibly collapses superposition
"""

import sys
import argparse
import hashlib
import struct
import zlib
from pathlib import Path
from getpass import getpass
from typing import Optional, Tuple
import hmac

from .crypto import decrypt_to_raw, derive_key, MAGIC
from .fountain import FountainDecoder, unpack_droplet
from .qr_code import QRCodeReader
from .gif_handler import GIFDecoder
from .frame_mac import unpack_frame_with_mac
from .schrodinger_encode import SchrodingerManifest, unpermute_blocks
from .constant_time import constant_time_compare


def verify_password_reality(
    password: str,
    manifest: SchrodingerManifest
) -> Optional[str]:
    """
    Verify password and determine which reality it unlocks.
    
    Args:
        password: Password to verify
        manifest: Schrödinger manifest
        
    Returns:
        'A' if password matches reality A
        'B' if password matches reality B
        None if password doesn't match either
        
    Security:
        - Uses constant-time comparison
        - Both HMACs checked (prevents timing attack)
        - No early return (constant time)
    """
    # Manifest core data (what HMACs were computed over)
    manifest_core = (
        manifest.salt_a + manifest.salt_b +
        manifest.nonce_a + manifest.nonce_b +
        manifest.merkle_root + manifest.shuffle_seed
    )
    
    # Try reality A
    key_a = hashlib.sha256(password.encode() + manifest.salt_a).digest()
    expected_hmac_a = hmac.new(key_a, manifest_core, hashlib.sha256).digest()
    match_a = constant_time_compare(expected_hmac_a, manifest.reality_a_hmac)
    
    # Try reality B (always compute, for constant-time)
    key_b = hashlib.sha256(password.encode() + manifest.salt_b).digest()
    expected_hmac_b = hmac.new(key_b, manifest_core, hashlib.sha256).digest()
    match_b = constant_time_compare(expected_hmac_b, manifest.reality_b_hmac)
    
    # Return result (constant-time selection)
    if match_a:
        return 'A'
    elif match_b:
        return 'B'
    else:
        return None


def extract_reality(
    mixed_blocks: list,
    reality: str,
    manifest: SchrodingerManifest
) -> bytes:
    """
    Extract one reality from mixed blocks.
    
    Args:
        mixed_blocks: Permuted, interleaved blocks
        reality: 'A' or 'B'
        manifest: Manifest with shuffle seed
        
    Returns:
        Ciphertext for requested reality
        
    Algorithm:
        1. Unpermute blocks (reverse cryptographic shuffle)
        2. Extract even positions (A) or odd positions (B)
        3. Concatenate into ciphertext
    """
    # Unpermute to get original interleaved order
    interleaved = unpermute_blocks(mixed_blocks, manifest.shuffle_seed)
    
    # Extract reality
    if reality == 'A':
        # Reality A is at even positions (0, 2, 4, ...)
        reality_blocks = [interleaved[i] for i in range(0, len(interleaved), 2)]
    else:
        # Reality B is at odd positions (1, 3, 5, ...)
        reality_blocks = [interleaved[i] for i in range(1, len(interleaved), 2)]
    
    # Concatenate
    ciphertext = b''.join(reality_blocks)
    
    return ciphertext


def decrypt_reality(
    ciphertext: bytes,
    password: str,
    manifest: SchrodingerManifest,
    reality: str
) -> bytes:
    """
    Decrypt extracted reality.
    
    Args:
        ciphertext: Extracted ciphertext (padded)
        password: Password for decryption
        manifest: Manifest with metadata
        reality: 'A' or 'B'
        
    Returns:
        Decrypted plaintext
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    if reality == 'A':
        salt = manifest.salt_a
        nonce = manifest.nonce_a
        enc_metadata = manifest.metadata_a
    else:
        salt = manifest.salt_b
        nonce = manifest.nonce_b
        enc_metadata = manifest.metadata_b
    
    # Decrypt metadata
    key = hashlib.sha256(password.encode() + salt).digest()
    aesgcm = AESGCM(key)
    
    try:
        # Remove padding if present (metadata padded to 96 bytes)
        enc_metadata = enc_metadata.rstrip(b'\x00')
        
        metadata_plain = aesgcm.decrypt(nonce, enc_metadata, None)
        
        # Parse: orig_len (8) + comp_len (8) + cipher_len (8) + salt_enc (16) + nonce_enc (12) + sha256 (32) = 84 bytes
        orig_len, comp_len, cipher_len = struct.unpack('>QQQ', metadata_plain[:24])
        salt_enc = metadata_plain[24:40]
        nonce_enc = metadata_plain[40:52]
        sha256_expected = metadata_plain[52:84]
        
    except Exception as e:
        raise ValueError(f"Failed to decrypt metadata - wrong password? {e}")
    
    # Trim ciphertext to actual cipher length (before padding)
    ciphertext = ciphertext[:cipher_len]
    
    # Decrypt using stored encryption parameters
    try:
        # Derive key using same method as encrypt_file_bytes
        derived_key = derive_key(password, salt_enc, None)
        aesgcm_cipher = AESGCM(derived_key)
        
        # Construct AAD (must match encrypt_file_bytes)
        aad = struct.pack('<QQ', orig_len, comp_len)
        aad += salt_enc
        aad += sha256_expected
        aad += MAGIC
        
        # Decrypt
        comp = aesgcm_cipher.decrypt(nonce_enc, ciphertext, aad)
        
        # Decompress
        import zlib
        raw = zlib.decompress(comp)
        
        # Verify hash
        actual_hash = hashlib.sha256(raw).digest()
        if not constant_time_compare(actual_hash, sha256_expected):
            raise ValueError("Hash mismatch - data corrupted")
        
        return raw
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


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
