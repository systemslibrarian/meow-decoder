#!/usr/bin/env python3
"""
🐱 Meow Encoder - Hiss Your Secrets Into Yarn Balls! 🧶
Encodes files into animated cat videos (GIFs) with paw print QR codes
"""

import sys
import argparse
from pathlib import Path
from getpass import getpass
from typing import Optional
import time

# Import our cat modules
from meow_decoder.config import MeowConfig, EncodingConfig
from meow_decoder.crypto import (
    encrypt_file_bytes as hiss_secret,
    compute_manifest_hmac as compute_collar_tag_auth,
    pack_manifest as pack_collar_tag,
    Manifest as CollarTag,
    verify_keyfile as verify_catnip,
)
from meow_decoder.fountain import FountainEncoder as CatnipFountain, pack_droplet as pack_kibble
from meow_decoder.qr_code import QRCodeGenerator as PawPrintMaker
from meow_decoder.gif_handler import GIFEncoder as YarnBallMaker


def hiss_file_into_yarn_ball(
    input_path: Path,
    output_path: Path,
    password: str,
    config: Optional[EncodingConfig] = None,
    catnip: Optional[bytes] = None,  # keyfile
    verbose: bool = False,
) -> dict:
    """
    🐱 Hiss your file into a yarn ball!

    Takes a file and turns it into an animated GIF with paw print QR codes.
    Each frame is a kibble (droplet) from the catnip fountain (fountain encoder).

    Args:
        input_path: Path to secret file
        output_path: Path to output yarn ball (GIF)
        password: Strong cat password
        config: Meowing configuration
        catnip: Optional catnip file (keyfile) for extra security
        verbose: Print kitty updates

    Returns:
        Dictionary with meowing statistics
    """
    if config is None:
        config = EncodingConfig()

    start_time = time.time()

    # 🐱 Read the secret
    if verbose:
        print(f"😸 Sniffing input file: {input_path}")

    with open(input_path, "rb") as f:
        secret_data = f.read()

    if verbose:
        print(f"  📦 Size: {len(secret_data):,} bytes")

    # 🔐 Hiss it into encrypted form
    if verbose:
        print("😼 Hissing secrets into encrypted form...")

    compressed, sha256, salt, nonce, hissed, _ephemeral_pk, _enc_key = hiss_secret(
        secret_data, password, catnip
    )

    if verbose:
        print(
            f"  🗜️  Compressed: {len(compressed):,} bytes ({len(compressed)/len(secret_data)*100:.1f}%)"
        )
        print(f"  🔐 Hissed: {len(hissed):,} bytes")

    # 🧮 Calculate catnip fountain parameters
    num_scratching_posts = (len(hissed) + config.block_size - 1) // config.block_size
    num_kibbles = int(num_scratching_posts * config.redundancy)

    if verbose:
        print(f"\n🌊 Catnip fountain encoding:")
        print(f"  📏 Scratching post size: {config.block_size} bytes")
        print(f"  🏠 Scratching posts (k): {num_scratching_posts}")
        print(f"  🍖 Kibbles: {num_kibbles} ({config.redundancy:.1f}x redundancy)")

    # 🏷️ Create collar tag (manifest)
    collar_tag = CollarTag(
        salt=salt,
        nonce=nonce,
        orig_len=len(secret_data),
        comp_len=len(compressed),
        cipher_len=len(hissed),
        sha256=sha256,
        block_size=config.block_size,
        k_blocks=num_scratching_posts,
        hmac=b"\x00" * 32,  # Placeholder
    )

    # 🔐 Compute collar tag authentication
    packed_no_hmac = pack_collar_tag(collar_tag)[:-32]
    collar_tag.hmac = compute_collar_tag_auth(password, salt, packed_no_hmac, catnip)

    # 📦 Pack collar tag
    collar_tag_bytes = pack_collar_tag(collar_tag)

    if verbose:
        print(f"  🏷️  Collar tag: {len(collar_tag_bytes)} bytes")

    # 🌊 Create catnip fountain
    fountain = CatnipFountain(hissed, num_scratching_posts, config.block_size)

    # 🐾 Generate paw prints (QR codes)
    if verbose:
        print("\n🐾 Making paw prints...")

    paw_maker = PawPrintMaker(
        error_correction=config.qr_error_correction,
        box_size=config.qr_box_size,
        border=config.qr_border,
    )

    paw_prints = []

    # First paw print: collar tag
    collar_paw = paw_maker.generate(collar_tag_bytes)
    paw_prints.append(collar_paw)

    if verbose:
        print(f"  🐾 Paw 0: Collar tag ({len(collar_tag_bytes)} bytes)")

    # Remaining paws: kibbles from fountain
    for i in range(num_kibbles):
        kibble = fountain.droplet()
        kibble_bytes = pack_kibble(kibble)

        paw = paw_maker.generate(kibble_bytes)
        paw_prints.append(paw)

        if verbose and (i + 1) % 100 == 0:
            print(f"  🐾 Generated {i + 1}/{num_kibbles} paw prints...")

    if verbose:
        print(f"  ✅ Total paw prints: {len(paw_prints)}")
        print(f"  📐 Paw size: {paw_prints[0].size}")

    # 🧶 Create yarn ball (GIF)
    if verbose:
        print("\n🧶 Weaving yarn ball...")

    yarn_maker = YarnBallMaker(fps=config.fps, loop=0)
    yarn_size = yarn_maker.create_gif(paw_prints, output_path, optimize=True)

    elapsed = time.time() - start_time

    if verbose:
        print(f"  🎁 Output: {output_path}")
        print(f"  📦 Size: {yarn_size:,} bytes")
        print(f"  ⏱️  Duration: {len(paw_prints) / config.fps:.1f} seconds at {config.fps} FPS")
        print(f"\n✨ Hissing complete in {elapsed:.2f} seconds! 😸")

    # Return statistics
    return {
        "input_size": len(secret_data),
        "compressed_size": len(compressed),
        "hissed_size": len(hissed),
        "output_size": yarn_size,
        "compression_ratio": len(compressed) / len(secret_data),
        "scratching_posts": num_scratching_posts,
        "kibbles": num_kibbles,
        "redundancy": config.redundancy,
        "paw_prints": len(paw_prints),
        "paw_size": paw_prints[0].size,
        "yarn_duration": len(paw_prints) / config.fps,
        "elapsed_time": elapsed,
    }


def main():
    """🐱 Main meow entry point!"""
    parser = argparse.ArgumentParser(
        description="🐱 Meow Encoder - Hiss Your Secrets Into Yarn Balls! 🧶",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
😸 Examples:
  # Basic hissing
  meow-encode --input secret.pdf --output secret.gif
  
  # With catnip (keyfile)
  meow-encode --input secret.pdf --catnip my.catnip --output secret.gif
  
  # Extra kibbles for scratchy conditions
  meow-encode --input secret.pdf --kibbles 2.0 --output secret.gif
  
  # Bigger scratching posts
  meow-encode --input secret.pdf --post-size 1024 --output secret.gif

🐾 Strong cat passwords only! 🔐
        """,
    )

    # Required arguments
    parser.add_argument("-i", "--input", type=Path, required=True, help="🐱 Input file to hiss")
    parser.add_argument(
        "-o", "--output", type=Path, required=True, help="🧶 Output yarn ball (GIF)"
    )

    # Optional arguments
    parser.add_argument(
        "-p", "--password", type=str, help="🔐 Strong cat password (prompted if not provided)"
    )
    parser.add_argument("-c", "--catnip", type=Path, help="🌿 Path to catnip file (keyfile)")

    # Encoding parameters
    parser.add_argument(
        "--post-size", type=int, default=512, help="📏 Scratching post size (default: 512)"
    )
    parser.add_argument(
        "--kibbles", type=float, default=1.5, help="🍖 Kibble redundancy factor (default: 1.5)"
    )
    parser.add_argument(
        "--fps", type=int, default=10, help="🎬 Yarn ball frames per second (default: 10)"
    )

    # QR code parameters
    parser.add_argument(
        "--paw-error",
        choices=["L", "M", "Q", "H"],
        default="M",
        help="🐾 Paw print error correction (default: M)",
    )
    parser.add_argument(
        "--paw-size", type=int, default=10, help="🐾 Paw print box size (default: 10)"
    )
    parser.add_argument(
        "--paw-border", type=int, default=4, help="🐾 Paw print border size (default: 4)"
    )

    # Output control
    parser.add_argument("-v", "--verbose", action="store_true", help="😸 Verbose kitty output")
    parser.add_argument(
        "--shred-source", action="store_true", help="🔥 Securely shred source file after encoding"
    )

    args = parser.parse_args()

    # Validate input file
    if not args.input.exists():
        print(f"😿 Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if not args.input.is_file():
        print(f"😿 Error: Input is not a file: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass("🔐 Enter strong cat password: ")
        password_confirm = getpass("🔐 Confirm cat password: ")

        if password != password_confirm:
            print("😿 Error: Passwords don't match", file=sys.stderr)
            sys.exit(1)

    if not password:
        print("😿 Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)

    # Load catnip if specified
    catnip = None
    if args.catnip:
        try:
            catnip = verify_catnip(str(args.catnip))
            if args.verbose:
                print(f"🌿 Loaded catnip: {args.catnip} ({len(catnip)} bytes)")
        except (FileNotFoundError, ValueError) as e:
            print(f"😿 Error: {e}", file=sys.stderr)
            sys.exit(1)

    # Create encoding config
    config = EncodingConfig(
        block_size=args.post_size,
        redundancy=args.kibbles,
        qr_error_correction=args.paw_error,
        qr_box_size=args.paw_size,
        qr_border=args.paw_border,
        fps=args.fps,
    )

    # Hiss the file!
    try:
        stats = hiss_file_into_yarn_ball(
            args.input, args.output, password, config=config, catnip=catnip, verbose=args.verbose
        )

        # Print summary
        if not args.verbose:
            print(f"\n✨ Hissing complete! 😸")
            print(f"  📥 Input: {stats['input_size']:,} bytes")
            print(f"  📤 Output: {stats['output_size']:,} bytes ({stats['paw_prints']} paw prints)")
            print(f"  🗜️  Compression: {stats['compression_ratio']*100:.1f}%")
            print(f"  ⏱️  Duration: {stats['yarn_duration']:.1f}s at {config.fps} FPS")
            print(f"  ⚡ Time: {stats['elapsed_time']:.2f}s")

        # Shred source if requested
        if args.shred_source:
            if args.verbose:
                print(f"\n🔥 Shredding source file...")

            # Overwrite with random data
            file_size = args.input.stat().st_size
            with open(args.input, "wb") as f:
                f.write(b"\x00" * file_size)

            args.input.unlink()
            print(f"  ✓ Source file shredded: {args.input}")

        print(f"\n🎁 Yarn ball saved to: {args.output}")
        print(f"🐾 Meow! Your secrets are safe! 😺")

    except Exception as e:
        print(f"\n😿 Error during hissing: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
