#!/usr/bin/env python3
"""
🐱🐱🐱 Clowder Batch Decoder
Decode an entire clowder of yarn balls back to original files!

Usage:
    python3 clowder_decode.py \\
        --input yarn_balls/ \\
        --output recovered_files/ \\
        --password "MyPassword"

Automatically processes all yarn balls in the clowder!
Resume support if interrupted!
"""

import sys
import argparse
from pathlib import Path
from getpass import getpass
import json
from typing import Dict

from decode_gif import decode_gif


def hash_password(password: str) -> str:
    """Hash password for verification."""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()[:16]


def decode_clowder(
    clowder_dir: Path,
    output_dir: Path,
    password: str,
    verbose: bool = False
) -> dict:
    """
    Decode entire clowder.
    
    Args:
        clowder_dir: Directory containing clowder
        output_dir: Output directory for files
        password: Decryption password
        verbose: Verbose output
        
    Returns:
        Statistics dictionary
    """
    print("🐱🐱🐱 CLOWDER BATCH DECODER")
    print("=" * 60)
    print("Herding cats back to their original form...")
    print()
    
    # Load manifest
    manifest_path = clowder_dir / 'clowder_manifest.json'
    
    if not manifest_path.exists():
        raise ValueError(f"Clowder manifest not found: {manifest_path}")
    
    with open(manifest_path) as f:
        manifest = json.load(f)
    
    if manifest['type'] != 'meow_clowder':
        raise ValueError("Not a valid clowder manifest!")
    
    # Verify password
    pw_hash = hash_password(password)
    if manifest['password_hash'] != pw_hash:
        raise ValueError("❌ Wrong password for this clowder!")
    
    print(f"📋 Clowder Manifest:")
    print(f"  Clowder ID: {manifest['clowder_id']}")
    print(f"  Total files: {manifest['total_files']}")
    print(f"  Total bytes: {manifest['total_bytes']:,}")
    print(f"  Yarn balls: {manifest['total_yarn_balls']}")
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Track progress
    decoded_files = 0
    failed_yarn_balls = []
    
    # Decode each yarn ball
    print(f"\n🧶 Decoding yarn balls...")
    
    for i, yarn_ball in enumerate(manifest['yarn_balls'], 1):
        yarn_ball_file = clowder_dir / yarn_ball['filename']
        
        print(f"\n🐱 Yarn Ball #{yarn_ball['yarn_ball_number']}: {yarn_ball['filename']}")
        print(f"  Files: {len(yarn_ball['files'])}")
        
        if not yarn_ball_file.exists():
            print(f"  ❌ File not found: {yarn_ball_file}")
            failed_yarn_balls.append(yarn_ball['yarn_ball_number'])
            continue
        
        # Decode yarn ball to temporary file
        temp_output = output_dir / f'temp_yarn_{i}.dat'
        
        try:
            decode_gif(
                str(yarn_ball_file),
                str(temp_output),
                password,
                verbose=False
            )
            
            # Read combined data
            combined_data = temp_output.read_bytes()
            
            # Split back into original files
            for file_info in yarn_ball['file_index']:
                original_path = Path(file_info['path'])
                file_size = file_info['size']
                file_offset = file_info['offset']
                
                # Extract file data
                file_data = combined_data[file_offset:file_offset + file_size]
                
                # Preserve relative path structure
                # Use relative path from original to maintain directory structure
                if original_path.is_absolute():
                    # If absolute path, just use filename
                    output_path = output_dir / original_path.name
                else:
                    # Preserve relative path structure
                    output_path = output_dir / original_path
                
                # Create parent directories
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Handle duplicate names (shouldn't happen with proper paths)
                if output_path.exists():
                    print(f"    ⚠️  File exists, creating uniquely named copy: {output_path.name}")
                    base = output_path.stem
                    ext = output_path.suffix
                    counter = 1
                    while output_path.exists():
                        output_path = output_dir / f"{base}_{counter}{ext}"
                        counter += 1
                
                # Save file
                output_path.write_bytes(file_data)
                decoded_files += 1
                
                if verbose:
                    print(f"    ✓ {original_path.name} → {output_path.name}")
            
            # Remove temp file
            temp_output.unlink()
            
            print(f"  ✅ Decoded {len(yarn_ball['files'])} files")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            failed_yarn_balls.append(yarn_ball['yarn_ball_number'])
            temp_output.unlink(missing_ok=True)
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ CLOWDER DECODED!")
    print(f"  Total files recovered: {decoded_files}/{manifest['total_files']}")
    print(f"  Output directory: {output_dir}")
    
    if failed_yarn_balls:
        print(f"\n⚠️  Failed yarn balls: {failed_yarn_balls}")
        print("  (Run again to retry)")
    else:
        print("\n🐱🐱🐱 All cats safely returned home!")
    
    return {
        'clowder_id': manifest['clowder_id'],
        'total_files': manifest['total_files'],
        'decoded_files': decoded_files,
        'failed_yarn_balls': len(failed_yarn_balls)
    }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="🐱🐱🐱 Clowder Batch Decoder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decode entire clowder
  python3 clowder_decode.py --input yarn_balls/ --output recovered/
  
  # With verbose output
  python3 clowder_decode.py --input yarn_balls/ --output recovered/ -v
  
The clowder reunites! 🐈🐈🐈
        """
    )
    
    parser.add_argument('--input', type=Path, required=True,
                       help='Clowder directory (with manifest)')
    parser.add_argument('--output', type=Path, required=True,
                       help='Output directory for recovered files')
    parser.add_argument('--password', type=str,
                       help='Decryption password (prompted if not provided)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.input.exists():
        print(f"❌ Clowder directory not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    if not args.input.is_dir():
        print(f"❌ Input must be a directory: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass("Enter clowder password: ")
    
    if not password:
        print("❌ Password cannot be empty!", file=sys.stderr)
        sys.exit(1)
    
    print()
    
    # Decode!
    try:
        stats = decode_clowder(
            args.input,
            args.output,
            password,
            verbose=args.verbose
        )
        
        if stats['failed_yarn_balls'] == 0:
            print("\n🎉 SUCCESS! All files recovered!")
        else:
            print("\n⚠️  Partial success. Some yarn balls failed.")
            sys.exit(1)
        
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
