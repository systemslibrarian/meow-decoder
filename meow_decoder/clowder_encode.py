#!/usr/bin/env python3
"""
🐱🐱🐱 Clowder Batch Mode - Multi-File Encoder
Encode entire folders into a coordinated "clowder" of yarn ball GIFs!

A clowder is a group of cats - and now a group of encrypted GIFs! 🐈🐈🐈

Usage:
    python3 clowder_encode.py \\
        --input secrets_folder/ \\
        --output yarn_balls/ \\
        --password "MyPassword"

Creates:
    yarn_balls/
    ├── clowder_manifest.json
    ├── yarn_001.gif
    ├── yarn_002.gif
    ├── yarn_003.gif
    └── ...

Resume support: If interrupted, just run again with same parameters!
"""

import sys
import argparse
from pathlib import Path
from getpass import getpass
import json
import hashlib
from typing import List, Dict, Optional
from datetime import datetime

from .encode import encode_file
from .config import EncodingConfig


class ClowderManifest:
    """Master manifest for a clowder of yarn balls."""
    
    def __init__(self, clowder_id: str, password_hash: str):
        self.clowder_id = clowder_id
        self.password_hash = password_hash
        self.created_at = datetime.now().isoformat()
        self.total_files = 0
        self.total_bytes = 0
        self.yarn_balls: List[Dict] = []
        self.completed = False
        
    def add_yarn_ball(self, yarn_ball: Dict):
        """Add a yarn ball to the clowder."""
        self.yarn_balls.append(yarn_ball)
        
    def to_dict(self) -> dict:
        """Export to dictionary."""
        return {
            'type': 'meow_clowder',
            'version': '5.0',
            'clowder_id': self.clowder_id,
            'password_hash': self.password_hash,
            'created_at': self.created_at,
            'total_files': self.total_files,
            'total_bytes': self.total_bytes,
            'total_yarn_balls': len(self.yarn_balls),
            'yarn_balls': self.yarn_balls,
            'completed': self.completed
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ClowderManifest':
        """Load from dictionary."""
        manifest = cls(data['clowder_id'], data['password_hash'])
        manifest.created_at = data['created_at']
        manifest.total_files = data['total_files']
        manifest.total_bytes = data['total_bytes']
        manifest.yarn_balls = data['yarn_balls']
        manifest.completed = data.get('completed', False)
        return manifest


def collect_files(input_path: Path) -> List[Path]:
    """Collect all files from path (recursively if directory)."""
    files = []
    
    if input_path.is_file():
        files.append(input_path)
    elif input_path.is_dir():
        for item in input_path.rglob('*'):
            if item.is_file():
                # Skip hidden files and system files
                if not item.name.startswith('.'):
                    files.append(item)
    else:
        raise ValueError(f"Invalid input: {input_path}")
    
    return sorted(files)


def hash_password(password: str) -> str:
    """Hash password for clowder manifest."""
    return hashlib.sha256(password.encode()).hexdigest()[:16]


def encode_clowder(
    input_path: Path,
    output_dir: Path,
    password: str,
    config: Optional[EncodingConfig] = None,
    max_files_per_yarn: int = 10,
    resume: bool = True,
    verbose: bool = False
) -> dict:
    """
    Encode folder into clowder of yarn balls.
    
    Args:
        input_path: Input file or directory
        output_dir: Output directory for yarn balls
        password: Encryption password
        config: Encoding configuration
        max_files_per_yarn: Max files to pack per GIF
        resume: Resume if interrupted
        verbose: Verbose output
        
    Returns:
        Statistics dictionary
    """
    if config is None:
        config = EncodingConfig()
    
    print("🐱🐱🐱 CLOWDER BATCH MODE")
    print("=" * 60)
    print("Summoning clowder of yarn balls...")
    print()
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / 'clowder_manifest.json'
    
    # Check for existing manifest (resume)
    clowder_manifest = None
    if resume and manifest_path.exists():
        print("📋 Found existing clowder manifest - resuming!")
        with open(manifest_path) as f:
            data = json.load(f)
        
        # Verify password
        pw_hash = hash_password(password)
        if data['password_hash'] != pw_hash:
            print("❌ Password doesn't match existing clowder!", file=sys.stderr)
            sys.exit(1)
        
        clowder_manifest = ClowderManifest.from_dict(data)
        print(f"  Clowder ID: {clowder_manifest.clowder_id}")
        print(f"  Completed: {len(clowder_manifest.yarn_balls)} yarn balls")
    else:
        # Create new clowder
        clowder_id = hashlib.sha256(
            f"{input_path}{datetime.now()}".encode()
        ).hexdigest()[:16]
        
        clowder_manifest = ClowderManifest(
            clowder_id=clowder_id,
            password_hash=hash_password(password)
        )
        
        if verbose:
            print(f"  Created clowder ID: {clowder_id}")
    
    # Collect files
    print(f"\n📂 Collecting files from: {input_path}")
    files = collect_files(input_path)
    
    if not files:
        print("❌ No files found!", file=sys.stderr)
        sys.exit(1)
    
    print(f"  Found {len(files)} files")
    
    # Calculate total size
    total_bytes = sum(f.stat().st_size for f in files)
    print(f"  Total size: {total_bytes:,} bytes")
    
    clowder_manifest.total_files = len(files)
    clowder_manifest.total_bytes = total_bytes
    
    # Check which files are already encoded
    completed_files = set()
    if resume:
        for yarn_ball in clowder_manifest.yarn_balls:
            completed_files.update(yarn_ball['files'])
    
    remaining_files = [f for f in files if str(f) not in completed_files]
    
    if resume and completed_files:
        print(f"\n🔄 Resume mode:")
        print(f"  Already encoded: {len(completed_files)} files")
        print(f"  Remaining: {len(remaining_files)} files")
    
    if not remaining_files:
        print("\n✅ Clowder already complete!")
        return {
            'clowder_id': clowder_manifest.clowder_id,
            'total_files': len(files),
            'total_yarn_balls': len(clowder_manifest.yarn_balls)
        }
    
    # Encode files into yarn balls
    print(f"\n🧶 Creating yarn balls...")
    
    yarn_ball_num = len(clowder_manifest.yarn_balls) + 1
    
    for i in range(0, len(remaining_files), max_files_per_yarn):
        batch = remaining_files[i:i + max_files_per_yarn]
        
        print(f"\n🐱 Yarn Ball #{yarn_ball_num}:")
        print(f"  Files: {len(batch)}")
        
        # Create temporary combined file
        combined_data = []
        file_index = []
        
        for file in batch:
            file_data = file.read_bytes()
            combined_data.append(file_data)
            file_index.append({
                'path': str(file),
                'size': len(file_data),
                'offset': sum(len(d) for d in combined_data[:-1])
            })
        
        # Combine all files
        combined_bytes = b''.join(combined_data)
        
        # Save to temporary file
        temp_file = output_dir / f'temp_batch_{yarn_ball_num}.dat'
        temp_file.write_bytes(combined_bytes)
        
        # Encode combined file
        yarn_ball_path = output_dir / f'yarn_{yarn_ball_num:03d}.gif'
        
        print(f"  Encoding to: {yarn_ball_path.name}")
        print(f"  Total: {len(combined_bytes):,} bytes")
        
        try:
            stats = encode_file(
                temp_file,
                yarn_ball_path,
                password,
                config=config,
                verbose=False
            )
            
            # Remove temporary file
            temp_file.unlink()
            
            # Add to manifest
            yarn_ball_info = {
                'yarn_ball_number': yarn_ball_num,
                'filename': yarn_ball_path.name,
                'files': [str(f) for f in batch],
                'file_index': file_index,
                'total_bytes': len(combined_bytes),
                'qr_frames': stats['qr_frames'],
                'created_at': datetime.now().isoformat()
            }
            
            clowder_manifest.add_yarn_ball(yarn_ball_info)
            
            # Save manifest after each yarn ball (for resume)
            with open(manifest_path, 'w') as f:
                json.dump(clowder_manifest.to_dict(), f, indent=2)
            
            print(f"  ✅ Created: {stats['qr_frames']} frames, {stats['output_size']:,} bytes")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            temp_file.unlink(missing_ok=True)
            raise
        
        yarn_ball_num += 1
    
    # Mark as completed
    clowder_manifest.completed = True
    
    with open(manifest_path, 'w') as f:
        json.dump(clowder_manifest.to_dict(), f, indent=2)
    
    print("\n✅ CLOWDER COMPLETE!")
    print(f"  Total files: {clowder_manifest.total_files}")
    print(f"  Total bytes: {clowder_manifest.total_bytes:,}")
    print(f"  Yarn balls: {len(clowder_manifest.yarn_balls)}")
    print(f"\n💾 Output directory: {output_dir}")
    print(f"  Manifest: {manifest_path.name}")
    
    for yarn_ball in clowder_manifest.yarn_balls:
        print(f"  {yarn_ball['filename']}: {len(yarn_ball['files'])} files, {yarn_ball['qr_frames']} frames")
    
    print("\n🐱🐱🐱 All cats accounted for! The clowder is ready!")
    
    return {
        'clowder_id': clowder_manifest.clowder_id,
        'total_files': clowder_manifest.total_files,
        'total_bytes': clowder_manifest.total_bytes,
        'total_yarn_balls': len(clowder_manifest.yarn_balls)
    }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="🐱🐱🐱 Clowder Batch Mode - Multi-File Encoder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encode entire folder
  python3 clowder_encode.py --input ~/secrets/ --output ~/yarn_balls/
  
  # Resume interrupted encoding
  python3 clowder_encode.py --input ~/secrets/ --output ~/yarn_balls/
  (Automatically resumes if interrupted!)
  
  # Control files per GIF
  python3 clowder_encode.py --input ~/docs/ --output ~/yarn/ --max-per-yarn 5
  
A clowder is a group of cats! 🐈🐈🐈
        """
    )
    
    parser.add_argument('--input', type=Path, required=True,
                       help='Input file or directory')
    parser.add_argument('--output', type=Path, required=True,
                       help='Output directory for yarn balls')
    parser.add_argument('--password', type=str,
                       help='Encryption password (prompted if not provided)')
    parser.add_argument('--max-per-yarn', type=int, default=10,
                       help='Maximum files per yarn ball (default: 10)')
    parser.add_argument('--no-resume', action='store_true',
                       help='Start fresh (ignore existing manifest)')
    parser.add_argument('--block-size', type=int, default=512,
                       help='Fountain code block size (default: 512)')
    parser.add_argument('--fps', type=int, default=10,
                       help='GIF frames per second (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.input.exists():
        print(f"❌ Input not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass("Enter clowder password: ")
        password_confirm = getpass("Confirm password: ")
        
        if password != password_confirm:
            print("❌ Passwords don't match!", file=sys.stderr)
            sys.exit(1)
    
    if not password:
        print("❌ Password cannot be empty!", file=sys.stderr)
        sys.exit(1)
    
    print()
    
    # Create config
    config = EncodingConfig(
        block_size=args.block_size,
        fps=args.fps
    )
    
    # Encode clowder!
    try:
        stats = encode_clowder(
            args.input,
            args.output,
            password,
            config=config,
            max_files_per_yarn=args.max_per_yarn,
            resume=not args.no_resume,
            verbose=args.verbose
        )
        
        print("\n🎉 SUCCESS! Clowder ready to hunt!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted! Run again to resume from where you left off.")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
