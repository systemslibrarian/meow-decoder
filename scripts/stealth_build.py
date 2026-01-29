#!/usr/bin/env python3
"""
🥷 Stealth Build Mode for Meow Decoder

Creates a deniable distribution of Meow Decoder with:
- Generic executable names (no "meow" or "decoder" references)
- Stripped version strings and branding
- Randomized internal identifiers
- Minimal metadata in binaries

USAGE:
    python scripts/stealth_build.py [--output-dir DIR] [--name NAME]

SECURITY NOTE:
    This provides cosmetic deniability only. A forensic analysis of the
    binary will still reveal its purpose through:
    - Import statements (cryptography, qrcode, etc.)
    - Function signatures and code patterns
    - Runtime behavior analysis
    
    For true deniability, use Schrödinger mode at the protocol level.
"""

import os
import re
import sys
import shutil
import hashlib
import secrets
import argparse
import subprocess
from pathlib import Path
from datetime import datetime


# Generic names that don't hint at purpose
STEALTH_NAMES = [
    "file_util",
    "data_sync", 
    "archive_tool",
    "backup_util",
    "doc_convert",
    "media_util",
    "sync_tool",
    "pack_util",
    "img_convert",
    "batch_proc",
]

# Strings to replace for deniability
REPLACEMENTS = {
    # Branding
    "meow": "util",
    "Meow": "Util",
    "MEOW": "UTIL",
    "decoder": "tool",
    "Decoder": "Tool",
    "DECODER": "TOOL",
    "cat": "app",
    "Cat": "App",
    "CAT": "APP",
    "kitten": "data",
    "Kitten": "Data",
    "yarn": "file",
    "Yarn": "File",
    "paw": "item",
    "Paw": "Item",
    "fountain": "stream",
    "Fountain": "Stream",
    "droplet": "chunk",
    "Droplet": "Chunk",
    
    # Fun/identifying phrases
    "🐱": "",
    "😺": "",
    "🐾": "",
    "🧶": "",
    "😸": "",
    "🐈": "",
    "🥷": "",
    "⚛️": "",
    "🔐": "",
}

# Files to modify (relative to project root)
FILES_TO_STEALTH = [
    "meow_decoder/__init__.py",
    "meow_decoder/config.py",
    "meow_decoder/cat_utils.py",
    "meow_decoder/encode.py",
    "meow_decoder/decode_gif.py",
    "pyproject.toml",
    "setup.py",
]

# Files to skip (crypto-critical, shouldn't be modified)
SKIP_FILES = [
    "crypto.py",
    "crypto_enhanced.py",
    "crypto_backend.py",
    "constant_time.py",
    "x25519_forward_secrecy.py",
    "pq_hybrid.py",
    "frame_mac.py",
]


def generate_stealth_name() -> str:
    """Generate a random generic name."""
    base = secrets.choice(STEALTH_NAMES)
    suffix = secrets.token_hex(2)
    return f"{base}_{suffix}"


def replace_strings(content: str, replacements: dict) -> str:
    """Replace identifying strings with generic alternatives."""
    result = content
    for old, new in replacements.items():
        # Use word boundaries to avoid partial replacements
        if old.isalpha():
            result = re.sub(rf'\b{old}\b', new, result)
        else:
            result = result.replace(old, new)
    return result


def strip_comments_and_docstrings(content: str) -> str:
    """Remove identifying comments and docstrings."""
    # Remove banner comments (# === ... ===)
    content = re.sub(r'#\s*=+.*?=+\s*\n', '\n', content)
    
    # Remove ASCII art
    content = re.sub(r'""".*?"""', '""""""', content, flags=re.DOTALL)
    
    # Remove version info comments
    content = re.sub(r'#.*version.*\n', '\n', content, flags=re.IGNORECASE)
    content = re.sub(r'#.*author.*\n', '\n', content, flags=re.IGNORECASE)
    
    return content


def create_stealth_build(
    source_dir: Path,
    output_dir: Path,
    stealth_name: str,
    strip_comments: bool = False,
    verbose: bool = True
) -> dict:
    """
    Create a stealth build of meow-decoder.
    
    Args:
        source_dir: Path to meow-decoder source
        output_dir: Output directory for stealth build
        stealth_name: Name for the stealth package
        strip_comments: Remove comments/docstrings (breaks debugging)
        verbose: Print progress
        
    Returns:
        Build statistics
    """
    stats = {
        "files_processed": 0,
        "files_skipped": 0,
        "replacements": 0,
        "output_name": stealth_name,
    }
    
    # Create output directory
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create stealth package directory
    pkg_dir = output_dir / stealth_name
    pkg_dir.mkdir(exist_ok=True)
    
    if verbose:
        print(f"🥷 Creating stealth build: {stealth_name}")
        print(f"   Output: {output_dir}")
    
    # Process source files
    source_dir = Path(source_dir)
    meow_src = source_dir / "meow_decoder"
    
    for py_file in meow_src.glob("*.py"):
        filename = py_file.name
        
        # Skip crypto-critical files
        if filename in SKIP_FILES:
            shutil.copy(py_file, pkg_dir / filename)
            stats["files_skipped"] += 1
            continue
        
        # Read and transform
        content = py_file.read_text(encoding="utf-8")
        original_len = len(content)
        
        # Apply replacements
        content = replace_strings(content, REPLACEMENTS)
        
        # Optionally strip comments
        if strip_comments:
            content = strip_comments_and_docstrings(content)
        
        # Track changes
        if len(content) != original_len:
            stats["replacements"] += 1
        
        # Write transformed file
        (pkg_dir / filename).write_text(content, encoding="utf-8")
        stats["files_processed"] += 1
        
        if verbose:
            print(f"   ✓ {filename}")
    
    # Create minimal pyproject.toml
    pyproject_content = f'''[project]
name = "{stealth_name}"
version = "1.0.0"
description = "File processing utility"
requires-python = ">=3.10"

dependencies = [
    "cryptography>=41.0.0",
    "qrcode[pil]>=7.4",
    "Pillow>=10.0.0",
    "pyzbar>=0.1.9",
    "argon2-cffi>=23.1.0",
]

[project.scripts]
{stealth_name} = "{stealth_name}:main"
encode = "{stealth_name}.encode:main"
decode = "{stealth_name}.decode_gif:main"
'''
    
    (output_dir / "pyproject.toml").write_text(pyproject_content)
    
    # Create minimal README
    readme_content = f"""# {stealth_name}

File processing utility.

## Installation

```bash
pip install .
```

## Usage

```bash
{stealth_name} --help
```
"""
    (output_dir / "README.md").write_text(readme_content)
    
    # Create __init__.py
    init_content = '''"""File processing utility."""
__version__ = "1.0.0"
'''
    (pkg_dir / "__init__.py").write_text(init_content)
    
    if verbose:
        print(f"\n✅ Stealth build complete!")
        print(f"   Package: {stealth_name}")
        print(f"   Files: {stats['files_processed']} processed, {stats['files_skipped']} skipped")
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Create a deniable build of meow-decoder",
        epilog="""
SECURITY WARNING:
    This provides cosmetic deniability only. Binary analysis, import 
    inspection, and behavioral analysis can still identify the tool.
    
    For protocol-level deniability, use Schrödinger mode.
        """
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("stealth_build"),
        help="Output directory (default: stealth_build)"
    )
    
    parser.add_argument(
        "--name", "-n",
        type=str,
        default=None,
        help="Package name (default: randomly generated)"
    )
    
    parser.add_argument(
        "--strip-comments",
        action="store_true",
        help="Remove comments and docstrings (breaks debugging)"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output"
    )
    
    args = parser.parse_args()
    
    # Determine source directory
    script_dir = Path(__file__).parent
    source_dir = script_dir.parent
    
    # Generate or use provided name
    stealth_name = args.name or generate_stealth_name()
    
    # Validate name
    if not re.match(r'^[a-z][a-z0-9_]*$', stealth_name):
        print(f"Error: Invalid package name '{stealth_name}'")
        print("       Must start with letter, contain only lowercase letters, numbers, underscores")
        return 1
    
    # Create build
    try:
        stats = create_stealth_build(
            source_dir,
            args.output_dir,
            stealth_name,
            strip_comments=args.strip_comments,
            verbose=not args.quiet
        )
        
        if not args.quiet:
            print(f"\n📦 To install the stealth build:")
            print(f"   cd {args.output_dir}")
            print(f"   pip install .")
            print(f"\n🏃 To run:")
            print(f"   encode -i file.txt -o output.gif -p password")
            print(f"   decode -i output.gif -o recovered.txt -p password")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
