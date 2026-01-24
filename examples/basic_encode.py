#!/usr/bin/env python3
"""
🐱 Basic Encode Example
Simple file encoding with Meow Decoder
"""

import sys
from pathlib import Path

# Import meow decoder (adjust path if needed)
sys.path.insert(0, str(Path(__file__).parent.parent))

from encode import main as encode_main

def basic_encode():
    """Basic encoding example."""
    print("🐱 Basic Encoding Example")
    print("=" * 50)
    print()
    
    # Set up arguments
    sys.argv = [
        "encode.py",
        "--input", "test.txt",
        "--output", "test.gif",
    ]
    
    # Run encoder
    try:
        encode_main()
        print("\n✅ Encoding complete!")
        print("📁 Output: test.gif")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    basic_encode()
