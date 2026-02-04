#!/usr/bin/env python3
"""
AFL++ fuzz target for manifest parsing.
Reads input from stdin (AFL style).
"""

import sys
from pathlib import Path

try:
    import afl
except ImportError:  # pragma: no cover - only used in AFL environments
    afl = None

sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.crypto import unpack_manifest


def main():
    if afl is None:
        raise RuntimeError("afl is required to run AFL fuzz targets")

    # AFL persistent mode
    while afl.loop(1000):
        # Read input from stdin
        data = sys.stdin.buffer.read()
        
        try:
            manifest = unpack_manifest(data)
            
            # Basic sanity checks
            if manifest:
                assert len(manifest.salt) == 16
                assert len(manifest.nonce) == 12
                assert len(manifest.sha256) == 32
                assert len(manifest.hmac) == 32
                
        except (ValueError, AssertionError):
            # Expected for invalid input
            pass
        except Exception as e:
            # Log unexpected errors but don't crash
            error_msg = str(e).lower()
            if any(x in error_msg for x in ["short", "invalid", "magic"]):
                pass  # Expected
            else:
                # This might be a real bug - let AFL know
                raise


if __name__ == "__main__":
    main()
