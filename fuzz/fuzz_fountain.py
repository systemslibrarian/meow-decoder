#!/usr/bin/env python3
"""
Fuzz target for fountain code parsing.
Uses Atheris (Google's Python fuzzing engine).
"""

import sys
import atheris

# Instrument modules before importing
with atheris.instrument_imports():
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from meow_decoder.fountain import unpack_droplet, FountainDecoder, Droplet


def fuzz_unpack_droplet(data: bytes):
    """Fuzz the droplet unpacking function."""
    # Try various block sizes
    block_sizes = [128, 256, 512, 1024]
    
    for block_size in block_sizes:
        try:
            droplet = unpack_droplet(data, block_size)
            
            # Verify droplet structure
            if droplet:
                assert isinstance(droplet.seed, int)
                assert isinstance(droplet.block_indices, list)
                assert isinstance(droplet.data, bytes)
                assert droplet.seed >= 0
                assert all(isinstance(i, int) and i >= 0 for i in droplet.block_indices)
                
        except (ValueError, struct.error):
            # Expected for malformed input
            pass
        except Exception as e:
            # Check if it's an expected error
            error_msg = str(e).lower()
            if any(x in error_msg for x in ["unpack", "index", "slice", "short"]):
                pass  # Expected parsing errors
            else:
                raise


def fuzz_fountain_decoder(data: bytes):
    """Fuzz the fountain decoder with random droplets."""
    if len(data) < 10:
        return
    
    # Extract parameters from fuzz data
    k_blocks = (data[0] % 100) + 1  # 1-100 blocks
    block_size = ((data[1] % 8) + 1) * 64  # 64-512 bytes
    
    try:
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Try to add fuzzed droplet
        droplet_data = data[2:]
        
        try:
            droplet = unpack_droplet(droplet_data, block_size)
            if droplet:
                decoder.add_droplet(droplet)
        except:
            pass  # Parsing errors are fine
        
        # Check decoder state is valid
        assert decoder.decoded_count >= 0
        assert decoder.decoded_count <= k_blocks
        
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["unpack", "index", "value"]):
            pass
        else:
            raise


# Need struct for error handling
import struct


def main():
    # Combine fuzz targets
    def combined_fuzz(data: bytes):
        fuzz_unpack_droplet(data)
        fuzz_fountain_decoder(data)
    
    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
