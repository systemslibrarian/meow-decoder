#!/usr/bin/env python3
"""
Fuzz target for cryptographic operations.
Uses Atheris (Google's Python fuzzing engine).

IMPORTANT: This fuzzer tests error handling, not crypto strength.
We're looking for crashes, not cryptanalysis.
"""

import sys
import atheris

# Instrument modules before importing
with atheris.instrument_imports():
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from meow_decoder.crypto import (
        derive_key, decrypt_to_raw, unpack_manifest,
        verify_manifest_hmac, Manifest
    )
    import secrets


def fuzz_derive_key(data: bytes):
    """Fuzz key derivation with random passwords and salts."""
    if len(data) < 17:
        return
    
    # Split fuzz data into password and salt
    salt = data[:16]
    password = data[16:].decode('utf-8', errors='replace')
    
    if not password:
        return
    
    try:
        key = derive_key(password, salt)
        
        # Verify key properties
        assert isinstance(key, bytes)
        assert len(key) == 32
        
    except ValueError as e:
        # Expected for invalid input
        if "empty" in str(e).lower() or "salt" in str(e).lower():
            pass
        else:
            raise
    except Exception as e:
        # Memory errors during Argon2 are possible with extreme params
        if "memory" in str(e).lower():
            pass
        else:
            raise


def fuzz_decrypt(data: bytes):
    """Fuzz decryption with random ciphertext."""
    if len(data) < 50:
        return
    
    # Extract components from fuzz data
    salt = data[:16]
    nonce = data[16:28]
    cipher = data[28:]
    password = "fuzz_password_123"
    
    try:
        # This should fail gracefully (wrong key, corrupted data, etc.)
        result = decrypt_to_raw(
            cipher=cipher,
            password=password,
            salt=salt,
            nonce=nonce,
            orig_len=len(cipher),
            comp_len=len(cipher),
            sha256=secrets.token_bytes(32)
        )
        
        # If decryption succeeded (unlikely), verify result
        if result:
            assert isinstance(result, bytes)
            
    except RuntimeError:
        # Expected - decryption should fail with garbage
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in [
            "decrypt", "tag", "authentication", "decompress",
            "invalid", "corrupt", "wrong", "failed"
        ]):
            pass  # Expected crypto/decompression errors
        else:
            raise


def fuzz_hmac_verify(data: bytes):
    """Fuzz HMAC verification."""
    if len(data) < 115:  # Minimum manifest size
        return
    
    try:
        manifest = unpack_manifest(data)
        
        # Try to verify with random password
        password = "test_password"
        result = verify_manifest_hmac(password, manifest)
        
        # Result should be boolean
        assert isinstance(result, bool)
        
    except ValueError:
        # Expected for invalid manifests
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["manifest", "magic", "version", "short"]):
            pass
        else:
            raise


def main():
    def combined_fuzz(data: bytes):
        # Run all fuzzers
        fuzz_derive_key(data)
        fuzz_decrypt(data)
        fuzz_hmac_verify(data)
    
    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
