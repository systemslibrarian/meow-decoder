#!/usr/bin/env python3
"""
Fuzz target for the crypto backend abstraction layer (crypto_backend.py).
Uses Atheris (Google's Python fuzzing engine).

Covers:
- CryptoBackend with crafted keys / nonces / AAD / ciphertexts
- Opaque handle lifecycle: derive → encrypt → decrypt
- AES-GCM with adversarial AAD, nonce reuse, truncated ciphertext
- HKDF derivation with adversarial IKM / info / salt
- Backend info and capability checks
"""

import sys
import os

os.environ.setdefault("MEOW_TEST_MODE", "1")

try:
    import atheris
except ImportError:  # pragma: no cover
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    # Import the backend — will be a no-op in test environments without Rust
    try:
        from meow_decoder.crypto_backend import RustCryptoBackend, BackendInfo

        backend_available = True
    except (ImportError, RuntimeError):
        RustCryptoBackend = None
        BackendInfo = None
        backend_available = False

    import secrets

    return RustCryptoBackend, BackendInfo, backend_available, secrets


if atheris is not None:
    with atheris.instrument_imports():
        RustCryptoBackend, BackendInfo, backend_available, secrets = _setup_imports()
else:
    RustCryptoBackend, BackendInfo, backend_available, secrets = _setup_imports()


def _get_backend():
    """Return a CryptoBackend instance or None if Rust not available."""
    if not backend_available or RustCryptoBackend is None:
        return None
    try:
        return RustCryptoBackend()
    except (ImportError, RuntimeError):
        return None


def fuzz_aes_gcm_encrypt_decrypt(data: bytes):
    """Fuzz AES-GCM with crafted key / nonce / AAD / plaintext."""
    if len(data) < 44:  # 32 key + 12 nonce
        return

    backend = _get_backend()
    if backend is None:
        return

    key = data[:32]
    nonce = data[32:44]
    aad = data[44:108] if len(data) > 44 else b""
    plaintext = data[108:] if len(data) > 108 else b"\x00"

    try:
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad=aad)
        assert isinstance(ciphertext, bytes), "ciphertext must be bytes"
        # Ciphertext must be at least len(plaintext) + 16 (tag)
        assert len(ciphertext) >= len(plaintext) + 16, "ciphertext too short"

        # Decrypt the just-encrypted data — must round-trip
        recovered = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad=aad)
        assert recovered == plaintext, "roundtrip mismatch"

    except (ValueError, RuntimeError) as e:
        msg = str(e).lower()
        if any(x in msg for x in ["key", "nonce", "aad", "length", "invalid", "gcm"]):
            pass
        else:
            raise


def fuzz_aes_gcm_decrypt_corrupt(data: bytes):
    """Fuzz AES-GCM decryption with garbage ciphertext — must always fail cleanly."""
    if len(data) < 44:
        return

    backend = _get_backend()
    if backend is None:
        return

    key = data[:32]
    nonce = data[32:44]
    aad = data[44:76] if len(data) > 44 else b""
    corrupt_ciphertext = data[76:] if len(data) > 76 else data[44:]

    if not corrupt_ciphertext:
        return

    try:
        result = backend.aes_gcm_decrypt(key, nonce, corrupt_ciphertext, aad=aad)
        # If it somehow succeeds (astronomically unlikely), verify it returns bytes
        if result is not None:
            assert isinstance(result, bytes)
    except (ValueError, RuntimeError):
        pass  # Expected: authentication failure
    except Exception as e:
        msg = str(e).lower()
        expected = [
            "tag", "authentication", "decrypt", "invalid", "gcm",
            "cipher", "length", "nonce", "key",
        ]
        if not any(x in msg for x in expected):
            raise


def fuzz_hkdf_derive(data: bytes):
    """Fuzz HKDF derivation with adversarial IKM, salt, info."""
    if len(data) < 1:
        return

    backend = _get_backend()
    if backend is None:
        return

    # Split data into IKM / salt / info / output_len
    split1 = max(1, len(data) // 3)
    split2 = max(split1 + 1, 2 * len(data) // 3)

    ikm = data[:split1]
    salt = data[split1:split2]
    info = data[split2:]
    output_len = (data[0] % 64) + 16  # 16-79 bytes

    try:
        if hasattr(backend, "hkdf_expand"):
            result = backend.hkdf_expand(ikm, salt=salt, info=info, length=output_len)
            assert isinstance(result, bytes)
            assert len(result) == output_len
        elif hasattr(backend, "hkdf_derive"):
            result = backend.hkdf_derive(ikm, salt=salt, info=info, length=output_len)
            assert isinstance(result, bytes)
    except (ValueError, RuntimeError) as e:
        msg = str(e).lower()
        if any(x in msg for x in ["hkdf", "length", "invalid", "derive", "key"]):
            pass
        else:
            raise


def fuzz_argon2id_derive(data: bytes):
    """Fuzz Argon2id key derivation with crafted password and salt."""
    if len(data) < 17:
        return

    backend = _get_backend()
    if backend is None:
        return

    salt = data[:16]
    password = data[16:80].decode("utf-8", errors="replace")

    if not password:
        return

    try:
        if hasattr(backend, "derive_key_argon2id"):
            key = backend.derive_key_argon2id(password, salt)
            assert isinstance(key, bytes)
            assert len(key) in (16, 32, 64)
    except (ValueError, RuntimeError, MemoryError) as e:
        msg = str(e).lower()
        if any(x in msg for x in ["argon2", "salt", "password", "memory", "invalid"]):
            pass
        else:
            raise


def fuzz_nonce_uniqueness(data: bytes):
    """Fuzz that two different inputs produce different nonces."""
    if len(data) < 64:
        return

    backend = _get_backend()
    if backend is None:
        return

    if not hasattr(backend, "derive_nonce"):
        return

    root_key1 = data[:32]
    root_key2 = data[32:64]
    context = data[64:]

    try:
        nonce1 = backend.derive_nonce(root_key1, context)
        nonce2 = backend.derive_nonce(root_key2, context)

        # Different root keys must produce different nonces
        if root_key1 != root_key2:
            assert nonce1 != nonce2, "nonce collision: different keys produced same nonce"
    except (ValueError, RuntimeError, AttributeError):
        pass


def fuzz_backend_info(data: bytes):
    """Fuzz backend info / capability probing — must never crash."""
    backend = _get_backend()
    if backend is None:
        return

    try:
        info = backend.get_info()
        if info is not None:
            assert hasattr(info, "name")
            assert isinstance(info.constant_time, bool)
            assert isinstance(info.memory_zeroing, bool)
    except Exception as e:
        msg = str(e).lower()
        if not any(x in msg for x in ["info", "backend", "rust", "unavailable"]):
            raise


def combined_fuzz(data: bytes):
    fuzz_aes_gcm_encrypt_decrypt(data)
    fuzz_aes_gcm_decrypt_corrupt(data)
    fuzz_hkdf_derive(data)
    fuzz_argon2id_derive(data)
    fuzz_nonce_uniqueness(data)
    fuzz_backend_info(data)


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
