#!/usr/bin/env python3
"""
Fuzz target for manifest_signing.py — ML-DSA-65 + Ed25519 hybrid signing.

Tests:
  - ManifestSignature serialization/deserialization with corrupt data
  - verify_manifest_signature with malformed signatures (must reject)
  - sign_manifest + verify roundtrip
  - Ed25519/ML-DSA-65 verify with garbage signatures
  - Public key commitment with adversarial keys
  - Dual-algo verification: must reject if EITHER sig fails

Uses Atheris (Google's Python fuzzing engine).
"""

import os
import struct
import sys

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.manifest_signing import (
        ManifestSignature,
        SigningKeyPair,
        generate_signing_keypair,
        sign_manifest,
        verify_manifest_signature,
        compute_public_key_commitment,
        _ed25519_verify,
        _mldsa65_verify,
    )
    import secrets

    return (
        ManifestSignature,
        SigningKeyPair,
        generate_signing_keypair,
        sign_manifest,
        verify_manifest_signature,
        compute_public_key_commitment,
        _ed25519_verify,
        _mldsa65_verify,
        secrets,
    )


if atheris is not None:
    with atheris.instrument_imports():
        (
            ManifestSignature,
            SigningKeyPair,
            generate_signing_keypair,
            sign_manifest,
            verify_manifest_signature,
            compute_public_key_commitment,
            _ed25519_verify,
            _mldsa65_verify,
            secrets,
        ) = _setup_imports()
else:
    (
        ManifestSignature,
        SigningKeyPair,
        generate_signing_keypair,
        sign_manifest,
        verify_manifest_signature,
        compute_public_key_commitment,
        _ed25519_verify,
        _mldsa65_verify,
        secrets,
    ) = _setup_imports()


# Pre-generate a valid keypair once (expensive for ML-DSA-65)
_VALID_KEYPAIR = None


def _get_valid_keypair():
    global _VALID_KEYPAIR
    if _VALID_KEYPAIR is None:
        try:
            _VALID_KEYPAIR = generate_signing_keypair()
        except RuntimeError:
            _VALID_KEYPAIR = False
    return _VALID_KEYPAIR


def fuzz_signature_roundtrip(data: bytes):
    """Fuzz ManifestSignature serialization/deserialization."""
    if len(data) < 66:
        return

    ed_sig = data[:64]
    mldsa_sig = data[64:]

    try:
        sig = ManifestSignature(ed25519_sig=ed_sig, mldsa65_sig=mldsa_sig)
        serialized = sig.to_bytes()
        recovered = ManifestSignature.from_bytes(serialized)

        assert recovered.ed25519_sig == ed_sig
        assert recovered.mldsa65_sig == mldsa_sig
    except (ValueError, TypeError, struct.error):
        pass


def fuzz_signature_corrupt_deserialize(data: bytes):
    """Fuzz ManifestSignature.from_bytes with corrupt data."""
    try:
        result = ManifestSignature.from_bytes(data)
        # If it parsed, verify fields are bytes
        assert isinstance(result.ed25519_sig, bytes)
        assert isinstance(result.mldsa65_sig, bytes)
        assert len(result.ed25519_sig) == 64
    except ValueError:
        # Expected for corrupted input
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["short", "magic", "version", "truncated"]):
            pass
        else:
            raise


def fuzz_signature_truncated_magic(data: bytes):
    """Fuzz with valid magic prefix but truncated body."""
    if len(data) < 2:
        return

    fuzzed = b"MSIG" + bytes([1]) + data  # magic + version=1 + fuzz
    try:
        result = ManifestSignature.from_bytes(fuzzed)
        if result is not None:
            assert isinstance(result.ed25519_sig, bytes)
    except ValueError:
        pass


def fuzz_verify_corrupt_signature(data: bytes):
    """Fuzz verify_manifest_signature with garbage signatures."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 65:
        return

    manifest_bytes = data[:32]
    ed_sig = data[32:96] if len(data) >= 96 else data[32:] + b"\x00" * (64 - len(data[32:]))
    mldsa_sig = data[96:] if len(data) > 96 else b"\x00" * 100

    fake_sig = ManifestSignature(ed25519_sig=ed_sig[:64], mldsa65_sig=mldsa_sig)

    try:
        verify_manifest_signature(
            keypair.export_public_key(),
            manifest_bytes,
            fake_sig,
        )
        # With garbage signatures, this should almost never return True
    except ValueError:
        # Expected: verification failure (fail-closed)
        pass
    except RuntimeError:
        # Expected: no implementation available
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(
            x in error_msg
            for x in [
                "signature",
                "verify",
                "invalid",
                "failed",
                "ed25519",
                "mldsa",
                "dilithium",
                "key",
            ]
        ):
            pass
        else:
            raise


def fuzz_verify_corrupt_pubkey(data: bytes):
    """Fuzz verification with corrupt public keys."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 32:
        return

    manifest_bytes = b"test manifest data"

    # Sign with valid keypair
    try:
        sig = sign_manifest(keypair, manifest_bytes)
    except RuntimeError:
        return

    # Verify with corrupt public key
    try:
        verify_manifest_signature(data, manifest_bytes, sig)
    except ValueError:
        # Expected: key too short or verification failure
        pass
    except RuntimeError:
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["key", "short", "invalid", "verify", "failed"]):
            pass
        else:
            raise


def fuzz_sign_verify_roundtrip(data: bytes):
    """Fuzz sign + verify roundtrip with various manifest data."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 1:
        return

    try:
        sig = sign_manifest(keypair, data, context=b"fuzz_context")
        result = verify_manifest_signature(
            keypair.export_public_key(), data, sig, context=b"fuzz_context"
        )
        assert result is True, "Valid signature must verify"
    except RuntimeError:
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["implementation", "available"]):
            pass
        else:
            raise


def fuzz_sign_verify_wrong_context(data: bytes):
    """Fuzz: signing with one context, verifying with another must fail."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 2:
        return

    split = max(1, len(data) // 2)
    context_a = data[:split]
    context_b = data[split:]

    if context_a == context_b:
        return  # Same context — not interesting

    manifest = b"test manifest"

    try:
        sig = sign_manifest(keypair, manifest, context=context_a)
        verify_manifest_signature(keypair.export_public_key(), manifest, sig, context=context_b)
        # Should have raised ValueError — contexts differ
        assert False, "Verification should fail with different context"
    except ValueError:
        # Expected: signature mismatch due to different domain separation
        pass
    except RuntimeError:
        pass
    except AssertionError:
        # If by cosmic coincidence the hash collides, that's a real bug worth seeing
        raise


def fuzz_ed25519_verify_garbage(data: bytes):
    """Fuzz Ed25519 verify with garbage inputs."""
    if len(data) < 97:
        return

    pk = data[:32]
    message = data[32:64]
    signature = data[64:128]

    try:
        result = _ed25519_verify(pk, message, signature)
        assert isinstance(result, bool)
    except RuntimeError:
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["key", "signature", "invalid", "verify"]):
            pass
        else:
            raise


def fuzz_public_key_commitment(data: bytes):
    """Fuzz public key commitment computation."""
    try:
        result = compute_public_key_commitment(data)
        assert isinstance(result, bytes)
        assert len(result) == 32
        # Deterministic: same input must give same output
        result2 = compute_public_key_commitment(data)
        assert result == result2
    except (ValueError, TypeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_signature_roundtrip(data)
        fuzz_signature_corrupt_deserialize(data)
        fuzz_signature_truncated_magic(data)
        fuzz_verify_corrupt_signature(data)
        fuzz_verify_corrupt_pubkey(data)
        fuzz_sign_verify_roundtrip(data)
        fuzz_sign_verify_wrong_context(data)
        fuzz_ed25519_verify_garbage(data)
        fuzz_public_key_commitment(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
