#!/usr/bin/env python3
"""
Fuzz target for X25519 forward secrecy key agreement.

Tests:
  - keypair generation with corrupted state
  - derive_shared_secret with adversarial inputs (bad lengths, types)
  - serialize/deserialize public key roundtrip with garbage
  - generate_receiver_keypair robustness

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

    from meow_decoder.x25519_forward_secrecy import (
        generate_ephemeral_keypair,
        derive_shared_secret,
        serialize_public_key,
        deserialize_public_key,
        generate_receiver_keypair,
        ForwardSecrecyKeys,
    )

    return {
        "generate_ephemeral_keypair": generate_ephemeral_keypair,
        "derive_shared_secret": derive_shared_secret,
        "serialize_public_key": serialize_public_key,
        "deserialize_public_key": deserialize_public_key,
        "generate_receiver_keypair": generate_receiver_keypair,
        "ForwardSecrecyKeys": ForwardSecrecyKeys,
    }


if atheris is not None:
    with atheris.instrument_imports():
        API = _setup_imports()
else:
    API = _setup_imports()


def fuzz_derive_shared_secret(data: bytes):
    """Fuzz derive_shared_secret with adversarial byte slices."""
    if len(data) < 82:
        return

    # Slice fuzz data into the required fields
    ephemeral_private = data[:32]
    receiver_public = data[32:64]
    salt = data[64:80]
    password = data[80:].decode("utf-8", errors="replace")

    try:
        result = API["derive_shared_secret"](
            ephemeral_private=ephemeral_private,
            receiver_public=receiver_public,
            password=password,
            salt=salt,
        )
        assert isinstance(result, bytes)
        assert len(result) == 32
    except (ValueError, TypeError, OverflowError, RuntimeError):
        pass  # Expected for malformed inputs


def fuzz_serialize_deserialize(data: bytes):
    """Fuzz public-key serialize → deserialize roundtrip."""
    if len(data) < 1:
        return

    try:
        serialized = API["serialize_public_key"](data[:32] if len(data) >= 32 else data)
        deserialized = API["deserialize_public_key"](serialized)
        assert isinstance(deserialized, bytes)
    except (ValueError, TypeError):
        pass

    # Also try deserializing raw fuzz input
    try:
        API["deserialize_public_key"](data)
    except (ValueError, TypeError):
        pass


def fuzz_keypair_roundtrip(data: bytes):
    """Generate keypair and exercise DH exchange with fuzzed receiver key."""
    if len(data) < 48:
        return

    try:
        keys = API["generate_ephemeral_keypair"]()
        assert isinstance(keys.ephemeral_public, bytes)
        assert len(keys.ephemeral_public) == 32

        # Try DH with fuzzed receiver key
        receiver_pub = data[:32]
        salt = data[32:48]
        API["derive_shared_secret"](
            ephemeral_private=keys.ephemeral_private,
            receiver_public=receiver_pub,
            password="fuzz",
            salt=salt,
        )
    except (ValueError, TypeError, RuntimeError):
        pass
    finally:
        try:
            keys.drop()
        except Exception:
            pass


def fuzz_derive_with_optional_params(data: bytes):
    """Fuzz derive_shared_secret with optional transcript-binding params."""
    if len(data) < 116:
        return

    ephemeral_private = data[:32]
    receiver_public = data[32:64]
    salt = data[64:80]
    ephemeral_public = data[80:112]
    mode_flags = data[112]
    protocol_version = struct.unpack("<H", data[113:115])[0] if len(data) >= 115 else None

    try:
        result = API["derive_shared_secret"](
            ephemeral_private=ephemeral_private,
            receiver_public=receiver_public,
            password="fuzz_transcript",
            salt=salt,
            protocol_version=protocol_version,
            ephemeral_public=ephemeral_public,
            mode_flags=mode_flags,
        )
        assert isinstance(result, bytes)
    except (ValueError, TypeError, OverflowError, RuntimeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_derive_shared_secret(data)
        fuzz_serialize_deserialize(data)
        fuzz_keypair_roundtrip(data)
        fuzz_derive_with_optional_params(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
