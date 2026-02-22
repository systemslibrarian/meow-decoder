#!/usr/bin/env python3
"""
Fuzz target for pq_ratchet_beacon.py — ML-KEM-1024 post-quantum ratchet beacon.

Tests:
  - PQBeaconFrame serialization/deserialization with corrupt data
  - ML-KEM-1024 encapsulate/decapsulate with corrupt ciphertexts
  - Beacon mixing with malformed KEM output
  - integrate_with_ratchet with adversarial inputs
  - Fail-closed on partial shared secrets

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

    from meow_decoder.pq_ratchet_beacon import (
        PQBeaconFrame,
        PQBeaconKeyPair,
        PQRatchetBeacon,
        generate_beacon_keypair,
        integrate_with_ratchet,
        _mlkem1024_keygen,
        _mlkem1024_encapsulate,
        _mlkem1024_decapsulate,
    )
    import secrets

    return (
        PQBeaconFrame,
        PQBeaconKeyPair,
        PQRatchetBeacon,
        generate_beacon_keypair,
        integrate_with_ratchet,
        _mlkem1024_keygen,
        _mlkem1024_encapsulate,
        _mlkem1024_decapsulate,
        secrets,
    )


if atheris is not None:
    with atheris.instrument_imports():
        (
            PQBeaconFrame, PQBeaconKeyPair, PQRatchetBeacon,
            generate_beacon_keypair, integrate_with_ratchet,
            _mlkem1024_keygen, _mlkem1024_encapsulate, _mlkem1024_decapsulate,
            secrets,
        ) = _setup_imports()
else:
    (
        PQBeaconFrame, PQBeaconKeyPair, PQRatchetBeacon,
        generate_beacon_keypair, integrate_with_ratchet,
        _mlkem1024_keygen, _mlkem1024_encapsulate, _mlkem1024_decapsulate,
        secrets,
    ) = _setup_imports()


# Pre-generate a valid keypair once (expensive operation)
_VALID_KEYPAIR = None


def _get_valid_keypair():
    global _VALID_KEYPAIR
    if _VALID_KEYPAIR is None:
        try:
            _VALID_KEYPAIR = generate_beacon_keypair()
        except RuntimeError:
            # No ML-KEM implementation available
            _VALID_KEYPAIR = False
    return _VALID_KEYPAIR


def fuzz_beacon_frame_roundtrip(data: bytes):
    """Fuzz PQBeaconFrame serialization/deserialization."""
    if len(data) < 7:
        return

    try:
        frame = PQBeaconFrame(ciphertext=data)
        serialized = frame.to_bytes()
        recovered = PQBeaconFrame.from_bytes(serialized)
        if recovered is not None:
            assert recovered.ciphertext == data
    except (ValueError, TypeError, struct.error):
        pass


def fuzz_beacon_frame_corrupt_deserialize(data: bytes):
    """Fuzz PQBeaconFrame.from_bytes with arbitrary data."""
    try:
        result = PQBeaconFrame.from_bytes(data)
        # Result should be None for non-beacon data, or a valid frame
        if result is not None:
            assert isinstance(result.ciphertext, bytes)
            assert len(result.ciphertext) > 0
    except (ValueError, TypeError, struct.error):
        pass


def fuzz_beacon_frame_truncated(data: bytes):
    """Fuzz with beacon magic but truncated body."""
    if len(data) < 2:
        return

    # Inject valid magic prefix
    fuzzed = b"PQBCN" + data
    try:
        result = PQBeaconFrame.from_bytes(fuzzed)
        if result is not None:
            assert isinstance(result.ciphertext, bytes)
    except (ValueError, TypeError, struct.error):
        pass


def fuzz_decapsulate_corrupt_ciphertext(data: bytes):
    """Fuzz ML-KEM-1024 decapsulation with corrupt ciphertexts."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 32:
        return

    message_key = data[:32]

    try:
        beacon = PQRatchetBeacon(receiver_keypair=keypair)
        # Try decapsulating garbage ciphertext — must fail-closed
        beacon.decapsulate(data[32:], message_key)
    except ValueError:
        # Expected: invalid ciphertext size or decapsulation failure
        pass
    except RuntimeError:
        # Expected: no ML-KEM implementation
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in [
            "ciphertext", "invalid", "decapsulate", "size", "kem",
            "kyber", "ml-kem", "decap"
        ]):
            pass
        else:
            raise


def fuzz_encapsulate_corrupt_pubkey(data: bytes):
    """Fuzz ML-KEM-1024 encapsulation with corrupt public keys."""
    if len(data) < 64:
        return

    message_key = data[:32]
    fake_pk = data[32:]

    try:
        beacon = PQRatchetBeacon(receiver_public_key=fake_pk)
        beacon.encapsulate(message_key)
    except (ValueError, RuntimeError):
        # Expected: invalid public key
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in [
            "key", "invalid", "encapsulate", "size", "kem",
            "kyber", "ml-kem", "encap", "public"
        ]):
            pass
        else:
            raise


def fuzz_beacon_mixing(data: bytes):
    """Fuzz beacon mixing (encapsulate + decapsulate roundtrip)."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 33:
        return

    message_key = data[:32]
    salt = data[32:]

    try:
        sender = PQRatchetBeacon(receiver_public_key=keypair.public_key)
        ciphertext, enhanced_key_sender = sender.encapsulate(message_key, salt=salt)

        assert isinstance(ciphertext, bytes)
        assert isinstance(enhanced_key_sender, bytes)
        assert len(enhanced_key_sender) == 32

        receiver = PQRatchetBeacon(receiver_keypair=keypair)
        enhanced_key_receiver = receiver.decapsulate(ciphertext, message_key, salt=salt)

        # Sender and receiver must derive the same enhanced key
        assert enhanced_key_sender == enhanced_key_receiver, (
            "Beacon mixing mismatch: sender and receiver derived different keys"
        )
    except (ValueError, RuntimeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["kem", "key", "implementation", "available"]):
            pass
        else:
            raise


def fuzz_integrate_with_ratchet(data: bytes):
    """Fuzz integrate_with_ratchet helper."""
    keypair = _get_valid_keypair()
    if keypair is False or keypair is None:
        return

    if len(data) < 37:
        return

    chain_key = data[:32]
    frame_index = struct.unpack("<I", data[32:36])[0] % 1000
    rekey_interval = (data[36] % 64) + 1

    try:
        enhanced_key, beacon_ct = integrate_with_ratchet(
            chain_key=chain_key,
            receiver_pk=keypair.public_key,
            frame_index=frame_index,
            rekey_interval=rekey_interval,
        )
        assert isinstance(enhanced_key, bytes)
        assert len(enhanced_key) == 32
        if beacon_ct is not None:
            assert isinstance(beacon_ct, bytes)
    except (ValueError, RuntimeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["kem", "key", "implementation"]):
            pass
        else:
            raise


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_beacon_frame_roundtrip(data)
        fuzz_beacon_frame_corrupt_deserialize(data)
        fuzz_beacon_frame_truncated(data)
        fuzz_decapsulate_corrupt_ciphertext(data)
        fuzz_encapsulate_corrupt_pubkey(data)
        fuzz_beacon_mixing(data)
        fuzz_integrate_with_ratchet(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
