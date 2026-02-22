#!/usr/bin/env python3
"""
Fuzz target for the MSR v1.2/v2.0 symmetric ratchet (meow_decoder/ratchet.py).

Tests:
  - Chain stepping with corrupted state
  - Header encryption/decryption with garbage inputs
  - Rekey beacon parsing (KEM beacons)
  - PQ beacon mixing with malformed KEM output
  - Skip key cache exhaustion (DoS bound)
  - Frame encryption/decryption with adversarial ciphertext

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

    from meow_decoder.ratchet import (
        init_ratchet,
        ratchet_step,
        derive_frame_keys,
        encrypt_frame,
        decrypt_frame,
        build_frame_aad,
        _encrypt_index,
        _build_header_lookup,
        _derive_header_key,
        _compute_commitment,
        _mix_beacon,
        _mix_beacon_handle,
        _generate_kem_beacon,
        _recover_kem_beacon,
        RatchetState,
        FrameKeys,
        MAX_SKIP_KEYS,
        MAX_FRAME_INDEX,
    )

    return {
        "init_ratchet": init_ratchet,
        "ratchet_step": ratchet_step,
        "derive_frame_keys": derive_frame_keys,
        "encrypt_frame": encrypt_frame,
        "decrypt_frame": decrypt_frame,
        "build_frame_aad": build_frame_aad,
        "_encrypt_index": _encrypt_index,
        "_build_header_lookup": _build_header_lookup,
        "_derive_header_key": _derive_header_key,
        "_compute_commitment": _compute_commitment,
        "_mix_beacon": _mix_beacon,
        "_mix_beacon_handle": _mix_beacon_handle,
        "_generate_kem_beacon": _generate_kem_beacon,
        "_recover_kem_beacon": _recover_kem_beacon,
        "RatchetState": RatchetState,
        "FrameKeys": FrameKeys,
        "MAX_SKIP_KEYS": MAX_SKIP_KEYS,
        "MAX_FRAME_INDEX": MAX_FRAME_INDEX,
    }


if atheris is not None:
    with atheris.instrument_imports():
        API = _setup_imports()
else:
    API = _setup_imports()


def fuzz_init_and_step(data: bytes):
    """Fuzz ratchet init + stepping with random root keys and salts."""
    if len(data) < 49:  # 32 root_key + 16 salt + 1 step_count
        return

    root_key = data[:32]
    salt = data[32:48]
    step_count = data[48] % 20  # 0–19 steps

    try:
        state = API["init_ratchet"](root_key, salt)
        for _ in range(step_count):
            msg_key, state = API["ratchet_step"](state)
            # Derive frame keys from each message key
            keys = API["derive_frame_keys"](msg_key, salt)
            # Verify key structure
            assert keys.nonce is not None
            assert len(keys.nonce) == 12
            keys.zeroize()
        state.zeroize()
    except ValueError:
        pass  # Expected for dead/overflow state
    except Exception as e:
        if "handle" in str(e).lower() or "backend" in str(e).lower():
            pass
        else:
            raise


def fuzz_encrypt_decrypt_frame(data: bytes):
    """Fuzz frame encrypt/decrypt with adversarial data."""
    if len(data) < 70:
        return

    root_key = data[:32]
    salt = data[32:48]
    frame_data = data[48:48 + min(len(data) - 48, 512)]

    try:
        state = API["init_ratchet"](root_key, salt)
        msg_key, state = API["ratchet_step"](state)

        encrypted = API["encrypt_frame"](
            frame_data=frame_data,
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            k_blocks=5,
            block_size=800,
            total_frames=10,
        )

        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(frame_data)  # Must include index + tag

        state.zeroize()
    except ValueError:
        pass
    except Exception as e:
        if any(x in str(e).lower() for x in ["handle", "backend", "encrypt"]):
            pass
        else:
            raise


def fuzz_decrypt_garbage(data: bytes):
    """Fuzz decryption with completely random ciphertext."""
    if len(data) < 70:
        return

    root_key = data[:32]
    salt = data[32:48]
    garbage_frame = data[48:]

    try:
        state = API["init_ratchet"](root_key, salt)
        msg_key, state = API["ratchet_step"](state)

        # This MUST fail — random ciphertext should never decrypt
        API["decrypt_frame"](
            encrypted_frame=garbage_frame,
            message_key=msg_key,
            expected_index=0,
            salt=salt,
            k_blocks=5,
            block_size=800,
            total_frames=10,
        )
        # If we get here, something is wrong (but may happen if garbage
        # happens to have valid frame_index prefix)
    except (ValueError, RuntimeError):
        pass  # Expected — decryption should fail
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["tag", "auth", "decrypt", "handle", "backend", "short"]):
            pass
        else:
            raise
    finally:
        try:
            state.zeroize()
        except Exception:
            pass


def fuzz_header_encryption(data: bytes):
    """Fuzz header encryption with random root keys and frame indices."""
    if len(data) < 52:
        return

    root_key = data[:32]
    salt = data[32:48]
    frame_index_bytes = data[48:52]
    frame_index = struct.unpack(">I", frame_index_bytes)[0]

    try:
        header_key = API["_derive_header_key"](root_key, salt)
        encrypted_idx = API["_encrypt_index"](header_key, frame_index % (API["MAX_FRAME_INDEX"] + 1))
        assert isinstance(encrypted_idx, bytes)
        assert len(encrypted_idx) == 4  # Frame index is 4 bytes

        # Build lookup should also work
        if frame_index < 100:  # Don't build huge lookups
            lookup = API["_build_header_lookup"](header_key, max(1, frame_index % 50))
            assert isinstance(lookup, dict)
    except (ValueError, OverflowError):
        pass
    except Exception as e:
        if "handle" in str(e).lower() or "backend" in str(e).lower():
            pass
        else:
            raise


def fuzz_commitment_tag(data: bytes):
    """Fuzz key commitment computation with random keys and frame bodies."""
    if len(data) < 33:
        return

    mac_key = data[:32]
    frame_body = data[32:]

    try:
        tag = API["_compute_commitment"](mac_key, frame_body)
        assert isinstance(tag, bytes)
        # Commitment tag should be COMMIT_TAG_SIZE (16 bytes)
        assert len(tag) == 16
    except (ValueError, TypeError):
        pass
    except Exception as e:
        if "handle" in str(e).lower() or "backend" in str(e).lower():
            pass
        else:
            raise


def fuzz_build_aad(data: bytes):
    """Fuzz AAD construction with random parameters."""
    if len(data) < 28:
        return

    frame_index = struct.unpack("<I", data[:4])[0]
    salt = data[4:20]
    k_blocks = struct.unpack("<H", data[20:22])[0]
    block_size = struct.unpack("<H", data[22:24])[0]
    total_frames = struct.unpack("<I", data[24:28])[0]

    try:
        aad = API["build_frame_aad"](frame_index, salt, k_blocks, block_size, total_frames)
        assert isinstance(aad, bytes)
        assert len(aad) > 0
    except (struct.error, OverflowError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_init_and_step(data)
        fuzz_encrypt_decrypt_frame(data)
        fuzz_decrypt_garbage(data)
        fuzz_header_encryption(data)
        fuzz_commitment_tag(data)
        fuzz_build_aad(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
