#!/usr/bin/env python3
"""
Fuzz target for master_ratchet.py — cross-session forward secrecy chain.

Tests:
  - ChainState serialization round-trip with corrupted data
  - MasterRatchet.load() with corrupted state files
  - Emergency wipe path (ensures no crash/leak on adversarial state)
  - derive_file_key with adversarial file_id strings
  - Generation counter manipulation

Uses Atheris (Google's Python fuzzing engine).
"""

import os
import struct
import sys
import tempfile

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.master_ratchet import (
        ChainState,
        MasterRatchet,
        _hkdf_expand,
        derive_file_key,
    )
    import secrets

    return ChainState, MasterRatchet, _hkdf_expand, derive_file_key, secrets


if atheris is not None:
    with atheris.instrument_imports():
        ChainState, MasterRatchet, _hkdf_expand, derive_file_key, secrets = _setup_imports()
else:
    ChainState, MasterRatchet, _hkdf_expand, derive_file_key, secrets = _setup_imports()


def fuzz_chain_state_roundtrip(data: bytes):
    """Fuzz ChainState serialization/deserialization."""
    if len(data) < 48:
        return

    encryption_key = data[:32]
    chain_key = data[:32]  # Reuse first 32 bytes
    master_salt = data[16:48]

    try:
        state = ChainState(
            chain_key=chain_key,
            generation=0,
            last_ratchet_time=0.0,
            master_salt=master_salt,
        )
        serialized = state.to_bytes(encryption_key)
        recovered = ChainState.from_bytes(serialized, encryption_key)
        if recovered is not None:
            assert recovered.chain_key == chain_key
            assert recovered.generation == 0
    except (ValueError, TypeError, struct.error):
        pass
    except Exception as e:
        if "cryptography" in str(e).lower() or "aesgcm" in str(e).lower():
            pass
        else:
            raise


def fuzz_chain_state_corrupt_deserialize(data: bytes):
    """Fuzz ChainState deserialization with totally corrupted input."""
    if len(data) < 33:
        return

    encryption_key = data[:32]
    corrupt_data = data[32:]

    try:
        result = ChainState.from_bytes(corrupt_data, encryption_key)
        # Result should be None for corrupted data (fail-closed)
        # or a valid ChainState (unlikely but possible)
        if result is not None:
            assert isinstance(result.chain_key, bytes)
            assert isinstance(result.generation, int)
            assert result.generation >= 0
    except (ValueError, TypeError, struct.error):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["decrypt", "tag", "authentication", "invalid", "corrupt"]):
            pass
        else:
            raise


def fuzz_master_ratchet_load_corrupt(data: bytes):
    """Fuzz MasterRatchet.load() with corrupt state files."""
    if len(data) < 10:
        return

    password = data[:8].decode("utf-8", errors="replace")
    if not password:
        return

    with tempfile.NamedTemporaryFile(suffix=".state", delete=False) as f:
        f.write(data[8:])
        tmppath = f.name

    try:
        from pathlib import Path
        result = MasterRatchet.load(password, Path(tmppath))
        # Should return None for corrupted state (fail-closed)
        if result is not None:
            assert isinstance(result.generation, int)
            assert result.generation >= 0
    except (ValueError, TypeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["decrypt", "authentication", "invalid", "corrupt", "memory"]):
            pass
        else:
            raise
    finally:
        try:
            os.unlink(tmppath)
        except OSError:
            pass


def fuzz_derive_file_key(data: bytes):
    """Fuzz derive_file_key with adversarial inputs."""
    if len(data) < 20:
        return

    password = data[:10].decode("utf-8", errors="replace")
    file_id = data[10:].decode("utf-8", errors="replace")

    if not password or not file_id:
        return

    try:
        key = derive_file_key(password, file_id, salt=data[:32] if len(data) >= 32 else None)
        assert isinstance(key, bytes)
        assert len(key) == 32
    except (ValueError, TypeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if "password" in error_msg or "empty" in error_msg:
            pass
        else:
            raise


def fuzz_ratchet_step_monotonicity(data: bytes):
    """Fuzz ratchet stepping — generation must always increase."""
    if len(data) < 8:
        return

    # Number of ratchet steps to perform (bounded to prevent timeout)
    n_steps = min(data[0], 20)

    try:
        ratchet = MasterRatchet.from_password("fuzz_password", auto_persist=False)
        prev_gen = ratchet.generation

        for _ in range(n_steps):
            ratchet.ratchet()
            assert ratchet.generation == prev_gen + 1, (
                f"Generation not monotonic: {ratchet.generation} != {prev_gen + 1}"
            )
            prev_gen = ratchet.generation

    except (ValueError, TypeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if "memory" in error_msg:
            pass
        else:
            raise


def fuzz_emergency_wipe(data: bytes):
    """Fuzz emergency wipe — must not crash, must zero state."""
    if len(data) < 4:
        return

    with tempfile.NamedTemporaryFile(suffix=".state", delete=False) as f:
        tmppath = f.name

    try:
        from pathlib import Path
        ratchet = MasterRatchet.from_password(
            "fuzz_password",
            state_file=Path(tmppath),
            auto_persist=True,
        )
        # Do some ratchets
        for _ in range(min(data[0] % 5, 3)):
            ratchet.ratchet()

        # Wipe
        result = ratchet.emergency_wipe()
        assert isinstance(result, bool)

        # After wipe, chain_key should be zeroed
        assert ratchet._state.chain_key == bytes(32)
        assert ratchet._state.master_salt == bytes(32)
        assert ratchet._state.generation == 0
    except (ValueError, TypeError, OSError):
        pass
    finally:
        try:
            os.unlink(tmppath)
        except OSError:
            pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_chain_state_roundtrip(data)
        fuzz_chain_state_corrupt_deserialize(data)
        fuzz_master_ratchet_load_corrupt(data)
        fuzz_derive_file_key(data)
        fuzz_ratchet_step_monotonicity(data)
        fuzz_emergency_wipe(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
