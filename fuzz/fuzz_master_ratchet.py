#!/usr/bin/env python3
"""
Fuzz target for master_ratchet.py — cross-session forward secrecy chain.

Tests:
  - MRCV2 sealed-handle on-disk format round-trip and corrupt deserialize
  - MasterRatchet.load() with corrupted state files
  - Emergency wipe path (ensures no crash/leak on adversarial state)
  - derive_file_key with adversarial file_id strings
  - Generation counter monotonicity across ratchet steps

Updated 2026-05-04 for the gemini #1 handle migration:
  - `ChainState.chain_key: bytes` → `chain_handle: Optional[int]`
  - `state.to_bytes/from_bytes` removed; on-disk format is now MRCV2,
    encoded by `_save_state` and decoded by `_decode_chain_state` —
    both round-trip via `HandleBackend.{seal_key,unseal_key}`.
  - The pure-Python `_hkdf_expand` helper is gone (Rust required).

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
        derive_file_key,
        _decode_chain_state,
    )
    from meow_decoder.crypto_backend import get_handle_backend
    import secrets

    return ChainState, MasterRatchet, derive_file_key, _decode_chain_state, get_handle_backend, secrets


if atheris is not None:
    with atheris.instrument_imports():
        ChainState, MasterRatchet, derive_file_key, _decode_chain_state, get_handle_backend, secrets = _setup_imports()
else:
    ChainState, MasterRatchet, derive_file_key, _decode_chain_state, get_handle_backend, secrets = _setup_imports()


def fuzz_mrcv2_state_roundtrip(data: bytes):
    """Fuzz MRCV2 on-disk state save/load round-trip via _save_state +
    _decode_chain_state. Replaces the old fuzz_chain_state_roundtrip
    (which relied on the removed ChainState.to_bytes/from_bytes)."""
    if len(data) < 32:
        return

    password = data[:8].decode("utf-8", errors="replace")
    if not password:
        return

    with tempfile.NamedTemporaryFile(suffix=".state", delete=False) as f:
        tmppath = f.name

    try:
        from pathlib import Path

        # Round-trip: write a state file via from_password+auto_persist,
        # then re-load it via MasterRatchet.load — should recover same gen.
        r1 = MasterRatchet.from_password(
            password, state_file=Path(tmppath), auto_persist=True
        )
        # Optionally ratchet a few times based on fuzz input
        n_steps = min(data[8] % 5 if len(data) > 8 else 0, 3)
        for _ in range(n_steps):
            r1.ratchet()
        gen_before = r1.generation

        r2 = MasterRatchet.load(password, Path(tmppath))
        if r2 is not None:
            assert r2.generation == gen_before, (
                f"generation drift: {r2.generation} != {gen_before}"
            )
            # File-key derivation should be deterministic across reload
            k1 = r1.derive_file_key("fuzz.bin")
            k2 = r2.derive_file_key("fuzz.bin")
            assert k1 == k2, "file key drift after MRCV2 reload"
    except (ValueError, TypeError, struct.error, RuntimeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        # AEAD/decryption errors and Rust-handle errors are expected
        # noise on adversarial input; anything else is a real bug.
        if any(x in error_msg for x in ("decrypt", "tag", "auth", "handle", "seal")):
            pass
        else:
            raise
    finally:
        try:
            os.unlink(tmppath)
        except OSError:
            pass


def fuzz_mrcv2_corrupt_deserialize(data: bytes):
    """Fuzz _decode_chain_state with totally corrupted MRCV2 blobs.

    The decoder must be fail-closed: return None or raise a bounded
    exception class — never crash with a buffer over-read.
    """
    if len(data) < 8:
        return

    password = data[:8].decode("utf-8", errors="replace")
    if not password:
        return
    corrupt_blob = data[8:]

    try:
        hb = get_handle_backend()
        # Derive a state KEK handle (mirrors what MasterRatchet.load does
        # internally). The static helper is internal but accessible.
        kek = MasterRatchet._derive_state_key_handle(hb, password)
        try:
            result = _decode_chain_state(corrupt_blob, kek, hb)
            # Success path: result is a ChainState whose handle is live.
            if result is not None:
                assert isinstance(result.generation, int)
                assert result.generation >= 0
                assert isinstance(result.master_salt, bytes)
                # Drop the chain handle if one was unsealed.
                if result.chain_handle is not None:
                    hb.drop(result.chain_handle)
        finally:
            hb.drop(kek)
    except (ValueError, TypeError, struct.error, RuntimeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ("decrypt", "tag", "auth", "handle", "seal", "invalid")):
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
        # or a valid MasterRatchet (extremely unlikely on random bytes).
        if result is not None:
            assert isinstance(result.generation, int)
            assert result.generation >= 0
            # The handle, if non-None, must be live.
            if result._state.chain_handle is not None:
                assert result._hb.exists(result._state.chain_handle)
    except (ValueError, TypeError, OSError, struct.error):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ("decrypt", "tag", "auth", "invalid", "corrupt", "handle")):
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
        salt = data[:32] if len(data) >= 32 else None
        # The module-level convenience helper.
        key = derive_file_key(password, file_id, salt=salt)
        assert isinstance(key, bytes)
        assert len(key) == 32
    except (ValueError, TypeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ("password", "empty", "handle")):
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
            assert (
                ratchet.generation == prev_gen + 1
            ), f"Generation not monotonic: {ratchet.generation} != {prev_gen + 1}"
            prev_gen = ratchet.generation

    except (ValueError, TypeError):
        pass
    except Exception as e:
        error_msg = str(e).lower()
        if "memory" in error_msg or "handle" in error_msg:
            pass
        else:
            raise


def fuzz_emergency_wipe(data: bytes):
    """Fuzz emergency wipe — must not crash; chain handle must be dropped
    and registry must show it gone after wipe."""
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

        pre_wipe_handle = ratchet._state.chain_handle

        # Wipe
        result = ratchet.emergency_wipe()
        assert isinstance(result, bool)

        # gemini #1 invariants after wipe:
        #  - chain_handle is None (Rust SecretKey dropped + zeroized)
        #  - master_salt zeroed (defence-in-depth on the non-secret salt)
        #  - generation reset
        #  - the previously-held handle is no longer in the registry
        assert ratchet._state.chain_handle is None
        if pre_wipe_handle is not None:
            assert not ratchet._hb.exists(pre_wipe_handle)
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
        fuzz_mrcv2_state_roundtrip(data)
        fuzz_mrcv2_corrupt_deserialize(data)
        fuzz_master_ratchet_load_corrupt(data)
        fuzz_derive_file_key(data)
        fuzz_ratchet_step_monotonicity(data)
        fuzz_emergency_wipe(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
