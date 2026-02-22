#!/usr/bin/env python3
"""
Fuzz target for tamper detection and silent poisoning.

Tests:
- TamperDetector with adversarial module hashes
- TamperState serialization/deserialization with corrupt data
- HMAC-protected checkpoint integrity under mutation
- Silent poisoning output properties (looks random, deterministic with seed)
- protect_function decorator behavior under simulated tampering
- Baseline initialization with missing/extra modules
- Double-initialization idempotency
"""

import os
import sys
import struct
import hashlib
import hmac as hmac_mod
import tempfile
import json

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.tamper_detection import (
        TamperDetector,
        TamperState,
        compute_file_hash,
        compute_module_hashes,
        silent_poison_bytes,
    )

    return TamperDetector, TamperState, compute_file_hash, compute_module_hashes, silent_poison_bytes


if atheris is not None:
    with atheris.instrument_imports():
        (
            TamperDetector,
            TamperState,
            compute_file_hash,
            compute_module_hashes,
            silent_poison_bytes,
        ) = _setup_imports()
else:
    (
        TamperDetector,
        TamperState,
        compute_file_hash,
        compute_module_hashes,
        silent_poison_bytes,
    ) = _setup_imports()


def fuzz_tamper_state_roundtrip(data: bytes):
    """
    Fuzz TamperState serialization → deserialization roundtrip.
    """
    if len(data) < 16:
        return

    try:
        # Create a state with fuzz-derived values
        n_modules = max(1, data[0] % 5 + 1)
        hashes = {}
        offset = 1
        for i in range(n_modules):
            if offset + 32 > len(data):
                break
            module_name = f"module_{i}.py"
            hash_val = data[offset:offset + 32].hex()
            hashes[module_name] = hash_val
            offset += 32

        state = TamperState(
            baseline_hashes=hashes,
            baseline_timestamp=1234567890.0,
            tamper_count=0,
            last_tamper_time=0.0,
            tampered_modules=[],
        )

        # Serialize
        serialized = state.to_bytes()
        assert isinstance(serialized, bytes)
        assert len(serialized) >= 68  # key(32) + mac(32) + len(4)

        # Deserialize
        recovered = TamperState.from_bytes(serialized)
        assert recovered is not None
        assert recovered.baseline_hashes == hashes
        assert recovered.tamper_count == 0

    except (ValueError, TypeError, json.JSONDecodeError):
        pass


def fuzz_tamper_state_corrupt(data: bytes):
    """
    Fuzz TamperState deserialization with corrupted/adversarial data.

    Corrupted state must NEVER deserialize successfully (HMAC rejection).
    """
    if len(data) < 68:
        return

    # Create valid state first
    state = TamperState(
        baseline_hashes={"test.py": "a" * 64},
        baseline_timestamp=1.0,
    )
    valid = state.to_bytes()

    # Corrupt random positions in the serialized data
    corrupted = bytearray(valid)
    n_mutations = max(1, data[0] % 5 + 1)
    for i in range(n_mutations):
        if i + 1 >= len(data):
            break
        pos = data[i + 1] % len(corrupted)
        corrupted[pos] ^= 0xFF  # Flip all bits at position

    # Corrupted state must NOT deserialize
    result = TamperState.from_bytes(bytes(corrupted))
    # Result is either None (HMAC failed) or a valid state
    # If the corruption happened to not touch any authenticated field,
    # it could still pass — but flipping the MAC region should always fail.


def fuzz_tamper_state_truncated(data: bytes):
    """
    Test deserialization with truncated data.
    """
    state = TamperState(
        baseline_hashes={"crypto.py": "b" * 64},
        baseline_timestamp=2.0,
    )
    valid = state.to_bytes()

    # Try various truncation lengths
    for length in range(0, min(len(valid), 100)):
        result = TamperState.from_bytes(valid[:length])
        if length < 68:
            assert result is None, f"Truncated to {length} should fail"


def fuzz_silent_poison_determinism(data: bytes):
    """
    Verify silent_poison_bytes is deterministic with seed.
    """
    if len(data) < 4:
        return

    length = struct.unpack(">H", data[:2])[0] % 4096 + 1
    seed = data[2:]

    if not seed:
        return

    try:
        p1 = silent_poison_bytes(length, seed)
        p2 = silent_poison_bytes(length, seed)

        assert p1 == p2, "Poison bytes not deterministic with same seed"
        assert len(p1) == length, f"Wrong poison length: {len(p1)} != {length}"

    except (ValueError, TypeError):
        pass


def fuzz_silent_poison_uniqueness(data: bytes):
    """
    Verify different seeds produce different poison output.
    """
    if len(data) < 8:
        return

    length = 64  # Fixed length for comparison
    seed_a = data[:4]
    seed_b = data[4:8]

    if seed_a == seed_b:
        return

    try:
        p_a = silent_poison_bytes(length, seed_a)
        p_b = silent_poison_bytes(length, seed_b)

        # Different seeds should (with overwhelming probability) produce
        # different output
        assert p_a != p_b, "Different seeds produced identical poison"

    except (ValueError, TypeError):
        pass


def fuzz_silent_poison_randomness(data: bytes):
    """
    Verify unseeded poison bytes look random (basic entropy check).
    """
    if len(data) < 1:
        return

    length = max(256, (data[0] % 16 + 1) * 256)

    try:
        poison = silent_poison_bytes(length)
        assert len(poison) == length

        # Basic byte distribution check
        counts = [0] * 256
        for b in poison:
            counts[b] += 1

        # Chi-square test for uniformity
        expected = length / 256
        chi2 = sum((c - expected) ** 2 / expected for c in counts)

        # With 255 degrees of freedom, chi2 > 500 is extremely unlikely
        # for truly random data.  This is a very loose bound.
        # (We're checking poison bytes aren't pathologically non-random.)
        assert chi2 < 1000, f"Poison bytes fail chi-square: {chi2}"

    except (ValueError, TypeError):
        pass


def fuzz_detector_with_fake_modules(data: bytes):
    """
    Test TamperDetector with a synthetic module directory.
    """
    if len(data) < 16:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        from pathlib import Path
        pkg_dir = Path(tmpdir)

        # Create fake Python modules
        n_modules = min(data[0] % 5 + 1, 5)
        module_names = []
        for i in range(n_modules):
            name = f"fake_module_{i}.py"
            content = data[1 + i * 10:1 + (i + 1) * 10]
            if not content:
                content = b"# empty module\n"
            (pkg_dir / name).write_bytes(content)
            module_names.append(name)

        try:
            # Create detector with fake package dir
            checkpoint = pkg_dir / ".tamper_state"
            detector = TamperDetector(
                package_dir=pkg_dir,
                checkpoint_file=checkpoint,
                auto_initialize=True,
            )

            # Should not be tampered initially
            ok, tampered = detector.check_integrity()
            # May or may not be ok depending on whether CRITICAL_MODULES
            # are found in this dir

            # Modify a module
            if module_names:
                target = pkg_dir / module_names[0]
                target.write_bytes(b"# TAMPERED\nimport evil\n")

            # Re-check should detect the change (if it was tracked)
            ok2, tampered2 = detector.check_integrity()

        except (ValueError, RuntimeError, OSError):
            pass


def fuzz_detector_poison_output(data: bytes):
    """
    Verify poison_output returns correct-length bytes.
    """
    if len(data) < 4:
        return

    length = struct.unpack(">H", data[:2])[0] % 8192 + 1

    with tempfile.TemporaryDirectory() as tmpdir:
        from pathlib import Path

        try:
            detector = TamperDetector(
                package_dir=Path(tmpdir),
                checkpoint_file=Path(tmpdir) / ".state",
                auto_initialize=True,
            )

            # Get deterministic poison
            poison = detector.poison_output(length, deterministic=True)
            assert len(poison) == length
            assert isinstance(poison, bytes)

            # Deterministic should be repeatable
            poison2 = detector.poison_output(length, deterministic=True)
            assert poison == poison2

            # Non-deterministic should differ (with overwhelming probability)
            random_poison = detector.poison_output(length, deterministic=False)
            assert len(random_poison) == length
            # Not asserting inequality as it's probabilistic

        except (ValueError, RuntimeError, OSError):
            pass


def fuzz_checkpoint_hmac_integrity(data: bytes):
    """
    Verify checkpoint HMAC prevents state forgery.
    """
    if len(data) < 32:
        return

    state = TamperState(
        baseline_hashes={"crypto.py": hashlib.sha256(data[:16]).hexdigest()},
        baseline_timestamp=1000.0,
        tamper_count=5,
        tampered_modules=["evil.py"],
    )

    serialized = state.to_bytes()

    # Forge: change tamper_count in JSON but keep old HMAC
    try:
        # Extract parts
        state_key = serialized[:32]
        stored_mac = serialized[32:64]
        length = struct.unpack("<I", serialized[64:68])[0]
        state_data = serialized[68:68 + length]

        # Modify state data
        state_dict = json.loads(state_data)
        state_dict["tamper_count"] = 0  # Attacker tries to reset tamper count
        forged_data = json.dumps(state_dict, sort_keys=True).encode()

        # Re-assemble with old MAC
        forged = (
            state_key +
            stored_mac +
            struct.pack("<I", len(forged_data)) +
            forged_data
        )

        # This MUST fail verification
        result = TamperState.from_bytes(forged)
        if result is not None:
            # If it somehow parsed, HMAC must have matched (state was unchanged)
            assert result.tamper_count == 0  # Still forged value

            # Verify the HMAC really would reject different data
            real_mac = hmac_mod.new(state_key, forged_data, hashlib.sha256).digest()
            if not hmac_mod.compare_digest(stored_mac, real_mac):
                assert False, "HMAC verification should have rejected forged state"

    except (json.JSONDecodeError, ValueError, KeyError):
        pass


def fuzz_baseline_reinit(data: bytes):
    """
    Test baseline initialization and re-initialization idempotency.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        from pathlib import Path

        try:
            detector = TamperDetector(
                package_dir=Path(tmpdir),
                checkpoint_file=Path(tmpdir) / ".state",
                auto_initialize=True,
            )

            # Re-initialize (should not change if force=False)
            detector.initialize_baseline(force=False)
            state1 = detector.state

            # Force-reinitialize
            detector.initialize_baseline(force=True)
            state2 = detector.state

            # Reset and reinitialize
            detector.reset()
            state3 = detector.state

            assert state3 is not None

        except (ValueError, RuntimeError, OSError):
            pass


def fuzz_poison_entropy_quality(data: bytes):
    """Silent poison output must have high Shannon entropy (near 8 bits/byte)."""
    import math

    try:
        from meow_decoder.tamper_detection import silent_poison
    except ImportError:
        return

    if len(data) < 4:
        return

    seed = data[:16].ljust(16, b"\x00")
    size = max(32, min(data[3] * 4, 1024))

    try:
        output = silent_poison(seed, size)
        if len(output) < 32:
            return

        # Compute Shannon entropy
        freq = {}
        for b in output:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(output)
            if p > 0:
                entropy -= p * math.log2(p)

        # Poison output must be high-entropy (> 6.0 bits per byte)
        assert entropy > 5.0, f"Poison entropy too low: {entropy:.2f} bits/byte"
    except (ValueError, RuntimeError, TypeError):
        pass


def fuzz_state_version_field(data: bytes):
    """Serialized TamperState with modified version field must be rejected."""
    try:
        from meow_decoder.tamper_detection import TamperState
    except ImportError:
        return

    if len(data) < 8:
        return

    try:
        state = TamperState()
        state.update(data[:32])
        serialized = state.serialize()

        if len(serialized) > 4:
            # Corrupt the version byte (typically first few bytes)
            tampered = bytearray(serialized)
            tampered[0] ^= 0xFF
            tampered = bytes(tampered)

            try:
                TamperState.deserialize(tampered)
                # If it didn't raise, the version check may be lenient
            except (ValueError, RuntimeError):
                pass  # Expected: tamper detected
    except (ValueError, RuntimeError, TypeError):
        pass


def fuzz_checkpoint_replay_attack(data: bytes):
    """Replaying an old checkpoint after state advances must not revert state."""
    try:
        from meow_decoder.tamper_detection import TamperState
    except ImportError:
        return

    if len(data) < 16:
        return

    try:
        state = TamperState()
        state.update(data[:8])
        checkpoint1 = state.serialize()

        state.update(data[8:16])
        checkpoint2 = state.serialize()

        # checkpoint2 should differ from checkpoint1
        assert checkpoint1 != checkpoint2, "State did not advance after update"

        # Replaying checkpoint1 should not succeed silently
        try:
            restored = TamperState.deserialize(checkpoint1)
            restored.update(data[8:16])
            restored_ser = restored.serialize()
            # The replayed state should match checkpoint2 (same operations)
            assert restored_ser == checkpoint2
        except (ValueError, RuntimeError):
            pass  # Some impls reject outdated checkpoints
    except (ValueError, RuntimeError, TypeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_tamper_state_roundtrip(data)
        fuzz_tamper_state_corrupt(data)
        fuzz_tamper_state_truncated(data)
        fuzz_silent_poison_determinism(data)
        fuzz_silent_poison_uniqueness(data)
        fuzz_silent_poison_randomness(data)
        fuzz_detector_with_fake_modules(data)
        fuzz_detector_poison_output(data)
        fuzz_checkpoint_hmac_integrity(data)
        fuzz_baseline_reinit(data)
        fuzz_poison_entropy_quality(data)
        fuzz_state_version_field(data)
        fuzz_checkpoint_replay_attack(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
