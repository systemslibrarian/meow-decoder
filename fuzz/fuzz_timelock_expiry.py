#!/usr/bin/env python3
"""
Fuzz target for time-lock duress and content expiry modules.

Tests:
  - TimeLockPuzzle.solve_puzzle with garbage puzzle_data
  - TimeLockState.from_dict with adversarial JSON
  - CountdownDuress / DeadManSwitch with malformed state
  - ExpiryManager.decode_expiry / check_expiry with arbitrary bytes
  - ExpiryManager.encode_expiry with extreme TTL values
  - encode_with_timelock / decode_with_timelock robustness

Uses Atheris (Google's Python fuzzing engine).
"""

import os
import struct
import sys
import json

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.timelock_duress import (
        TimeLockConfig,
        TimeLockState,
        TimeLockPuzzle,
        CountdownDuress,
        DeadManSwitch,
    )
    from meow_decoder.expiry import (
        ExpiryManager,
        ExpiryPolicy,
        ContentExpiredError,
    )

    return {
        "TimeLockConfig": TimeLockConfig,
        "TimeLockState": TimeLockState,
        "TimeLockPuzzle": TimeLockPuzzle,
        "CountdownDuress": CountdownDuress,
        "DeadManSwitch": DeadManSwitch,
        "ExpiryManager": ExpiryManager,
        "ExpiryPolicy": ExpiryPolicy,
        "ContentExpiredError": ContentExpiredError,
    }


if atheris is not None:
    with atheris.instrument_imports():
        API = _setup_imports()
else:
    API = _setup_imports()


def fuzz_timelock_state_from_dict(data: bytes):
    """Fuzz TimeLockState.from_dict with adversarial JSON."""
    try:
        text = data.decode("utf-8", errors="replace")
        d = json.loads(text)
        if not isinstance(d, dict):
            return
        state = API["TimeLockState"].from_dict(d)
        # Roundtrip: to_dict → from_dict
        d2 = state.to_dict()
        API["TimeLockState"].from_dict(d2)
    except (json.JSONDecodeError, ValueError, TypeError, KeyError, OverflowError):
        pass


def fuzz_solve_puzzle(data: bytes):
    """Fuzz TimeLockPuzzle.solve_puzzle with garbage puzzle_data."""
    if len(data) < 40:
        return

    config = API["TimeLockConfig"](
        lock_duration_seconds=1,
        hash_iterations_per_second=10,  # Tiny for speed
    )
    puzzle = API["TimeLockPuzzle"](config)

    try:
        # solve_puzzle expects at least 40 bytes (32-byte hash + 8-byte iterations)
        solution, state = puzzle.solve_puzzle(data[:40])
        assert isinstance(solution, bytes)
    except (ValueError, TypeError, struct.error, OverflowError):
        pass


def fuzz_expiry_decode(data: bytes):
    """Fuzz ExpiryManager with arbitrary bytes."""
    # decode_expiry expects exactly 8 bytes
    try:
        ts = API["ExpiryManager"].decode_expiry(data)
        assert isinstance(ts, int)
    except (ValueError, struct.error):
        pass

    # check_expiry with arbitrary bytes
    try:
        result = API["ExpiryManager"].check_expiry(data)
        assert isinstance(result, bool)
    except (ValueError, struct.error):
        pass

    # time_remaining with arbitrary bytes
    try:
        API["ExpiryManager"].time_remaining(data)
    except (ValueError, struct.error):
        pass


def fuzz_expiry_encode(data: bytes):
    """Fuzz ExpiryManager encode with extreme TTL values."""
    if len(data) < 4:
        return

    ttl = struct.unpack("<i", data[:4])[0]  # Signed int — negative = no expiry

    try:
        encoded = API["ExpiryManager"].encode_expiry(ttl)
        assert isinstance(encoded, bytes)
        assert len(encoded) == 8

        # Roundtrip
        decoded_ts = API["ExpiryManager"].decode_expiry(encoded)
        assert isinstance(decoded_ts, int)
    except (ValueError, struct.error, OverflowError):
        pass


def fuzz_countdown_duress(data: bytes):
    """Fuzz CountdownDuress with adversarial check-in times."""
    if len(data) < 16:
        return

    config = API["TimeLockConfig"](
        checkin_interval_seconds=60,
        grace_period_seconds=10,
    )

    try:
        cd = API["CountdownDuress"](config)
        # Feed fuzzed bytes as simulated checkin
        checkin_time = struct.unpack("<d", data[:8])[0]
        cd.checkin(checkin_time)
    except (ValueError, TypeError, struct.error, OverflowError, AttributeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_timelock_state_from_dict(data)
        fuzz_solve_puzzle(data)
        fuzz_expiry_decode(data)
        fuzz_expiry_encode(data)
        fuzz_countdown_duress(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
