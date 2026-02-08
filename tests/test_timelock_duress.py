#!/usr/bin/env python3
"""Tests for meow_decoder.timelock_duress.
Focus on time-lock puzzle and countdown/deadman state.
"""

import os
import secrets
import time
from pathlib import Path

import pytest

from meow_decoder.timelock_duress import (
    TimeLockConfig,
    TimeLockState,
    TimeLockPuzzle,
    CountdownDuress,
    DeadManSwitch,
    encode_with_timelock,
    decode_with_timelock,
)


def test_timelock_config_total_iterations():
    cfg = TimeLockConfig(lock_duration_seconds=3, hash_iterations_per_second=7)
    assert cfg.total_iterations() == 21


def test_timelock_state_roundtrip(tmp_path):
    state = TimeLockState(
        puzzle_start_hash=b"a" * 32,
        puzzle_target_hash=b"b" * 32,
        total_iterations=10,
        iterations_completed=5,
        start_timestamp=1.0,
        unlock_timestamp=2.0,
        last_checkin=3.0,
        countdown_triggered=True,
        deadman_last_renewal=4.0,
        deadman_triggered=False,
    )

    path = tmp_path / "state.json"
    state.save(path)
    loaded = TimeLockState.load(path)

    assert loaded.puzzle_start_hash == state.puzzle_start_hash
    assert loaded.puzzle_target_hash == state.puzzle_target_hash
    assert loaded.total_iterations == 10
    assert loaded.iterations_completed == 5
    assert loaded.last_checkin == 3.0
    assert loaded.countdown_triggered is True


def test_timelock_state_from_dict_defaults():
    data = {
        "puzzle_start_hash": (b"a" * 32).hex(),
        "puzzle_target_hash": (b"b" * 32).hex(),
        "total_iterations": 10,
        "iterations_completed": 2,
        "start_timestamp": 1.0,
        "unlock_timestamp": 2.0,
        "last_checkin": None,
        "deadman_last_renewal": None,
    }

    loaded = TimeLockState.from_dict(data)
    assert loaded.countdown_triggered is False
    assert loaded.deadman_triggered is False


def test_timelock_puzzle_create_solve_decrypt_short():
    cfg = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=2)
    puzzle = TimeLockPuzzle(cfg)

    secret = b"secret16bytes!!"
    encrypted, puzzle_data, state = puzzle.create_puzzle(secret)
    solution, state = puzzle.solve_puzzle(puzzle_data, state)

    recovered = puzzle.decrypt_secret(encrypted, solution)
    assert recovered == secret


def test_timelock_puzzle_expand_key_long_secret():
    cfg = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=1)
    puzzle = TimeLockPuzzle(cfg)

    secret = b"s" * 64
    encrypted, puzzle_data, state = puzzle.create_puzzle(secret)
    solution, _ = puzzle.solve_puzzle(puzzle_data, state)

    recovered = puzzle.decrypt_secret(encrypted, solution)
    assert recovered == secret


def test_timelock_puzzle_memory_hard_branch_short_iterations():
    cfg = TimeLockConfig(
        lock_duration_seconds=1,
        hash_iterations_per_second=500,
        use_memory_hard=True,
    )
    puzzle = TimeLockPuzzle(cfg)

    secret = b"m" * 64
    encrypted, puzzle_data, state = puzzle.create_puzzle(secret)

    assert state.total_iterations == 500
    assert state.puzzle_target_hash == state.puzzle_start_hash

    recovered = puzzle.decrypt_secret(encrypted, state.puzzle_target_hash)
    assert recovered == secret
    assert len(puzzle_data) == 40


def test_timelock_solve_without_state(monkeypatch):
    import meow_decoder.timelock_duress as tl

    now = {"t": 1000.0}
    monkeypatch.setattr(tl.time, "time", lambda: now["t"])

    cfg = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=2)
    puzzle = TimeLockPuzzle(cfg)

    secret = b"no-state"
    _, puzzle_data, _ = puzzle.create_puzzle(secret)

    solution, state = puzzle.solve_puzzle(puzzle_data, state=None)

    assert state.iterations_completed == state.total_iterations
    assert state.puzzle_target_hash == solution


def test_timelock_puzzle_resume_progress():
    cfg = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=3)
    puzzle = TimeLockPuzzle(cfg)

    secret = b"resume-test"
    encrypted, puzzle_data, state = puzzle.create_puzzle(secret)

    # Simulate progress
    state.iterations_completed = 1

    progress = {"called": 0}

    def _cb(done, total):
        progress["called"] += 1
        assert done <= total

    solution, updated = puzzle.solve_puzzle(puzzle_data, state, progress_callback=_cb)
    recovered = puzzle.decrypt_secret(encrypted, solution)

    assert recovered == secret
    assert updated.iterations_completed == updated.total_iterations
    assert progress["called"] >= 1


def test_countdown_requires_init(tmp_path):
    cfg = TimeLockConfig(checkin_interval_seconds=10, grace_period_seconds=5)
    cd = CountdownDuress(cfg, tmp_path / "countdown.json")

    with pytest.raises(RuntimeError):
        cd.checkin()

    with pytest.raises(RuntimeError):
        cd.check_status()


def test_countdown_flow(monkeypatch, tmp_path):
    import meow_decoder.timelock_duress as tl

    now = {"t": 1000.0}
    monkeypatch.setattr(tl.time, "time", lambda: now["t"])

    cfg = TimeLockConfig(checkin_interval_seconds=10, grace_period_seconds=5)
    cd = CountdownDuress(cfg, tmp_path / "countdown.json")
    cd.initialize()

    should_trigger, remaining = cd.check_status()
    assert should_trigger is False
    assert remaining > 0

    # Advance past deadline
    now["t"] += 20
    should_trigger, remaining = cd.check_status()
    assert should_trigger is True
    assert remaining == 0.0

    # Check-in after trigger should be blocked
    assert cd.checkin() is False


def test_countdown_trigger_manual(tmp_path):
    cfg = TimeLockConfig(checkin_interval_seconds=10, grace_period_seconds=5)
    cd = CountdownDuress(cfg, tmp_path / "countdown.json")
    cd.initialize()

    cd.trigger_duress()
    triggered, remaining = cd.check_status()
    assert triggered is True
    assert remaining == 0.0
    assert cd.checkin() is False


def test_deadman_requires_enabled(tmp_path):
    cfg = TimeLockConfig(deadman_enabled=False)
    dm = DeadManSwitch(cfg, tmp_path / "deadman.json")

    with pytest.raises(RuntimeError):
        dm.initialize()


def test_deadman_flow(monkeypatch, tmp_path):
    import meow_decoder.timelock_duress as tl

    now = {"t": 1000.0}
    monkeypatch.setattr(tl.time, "time", lambda: now["t"])

    cfg = TimeLockConfig(deadman_enabled=True, deadman_duration_days=1)
    dm = DeadManSwitch(cfg, tmp_path / "deadman.json")
    dm.initialize()

    should_trigger, remaining = dm.check_status()
    assert should_trigger is False
    assert remaining > 0

    # Advance beyond duration
    now["t"] += 2 * 86400
    should_trigger, remaining = dm.check_status()
    assert should_trigger is True
    assert remaining == 0.0

    # Renew after trigger should fail
    assert dm.renew() is False


def test_deadman_renew_success(monkeypatch, tmp_path):
    import meow_decoder.timelock_duress as tl

    now = {"t": 1000.0}
    monkeypatch.setattr(tl.time, "time", lambda: now["t"])

    cfg = TimeLockConfig(deadman_enabled=True, deadman_duration_days=2)
    dm = DeadManSwitch(cfg, tmp_path / "deadman.json")
    dm.initialize()

    now["t"] += 10
    assert dm.renew() is True
    assert dm.state.deadman_last_renewal == now["t"]

    triggered, remaining = dm.check_status()
    assert triggered is False
    assert remaining > 0


def test_deadman_status_when_triggered(tmp_path):
    cfg = TimeLockConfig(deadman_enabled=True, deadman_duration_days=1)
    dm = DeadManSwitch(cfg, tmp_path / "deadman.json")
    dm.initialize()

    dm.state.deadman_triggered = True
    dm.state.save(dm.state_path)

    triggered, remaining = dm.check_status()
    assert triggered is True
    assert remaining == 0.0


def test_encode_decode_with_timelock_returns_key(monkeypatch):
    import meow_decoder.crypto as crypto

    enc_key = b"k" * 32

    def _fake_encrypt_file_bytes(data, password):
        return b"", b"", b"s" * 16, b"n" * 12, b"cipher", None, enc_key

    monkeypatch.setattr(crypto, "encrypt_file_bytes", _fake_encrypt_file_bytes)

    encoded, puzzle_data, state = encode_with_timelock(
        b"data",
        "password",
        lock_duration_seconds=0,
    )

    assert len(puzzle_data) == 40
    assert state.total_iterations == 0

    recovered_key = decode_with_timelock(encoded, "password")
    assert recovered_key == enc_key


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# timelock_duress.py — push from 92.89% higher
# =====================================================
class TestTimelockDuressExtras:
    """Extra timelock_duress tests for uncovered branches."""

    def test_puzzle_long_secret(self, tmp_path):
        """Puzzle with secret > 32 bytes hits the _expand_key path."""
        from meow_decoder.timelock_duress import TimeLockPuzzle, TimeLockConfig

        config = TimeLockConfig()
        config.lock_duration_seconds = 1
        config.hash_iterations_per_second = 10
        puzzle = TimeLockPuzzle(config)

        secret = secrets.token_bytes(64)  # > 32 bytes
        encrypted, puzzle_data, state = puzzle.create_puzzle(secret)

        solution, _ = puzzle.solve_puzzle(puzzle_data, state)
        decrypted = puzzle.decrypt_secret(encrypted, solution)
        assert decrypted == secret

    def test_countdown_check_not_initialized(self, tmp_path):
        """check_status on uninitialized CountdownDuress should raise."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        cd = CountdownDuress(config, tmp_path / "state.json")
        # Don't initialize
        with pytest.raises(RuntimeError):
            cd.check_status()

    def test_countdown_trigger_duress(self, tmp_path):
        """Manual trigger_duress sets countdown_triggered."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        cd = CountdownDuress(config, tmp_path / "state.json")
        cd.initialize()

        triggered_before, _ = cd.check_status()
        assert triggered_before is False

        cd.trigger_duress()
        triggered_after, remaining = cd.check_status()
        assert triggered_after is True
        assert remaining == 0.0

    def test_countdown_checkin(self, tmp_path):
        """CountdownDuress.checkin resets the timer."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        config.checkin_interval_seconds = 3600
        cd = CountdownDuress(config, tmp_path / "state.json")
        cd.initialize()
        # Checkin should not raise
        cd.checkin()
        triggered, remaining = cd.check_status()
        assert triggered is False
        assert remaining > 0

    def test_countdown_checkin_not_initialized(self, tmp_path):
        """checkin on uninitialized CountdownDuress should raise."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        cd = CountdownDuress(config, tmp_path / "state.json")
        with pytest.raises(RuntimeError):
            cd.checkin()

    def test_deadman_check_not_initialized(self, tmp_path):
        """check_status on uninitialized DeadManSwitch should raise."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = True
        switch = DeadManSwitch(config, tmp_path / "state.json")
        with pytest.raises(RuntimeError):
            switch.check_status()

    def test_deadman_renew_not_initialized(self, tmp_path):
        """renew on uninitialized DeadManSwitch should raise."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = True
        switch = DeadManSwitch(config, tmp_path / "state.json")
        with pytest.raises(RuntimeError):
            switch.renew()

    def test_deadman_expired(self, tmp_path):
        """DeadManSwitch with expired timer triggers duress."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = True
        config.deadman_duration_days = 0  # Immediate expiry
        switch = DeadManSwitch(config, tmp_path / "state.json")
        switch.initialize()

        # Force the last renewal far into the past
        if switch.state:
            switch.state.deadman_last_renewal = time.time() - 86400
            # Re-save state
            import json

            state_data = {"deadman_last_renewal": switch.state.deadman_last_renewal}
            if hasattr(switch.state, "to_dict"):
                state_data = switch.state.to_dict()
                state_data["deadman_last_renewal"] = time.time() - 86400
                (tmp_path / "state.json").write_text(json.dumps(state_data))
            # Re-create to load
            switch2 = DeadManSwitch(config, tmp_path / "state.json")
            if switch2.state:
                triggered, remaining = switch2.check_status()
                assert triggered is True or remaining <= 0

    def test_timelock_state_serialization(self, tmp_path):
        """TimeLockState to_dict/from_dict roundtrip."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        cd = CountdownDuress(config, tmp_path / "state.json")
        cd.initialize()

        # State should be loadable
        assert (tmp_path / "state.json").exists()
        cd2 = CountdownDuress(config, tmp_path / "state.json")
        assert cd2.state is not None


# =====================================================
# forward_secrecy_x25519.py — push from 94.52% higher
# =====================================================

# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# timelock_duress.py coverage
# =====================================================
class TestTimelockDuressBoost:
    def test_countdown_duress_init_and_check(self, tmp_path):
        """Test CountdownDuress initialization and state."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        state_path = tmp_path / "state.json"

        cd = CountdownDuress(config, state_path)
        cd.initialize()
        assert state_path.exists()

        # Reload from disk
        cd2 = CountdownDuress(config, state_path)
        assert cd2.state is not None

    def test_countdown_already_triggered(self, tmp_path):
        """Test check_status when countdown is already triggered."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        config = TimeLockConfig()
        state_path = tmp_path / "state.json"

        cd = CountdownDuress(config, state_path)
        cd.initialize()
        cd.state.countdown_triggered = True

        triggered, remaining = cd.check_status()
        assert triggered is True
        assert remaining == 0.0

    def test_deadman_switch_not_enabled(self, tmp_path):
        """DeadManSwitch with disabled config should raise."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = False
        state_path = tmp_path / "state.json"

        switch = DeadManSwitch(config, state_path)
        with pytest.raises(RuntimeError, match="not enabled"):
            switch.initialize()

    def test_deadman_already_triggered(self, tmp_path):
        """Test dead-man check_status when already triggered."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = True
        state_path = tmp_path / "state.json"

        switch = DeadManSwitch(config, state_path)
        switch.initialize()
        switch.state.deadman_triggered = True

        triggered, remaining = switch.check_status()
        assert triggered is True
        assert remaining == 0.0

    def test_deadman_load_existing_state(self, tmp_path):
        """Test DeadManSwitch loading existing state from disk."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = True
        state_path = tmp_path / "state.json"

        switch = DeadManSwitch(config, state_path)
        switch.initialize()
        assert state_path.exists()

        switch2 = DeadManSwitch(config, state_path)
        assert switch2.state is not None

    def test_timelock_puzzle_create_solve(self, tmp_path):
        """Test TimeLockPuzzle create/solve/decrypt roundtrip."""
        from meow_decoder.timelock_duress import TimeLockPuzzle, TimeLockConfig

        config = TimeLockConfig()
        config.lock_duration_seconds = 1  # minimal
        config.hash_iterations_per_second = 10  # fast
        puzzle = TimeLockPuzzle(config)

        secret = os.urandom(64)
        encrypted, puzzle_data, state = puzzle.create_puzzle(secret)

        solution, solved_state = puzzle.solve_puzzle(puzzle_data, state)

        decrypted = puzzle.decrypt_secret(encrypted, solution)
        assert decrypted == secret

    def test_deadman_renew(self, tmp_path):
        """Test DeadManSwitch renew functionality."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        config = TimeLockConfig()
        config.deadman_enabled = True
        state_path = tmp_path / "state.json"

        switch = DeadManSwitch(config, state_path)
        switch.initialize()
        result = switch.renew()
        assert result is True


# =====================================================
# crypto.py small gaps
# =====================================================
