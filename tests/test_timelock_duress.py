#!/usr/bin/env python3
"""Tests for meow_decoder.timelock_duress.
Focus on time-lock puzzle and countdown/deadman state.
"""

from pathlib import Path

import pytest

from meow_decoder.timelock_duress import (
    TimeLockConfig,
    TimeLockState,
    TimeLockPuzzle,
    CountdownDuress,
    DeadManSwitch,
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
