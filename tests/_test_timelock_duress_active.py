#!/usr/bin/env python3
"""
⏰ Active tests for timelock_duress.py
"""

import time
import secrets
import pytest

from meow_decoder.timelock_duress import (
    TimeLockConfig,
    TimeLockPuzzle,
    TimeLockState,
    CountdownDuress,
    DeadManSwitch,
)


def test_timelock_config_total_iterations():
    config = TimeLockConfig(lock_duration_seconds=2, hash_iterations_per_second=3)
    assert config.total_iterations() == 6


def test_timelock_state_roundtrip(tmp_path):
    state = TimeLockState(
        puzzle_start_hash=b"\x00" * 32,
        puzzle_target_hash=b"\x01" * 32,
        total_iterations=5,
        iterations_completed=2,
        start_timestamp=1.0,
        unlock_timestamp=2.0,
        last_checkin=3.0,
        countdown_triggered=True,
        deadman_last_renewal=4.0,
        deadman_triggered=True,
    )
    path = tmp_path / "state.json"
    state.save(path)
    loaded = TimeLockState.load(path)
    assert loaded.to_dict() == state.to_dict()


def test_puzzle_create_solve_and_decrypt_small():
    config = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=2)
    puzzle = TimeLockPuzzle(config)

    secret = b"secret-data"
    enc_secret, puzzle_data, state = puzzle.create_puzzle(secret)
    solution, updated_state = puzzle.solve_puzzle(puzzle_data)

    recovered = puzzle.decrypt_secret(enc_secret, solution)
    assert recovered == secret


def test_puzzle_resume_with_progress_callback():
    config = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=2)
    puzzle = TimeLockPuzzle(config)

    secret = b"abc"
    enc_secret, puzzle_data, state = puzzle.create_puzzle(secret)
    state.iterations_completed = 1

    progress = []
    solution, updated = puzzle.solve_puzzle(puzzle_data, state=state, progress_callback=lambda c, t: progress.append((c, t)))
    assert updated.iterations_completed == updated.total_iterations
    assert progress


def test_decrypt_secret_longer_than_32():
    config = TimeLockConfig(lock_duration_seconds=1, hash_iterations_per_second=2)
    puzzle = TimeLockPuzzle(config)

    secret = b"A" * 64
    enc_secret, puzzle_data, state = puzzle.create_puzzle(secret)
    solution, _ = puzzle.solve_puzzle(puzzle_data)
    recovered = puzzle.decrypt_secret(enc_secret, solution)
    assert recovered == secret


def test_countdown_duress_flow(tmp_path, monkeypatch):
    config = TimeLockConfig(checkin_interval_seconds=1, grace_period_seconds=1)
    state_path = tmp_path / "countdown.json"
    cd = CountdownDuress(config, state_path)

    # Initialize and checkin
    monkeypatch.setattr(time, "time", lambda: 100.0)
    cd.initialize()
    assert cd.checkin() is True

    # Advance time beyond deadline
    monkeypatch.setattr(time, "time", lambda: 200.0)
    should_trigger, remaining = cd.check_status()
    assert should_trigger is True
    assert remaining == 0.0


def test_deadman_switch_flow(tmp_path, monkeypatch):
    # Not enabled -> initialize error
    config = TimeLockConfig(deadman_enabled=False)
    dm = DeadManSwitch(config, tmp_path / "deadman.json")
    with pytest.raises(RuntimeError, match="not enabled"):
        dm.initialize()

    # Enabled flow
    config = TimeLockConfig(deadman_enabled=True, deadman_duration_days=1)
    dm = DeadManSwitch(config, tmp_path / "deadman.json")
    monkeypatch.setattr(time, "time", lambda: 100.0)
    dm.initialize()
    assert dm.renew() is True

    # Advance time beyond duration
    monkeypatch.setattr(time, "time", lambda: 100.0 + 2 * 86400)
    should_trigger, remaining = dm.check_status()
    assert should_trigger is True
    assert remaining == 0.0
