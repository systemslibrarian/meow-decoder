#!/usr/bin/env python3
"""
⚠️ DEPRECATED: Tests consolidated into test_duress_mode.py
Do not add new tests here. This file will be removed in a future cleanup.

🧪 Test Suite: timelock_duress.py
Tests time-lock puzzles and duress triggers for anti-coercion features.

Maps to source module: meow_decoder/timelock_duress.py

API Pattern:
    - TimeLockPuzzle(config: TimeLockConfig) - Time-lock puzzle creator/solver
    - CountdownDuress(config: TimeLockConfig, state_path: Path) - Check-in based trigger
    - DeadManSwitch(config: TimeLockConfig, state_path: Path) - Renewal-based trigger
"""
import pytest
pytestmark = pytest.mark.skip(reason="DEPRECATED: Merged into test_duress_mode.py")
import os
import time
import tempfile
from pathlib import Path

os.environ["MEOW_TEST_MODE"] = "1"

# Try to import timelock_duress module
try:
    from meow_decoder.timelock_duress import (
        TimeLockPuzzle,
        TimeLockConfig,
        TimeLockState,
        CountdownDuress,
        DeadManSwitch,
    )
    TIMELOCK_AVAILABLE = True
except (ImportError, AttributeError):
    TIMELOCK_AVAILABLE = False
    # Try partial imports
    try:
        from meow_decoder import timelock_duress
        TIMELOCK_AVAILABLE = hasattr(timelock_duress, 'TimeLockPuzzle')
    except ImportError:
        pass


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestTimeLockConfig:
    """Tests for TimeLockConfig dataclass."""

    def test_config_defaults(self):
        """Test default config values."""
        config = TimeLockConfig()
        assert config.lock_duration_seconds == 3600
        assert config.hash_iterations_per_second == 100000
        assert config.use_memory_hard is False
        assert config.checkin_interval_seconds == 86400
        assert config.grace_period_seconds == 3600

    #!/usr/bin/env python3
    """
    ⏰ Time-Lock Duress Tests (consolidated)
    """

    import time
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

        monkeypatch.setattr(time, "time", lambda: 100.0)
        cd.initialize()
        assert cd.checkin() is True

        monkeypatch.setattr(time, "time", lambda: 200.0)
        should_trigger, remaining = cd.check_status()
        assert should_trigger is True
        assert remaining == 0.0


    def test_deadman_switch_flow(tmp_path, monkeypatch):
        config = TimeLockConfig(deadman_enabled=False)
        dm = DeadManSwitch(config, tmp_path / "deadman.json")
        with pytest.raises(RuntimeError, match="not enabled"):
            dm.initialize()

        config = TimeLockConfig(deadman_enabled=True, deadman_duration_days=1)
        dm = DeadManSwitch(config, tmp_path / "deadman.json")
        monkeypatch.setattr(time, "time", lambda: 100.0)
        dm.initialize()
        assert dm.renew() is True

        monkeypatch.setattr(time, "time", lambda: 100.0 + 2 * 86400)
        should_trigger, remaining = dm.check_status()
        assert should_trigger is True
        assert remaining == 0.0
            time.sleep(0.01)  # Wait a tiny bit
            
            should_trigger, time_remaining = countdown.check_status()
            assert should_trigger is True
            assert time_remaining == 0.0

    def test_countdown_manual_trigger(self):
        """Test manual duress trigger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "countdown.json"
            config = TimeLockConfig(
                checkin_interval_seconds=3600,
                grace_period_seconds=600
            )
            countdown = CountdownDuress(config, state_path)
            countdown.initialize()
            
            countdown.trigger_duress()
            
            should_trigger, _ = countdown.check_status()
            assert should_trigger is True


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestDeadManSwitch:
    """Tests for DeadManSwitch renewal-based trigger."""

    def test_switch_creation(self):
        """Test dead man switch creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "deadman.json"
            config = TimeLockConfig(deadman_enabled=True, deadman_duration_days=30)
            switch = DeadManSwitch(config, state_path)
            assert switch is not None


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestTimeLockIntegration:
    """Integration tests for time-lock features."""

    def test_puzzle_progress_callback(self):
        """Test puzzle with progress callback."""
        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=1000  # 1000 iterations
        )
        puzzle = TimeLockPuzzle(config)
        
        secret = b"callback_test"
        encrypted_secret, puzzle_data, state = puzzle.create_puzzle(secret)
        
        progress_updates = []
        
        def on_progress(completed, total):
            progress_updates.append((completed, total))
        
        solution, _ = puzzle.solve_puzzle(puzzle_data, progress_callback=on_progress)
        
        # Should have received some progress updates
        # (every 100K iterations, so might be 0 for small puzzles)
        # Just verify solution works
        recovered = puzzle.decrypt_secret(encrypted_secret, solution)
        assert recovered == secret

    def test_full_workflow(self):
        """Test complete time-lock workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Create time-lock puzzle
            config = TimeLockConfig(
                lock_duration_seconds=1,
                hash_iterations_per_second=100
            )
            puzzle = TimeLockPuzzle(config)
            
            secret = b"full_workflow_secret"
            encrypted_secret, puzzle_data, state = puzzle.create_puzzle(secret)
            
            # 2. Save state
            state_path = Path(tmpdir) / "puzzle_state.json"
            state.save(state_path)
            
            # 3. Load state and verify
            loaded_state = TimeLockState.load(state_path)
            assert loaded_state.total_iterations == state.total_iterations
            
            # 4. Solve puzzle
            solution, _ = puzzle.solve_puzzle(puzzle_data)
            
            # 5. Recover secret
            recovered = puzzle.decrypt_secret(encrypted_secret, solution)
            assert recovered == secret


# Fallback test
@pytest.mark.skipif(TIMELOCK_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not TIMELOCK_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
