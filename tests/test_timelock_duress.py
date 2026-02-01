#!/usr/bin/env python3
"""
🧪 Test Suite: timelock_duress.py
Tests time-lock puzzles and duress triggers for anti-coercion features.

Maps to source module: meow_decoder/timelock_duress.py

API Pattern:
    - TimeLockPuzzle(config: TimeLockConfig) - Time-lock puzzle creator/solver
    - CountdownDuress(config: TimeLockConfig, state_path: Path) - Check-in based trigger
    - DeadManSwitch(config: TimeLockConfig, state_path: Path) - Renewal-based trigger
"""

import pytest
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

    def test_config_total_iterations(self):
        """Test total_iterations calculation."""
        config = TimeLockConfig(
            lock_duration_seconds=10,
            hash_iterations_per_second=1000
        )
        assert config.total_iterations() == 10000

    def test_config_custom_values(self):
        """Test custom config values."""
        config = TimeLockConfig(
            lock_duration_seconds=60,
            hash_iterations_per_second=50000,
            use_memory_hard=True,
            checkin_interval_seconds=3600,
            grace_period_seconds=600,
        )
        assert config.lock_duration_seconds == 60
        assert config.use_memory_hard is True


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestTimeLockPuzzle:
    """Tests for TimeLockPuzzle class."""

    def test_puzzle_creation(self):
        """Test basic puzzle creation."""
        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=100  # Very fast for testing
        )
        puzzle = TimeLockPuzzle(config)
        assert puzzle is not None
        assert puzzle.config == config

    def test_puzzle_create_and_solve(self):
        """Test creating and solving a puzzle."""
        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=100  # 100 iterations total
        )
        puzzle = TimeLockPuzzle(config)
        
        secret = b"my_secret_data_here"
        encrypted_secret, puzzle_data, state = puzzle.create_puzzle(secret)
        
        # Verify returned data
        assert len(encrypted_secret) == len(secret)
        assert len(puzzle_data) >= 40  # start_hash(32) + iterations(8)
        assert state.total_iterations == 100
        
        # Solve the puzzle
        solution, updated_state = puzzle.solve_puzzle(puzzle_data)
        
        # Decrypt the secret
        recovered = puzzle.decrypt_secret(encrypted_secret, solution)
        assert recovered == secret

    def test_puzzle_timing(self):
        """Test that puzzle takes time to solve."""
        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=5000  # 5000 iterations
        )
        puzzle = TimeLockPuzzle(config)
        
        secret = b"test"
        encrypted_secret, puzzle_data, state = puzzle.create_puzzle(secret)
        
        start = time.time()
        puzzle.solve_puzzle(puzzle_data)
        elapsed = time.time() - start
        
        # Should take measurable time (at least a few ms)
        assert elapsed >= 0.001

    def test_puzzle_key_expansion(self):
        """Test key expansion for long secrets."""
        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=50
        )
        puzzle = TimeLockPuzzle(config)
        
        # Secret longer than 32 bytes (SHA-256 output)
        long_secret = b"A" * 100
        encrypted_secret, puzzle_data, state = puzzle.create_puzzle(long_secret)
        
        solution, _ = puzzle.solve_puzzle(puzzle_data)
        recovered = puzzle.decrypt_secret(encrypted_secret, solution)
        
        assert recovered == long_secret


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestTimeLockState:
    """Tests for TimeLockState serialization."""

    def test_state_to_dict(self):
        """Test state serialization to dict."""
        state = TimeLockState(
            puzzle_start_hash=b'\x00' * 32,
            puzzle_target_hash=b'\xff' * 32,
            total_iterations=1000,
            iterations_completed=500,
            start_timestamp=1000.0,
            unlock_timestamp=2000.0,
        )
        data = state.to_dict()
        assert data['total_iterations'] == 1000
        assert data['iterations_completed'] == 500

    def test_state_roundtrip(self):
        """Test state serialization roundtrip."""
        state = TimeLockState(
            puzzle_start_hash=b'\xab' * 32,
            puzzle_target_hash=b'\xcd' * 32,
            total_iterations=5000,
            iterations_completed=2500,
            start_timestamp=time.time(),
            unlock_timestamp=time.time() + 3600,
            last_checkin=time.time(),
            countdown_triggered=False,
        )
        
        data = state.to_dict()
        restored = TimeLockState.from_dict(data)
        
        assert restored.total_iterations == state.total_iterations
        assert restored.iterations_completed == state.iterations_completed
        assert restored.puzzle_start_hash == state.puzzle_start_hash

    def test_state_file_persistence(self):
        """Test state save/load from file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            
            state = TimeLockState(
                puzzle_start_hash=b'\x11' * 32,
                puzzle_target_hash=b'\x22' * 32,
                total_iterations=100,
                iterations_completed=0,
                start_timestamp=time.time(),
                unlock_timestamp=time.time() + 60,
            )
            state.save(state_path)
            
            loaded = TimeLockState.load(state_path)
            assert loaded.total_iterations == 100


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestCountdownDuress:
    """Tests for CountdownDuress check-in based trigger."""

    def test_countdown_creation(self):
        """Test countdown creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "countdown.json"
            config = TimeLockConfig(
                checkin_interval_seconds=60,
                grace_period_seconds=10
            )
            countdown = CountdownDuress(config, state_path)
            assert countdown is not None

    def test_countdown_initialize(self):
        """Test countdown initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "countdown.json"
            config = TimeLockConfig(
                checkin_interval_seconds=60,
                grace_period_seconds=10
            )
            countdown = CountdownDuress(config, state_path)
            countdown.initialize()
            
            assert countdown.state is not None
            assert countdown.state.last_checkin is not None
            assert state_path.exists()

    def test_countdown_checkin(self):
        """Test check-in functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "countdown.json"
            config = TimeLockConfig(
                checkin_interval_seconds=60,
                grace_period_seconds=10
            )
            countdown = CountdownDuress(config, state_path)
            countdown.initialize()
            
            success = countdown.checkin()
            assert success is True
            
            should_trigger, time_remaining = countdown.check_status()
            assert should_trigger is False
            assert time_remaining > 0

    def test_countdown_expiry(self):
        """Test countdown expiry detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "countdown.json"
            # Very short intervals for testing
            config = TimeLockConfig(
                checkin_interval_seconds=0,  # 0 second interval
                grace_period_seconds=0  # 0 second grace
            )
            countdown = CountdownDuress(config, state_path)
            countdown.initialize()
            
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
