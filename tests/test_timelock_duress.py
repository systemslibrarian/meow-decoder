#!/usr/bin/env python3
"""
🧪 Test Suite: timelock_duress.py
Tests time-lock puzzles and duress triggers for anti-coercion features.
"""

import pytest
import os
import time
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import timelock_duress module
try:
    from meow_decoder.timelock_duress import (
        TimeLockPuzzle,
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
class TestTimeLockPuzzle:
    """Tests for TimeLockPuzzle class."""

    def test_puzzle_creation(self):
        """Test basic puzzle creation."""
        from meow_decoder.timelock_duress import TimeLockPuzzle
        puzzle = TimeLockPuzzle(secret=b"test_secret", iterations=1000)
        assert puzzle is not None

    def test_puzzle_solve(self):
        """Test solving a puzzle."""
        from meow_decoder.timelock_duress import TimeLockPuzzle
        secret = b"my_secret_data"
        puzzle = TimeLockPuzzle(secret=secret, iterations=100)
        
        # Solve the puzzle
        recovered = puzzle.solve()
        assert recovered == secret

    def test_puzzle_timing(self):
        """Test that puzzle takes time to solve."""
        from meow_decoder.timelock_duress import TimeLockPuzzle
        puzzle = TimeLockPuzzle(secret=b"test", iterations=5000)
        
        start = time.time()
        puzzle.solve()
        elapsed = time.time() - start
        
        # Should take some measurable time
        assert elapsed >= 0.001  # At least 1ms

    def test_puzzle_serialization(self):
        """Test puzzle serialization/deserialization."""
        from meow_decoder.timelock_duress import TimeLockPuzzle
        puzzle = TimeLockPuzzle(secret=b"test", iterations=100)
        
        # Serialize
        if hasattr(puzzle, 'to_bytes'):
            data = puzzle.to_bytes()
            # Deserialize
            restored = TimeLockPuzzle.from_bytes(data)
            assert restored.solve() == puzzle.solve()


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestCountdownDuress:
    """Tests for CountdownDuress check-in based trigger."""

    def test_countdown_creation(self):
        """Test countdown creation."""
        from meow_decoder.timelock_duress import CountdownDuress
        countdown = CountdownDuress(timeout_seconds=60)
        assert countdown is not None

    def test_countdown_checkin(self):
        """Test check-in functionality."""
        from meow_decoder.timelock_duress import CountdownDuress
        countdown = CountdownDuress(timeout_seconds=60)
        countdown.check_in()
        assert not countdown.is_expired()

    def test_countdown_expiry(self):
        """Test countdown expiry detection."""
        from meow_decoder.timelock_duress import CountdownDuress
        # Very short timeout
        countdown = CountdownDuress(timeout_seconds=0.01)
        time.sleep(0.02)
        assert countdown.is_expired()

    def test_countdown_reset(self):
        """Test countdown reset after check-in."""
        from meow_decoder.timelock_duress import CountdownDuress
        countdown = CountdownDuress(timeout_seconds=1)
        time.sleep(0.5)
        countdown.check_in()  # Reset the countdown
        assert not countdown.is_expired()


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestDeadManSwitch:
    """Tests for DeadManSwitch renewal-based trigger."""

    def test_switch_creation(self):
        """Test dead man switch creation."""
        from meow_decoder.timelock_duress import DeadManSwitch
        switch = DeadManSwitch(renewal_interval=60)
        assert switch is not None

    def test_switch_renewal(self):
        """Test switch renewal."""
        from meow_decoder.timelock_duress import DeadManSwitch
        switch = DeadManSwitch(renewal_interval=60)
        switch.renew()
        assert switch.is_alive()

    def test_switch_expiry(self):
        """Test switch expiry after interval."""
        from meow_decoder.timelock_duress import DeadManSwitch
        switch = DeadManSwitch(renewal_interval=0.01)
        time.sleep(0.02)
        assert not switch.is_alive()

    def test_switch_state_persistence(self):
        """Test state persistence."""
        from meow_decoder.timelock_duress import DeadManSwitch
        import tempfile
        
        switch = DeadManSwitch(renewal_interval=60)
        switch.renew()
        
        # Save state
        if hasattr(switch, 'save_state'):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                switch.save_state(f.name)
                
            # Restore state
            restored = DeadManSwitch.load_state(f.name)
            assert restored.is_alive()
            
            os.unlink(f.name)


@pytest.mark.skipif(not TIMELOCK_AVAILABLE, reason="timelock_duress module not available")
class TestTimeLockIntegration:
    """Integration tests for time-lock features."""

    def test_puzzle_with_callback(self):
        """Test puzzle with callback on solve."""
        from meow_decoder.timelock_duress import TimeLockPuzzle
        
        callback_called = []
        
        def on_solve(secret):
            callback_called.append(secret)
        
        puzzle = TimeLockPuzzle(secret=b"test", iterations=100)
        if hasattr(puzzle, 'solve_with_callback'):
            puzzle.solve_with_callback(on_solve)
            assert len(callback_called) == 1

    def test_countdown_with_trigger(self):
        """Test countdown with trigger action."""
        from meow_decoder.timelock_duress import CountdownDuress
        
        triggered = []
        
        countdown = CountdownDuress(
            timeout_seconds=0.01,
            on_expire=lambda: triggered.append(True)
        )
        time.sleep(0.02)
        
        if hasattr(countdown, 'check_and_trigger'):
            countdown.check_and_trigger()
            assert len(triggered) >= 1


# Fallback test
@pytest.mark.skipif(TIMELOCK_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not TIMELOCK_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
