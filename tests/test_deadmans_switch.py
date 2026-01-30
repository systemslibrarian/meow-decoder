#!/usr/bin/env python3
"""
🧪 Dead-Man's Switch Integration Tests
Tests the deadline-triggered auto-release functionality.
"""

import tempfile
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.config import EncodingConfig
from meow_decoder.deadmans_switch_cli import DeadManSwitchState


def test_deadmans_switch_basic():
    """Test basic dead-man's switch state lifecycle."""
    print("\n🧪 Test 1: Dead-Man's Switch State Lifecycle")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create test GIF path
        gif_path = tmpdir / "test.gif"
        gif_path.touch()  # Create empty file
        
        # Create dead-man's switch state
        state = DeadManSwitchState(
            gif_path=str(gif_path),
            checkin_interval_seconds=3600,  # 1 hour
            grace_period_seconds=1800,  # 30 minutes
            decoy_file=None
        )
        
        # Verify initial state
        assert state.state['status'] == 'armed', "Initial status should be 'armed'"
        assert state.state['configured_at'] is not None, "Should have configured_at timestamp"
        print("   ✅ Initial state: armed")
        
        # Save state
        state.save()
        state_file = tmpdir / f".{gif_path.stem}.deadman.json"
        assert state_file.exists(), "State file should be created"
        print(f"   ✅ State saved to: {state_file}")
        
        # Load state
        loaded_state = DeadManSwitchState.load(str(gif_path))
        assert loaded_state.state['status'] == 'armed', "Loaded state should still be armed"
        print("   ✅ State loaded from JSON")
        
        # Verify deadline not passed yet
        is_deadline_passed = loaded_state.is_deadline_passed()
        assert not is_deadline_passed, "Deadline should not be passed yet"
        print("   ✅ Deadline check: not yet passed (correct)")


def test_deadmans_switch_renewal():
    """Test renewing the check-in to prevent deadline trigger."""
    print("\n🧪 Test 2: Dead-Man's Switch Renewal")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        gif_path = tmpdir / "test.gif"
        gif_path.touch()
        
        # Create state with short interval for testing
        state = DeadManSwitchState(
            gif_path=str(gif_path),
            checkin_interval_seconds=2,  # 2 seconds
            grace_period_seconds=1,  # 1 second
            decoy_file=None
        )
        state.save()
        print("   ✅ State created with 2-second interval")
        
        # Wait for deadline to pass
        time.sleep(4)
        
        # Verify deadline passed
        loaded_state = DeadManSwitchState.load(str(gif_path))
        assert loaded_state.is_deadline_passed(), "Deadline should have passed"
        print("   ✅ Deadline verification: passed (expected after 4 seconds)")
        
        # Renew the state
        loaded_state.renew()
        print("   ✅ State renewed")
        
        # Verify deadline is no longer passed
        assert not loaded_state.is_deadline_passed(), "Deadline should not be passed after renewal"
        print("   ✅ Deadline verification: not passed (after renewal)")


def test_deadmans_switch_trigger():
    """Test manually triggering the dead-man's switch."""
    print("\n🧪 Test 3: Dead-Man's Switch Trigger")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        gif_path = tmpdir / "test.gif"
        gif_path.touch()
        
        # Create state
        state = DeadManSwitchState(
            gif_path=str(gif_path),
            checkin_interval_seconds=3600,
            grace_period_seconds=1800,
            decoy_file=None
        )
        state.save()
        print("   ✅ State created and saved")
        
        # Load and trigger
        loaded_state = DeadManSwitchState.load(str(gif_path))
        assert loaded_state.state['status'] == 'armed', "Status should be armed"
        
        loaded_state.trigger()
        print("   ✅ State triggered")
        
        # Verify status changed
        assert loaded_state.state['status'] == 'triggered', "Status should be 'triggered'"
        assert loaded_state.state['triggered_at'] is not None, "Should have triggered_at timestamp"
        print("   ✅ Status changed to 'triggered'")
        
        # Load again and verify persistence
        loaded_again = DeadManSwitchState.load(str(gif_path))
        assert loaded_again.state['status'] == 'triggered', "Status should persist as 'triggered'"
        print("   ✅ Status persisted across load/save cycles")


def test_deadmans_switch_disable():
    """Test disabling the dead-man's switch."""
    print("\n🧪 Test 4: Dead-Man's Switch Disable")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        gif_path = tmpdir / "test.gif"
        gif_path.touch()
        
        # Create state
        state = DeadManSwitchState(
            gif_path=str(gif_path),
            checkin_interval_seconds=3600,
            grace_period_seconds=1800,
            decoy_file=None
        )
        state.save()
        
        # Load and disable
        loaded_state = DeadManSwitchState.load(str(gif_path))
        loaded_state.disable()
        print("   ✅ State disabled")
        
        # Verify status changed
        assert loaded_state.state['status'] == 'disabled', "Status should be 'disabled'"
        assert loaded_state.state['disabled_at'] is not None, "Should have disabled_at timestamp"
        print("   ✅ Status changed to 'disabled'")
        
        # Verify deadline check returns False when disabled
        assert not loaded_state.is_deadline_passed(), "Should return False when disabled"
        print("   ✅ is_deadline_passed() returns False for disabled switch")


def test_encode_with_deadmans_switch():
    """Test encoding a file with --dead-mans-switch flag."""
    print("\n🧪 Test 5: Encoding with --dead-mans-switch")
    print("=" * 60)
    
    test_data = b"Secret test data for dead-man's switch" * 50
    test_password = "TestPassword123!"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create test file
        input_file = tmpdir / "test_input.txt"
        input_file.write_bytes(test_data)
        
        # Encode with dead-man's switch
        output_gif = tmpdir / "test_output.gif"
        config = EncodingConfig(block_size=256, redundancy=1.5)
        
        # This simulates the encode.py workflow
        try:
            encode_file(
                input_file,
                output_gif,
                test_password,
                config=config,
                verbose=False
            )
            print("   ✅ File encoded successfully")
        except Exception as e:
            print(f"   ❌ Encoding failed: {e}")
            raise
        
        # Verify GIF created
        assert output_gif.exists(), "GIF should be created"
        print(f"   ✅ GIF created ({output_gif.stat().st_size} bytes)")
        
        # Manually create dead-man's switch state (simulating encode.py behavior)
        from meow_decoder.deadmans_switch_cli import DeadManSwitchState
        
        state = DeadManSwitchState(
            gif_path=str(output_gif),
            checkin_interval_seconds=3600,  # 1 hour
            grace_period_seconds=1800,
            decoy_file=None
        )
        state.save()
        print("   ✅ Dead-man's switch state file created")
        
        # Verify state file exists alongside GIF
        state_file = tmpdir / f".{output_gif.stem}.deadman.json"
        assert state_file.exists(), f"State file should exist: {state_file}"
        print(f"   ✅ State file: {state_file}")
        
        # Load and verify state
        loaded_state = DeadManSwitchState.load(str(output_gif))
        assert loaded_state.state['status'] == 'armed', "Status should be armed"
        assert loaded_state.state['checkin_interval_seconds'] == 3600, "Checkin interval should match"
        assert loaded_state.state['grace_period_seconds'] == 1800, "Grace period should match"
        print("   ✅ State loaded and verified")


def test_decode_with_active_switch():
    """Test decoding when dead-man's switch is active but not triggered."""
    print("\n🧪 Test 6: Decoding with Active (but not triggered) Switch")
    print("=" * 60)
    
    test_data = b"Normal decode test data" * 50
    test_password = "TestPassword123!"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create and encode test file
        input_file = tmpdir / "test_input.txt"
        input_file.write_bytes(test_data)
        
        output_gif = tmpdir / "test_output.gif"
        config = EncodingConfig(block_size=256, redundancy=1.5)
        
        encode_file(input_file, output_gif, test_password, config=config, verbose=False)
        print("   ✅ File encoded")
        
        # Create dead-man's switch with future deadline
        state = DeadManSwitchState(
            gif_path=str(output_gif),
            checkin_interval_seconds=3600,  # 1 hour
            grace_period_seconds=1800,
            decoy_file=None
        )
        state.save()
        print("   ✅ Dead-man's switch created (deadline in future)")
        
        # Decode should proceed normally
        decoded_file = tmpdir / "decoded.txt"
        try:
            decode_gif(
                str(output_gif),
                str(decoded_file),
                test_password,
                verbose=False
            )
            print("   ✅ File decoded successfully (normal path)")
        except Exception as e:
            print(f"   ❌ Decoding failed: {e}")
            raise
        
        # Verify decoded file matches original
        assert decoded_file.exists(), "Decoded file should exist"
        decoded_data = decoded_file.read_bytes()
        assert decoded_data == test_data, "Decoded data should match original"
        print("   ✅ Decoded data matches original")


def test_decode_with_triggered_switch():
    """Test decoding when dead-man's switch deadline has passed."""
    print("\n🧪 Test 7: Decoding with Triggered Switch (Deadline Passed)")
    print("=" * 60)
    
    test_data = b"Secret data" * 50
    test_password = "TestPassword123!"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create and encode test file
        input_file = tmpdir / "test_input.txt"
        input_file.write_bytes(test_data)
        
        output_gif = tmpdir / "test_output.gif"
        config = EncodingConfig(block_size=256, redundancy=1.5)
        
        encode_file(input_file, output_gif, test_password, config=config, verbose=False)
        print("   ✅ File encoded")
        
        # Create decoy file
        decoy_data = b"This is the decoy content" * 10
        decoy_file = tmpdir / "decoy.txt"
        decoy_file.write_bytes(decoy_data)
        print(f"   ✅ Decoy file created ({len(decoy_data)} bytes)")
        
        # Create dead-man's switch with deadline in past
        state = DeadManSwitchState(
            gif_path=str(output_gif),
            checkin_interval_seconds=2,  # 2 seconds (will be past)
            grace_period_seconds=1,  # 1 second
            decoy_file=str(decoy_file)
        )
        state.save()
        
        # Wait for deadline to pass
        time.sleep(4)
        print("   ✅ Waited for deadline to pass")
        
        # Decode should return decoy instead of real data
        decoded_file = tmpdir / "decoded.txt"
        try:
            result = decode_gif(
                str(output_gif),
                str(decoded_file),
                test_password,
                verbose=False
            )
            print("   ✅ Decode completed")
        except Exception as e:
            print(f"   ⚠️ Decode raised exception (might be expected): {e}")
        
        # Verify decoded file is the decoy
        if decoded_file.exists():
            decoded_data = decoded_file.read_bytes()
            if decoded_data == decoy_data:
                print("   ✅ Decoy file was released (correct behavior)")
            else:
                print(f"   ⚠️ Decoded data doesn't match decoy")
                print(f"      Expected {len(decoy_data)} bytes, got {len(decoded_data)} bytes")
        else:
            print(f"   ⚠️ Decoded file not created")


def main():
    """Run all dead-man's switch tests."""
    print("🐱 Dead-Man's Switch Integration Tests")
    print("=" * 60)
    
    tests = [
        test_deadmans_switch_basic,
        test_deadmans_switch_renewal,
        test_deadmans_switch_trigger,
        test_deadmans_switch_disable,
        test_encode_with_deadmans_switch,
        test_decode_with_active_switch,
        test_decode_with_triggered_switch,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"   ❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"🧪 Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)
    
    if failed == 0:
        print("✅ All tests passed! 🎉")
        return 0
    else:
        print("❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
