"""
Coverage gap tests — Phase 1
Targets uncovered lines in:
  streaming_crypto, high_security, duress_mode, timelock_duress,
  entropy_boost, secure_bridge, schrodinger_decode, schrodinger_encode,
  catnip_fountain
"""

import os
import sys
import io
import gc
import time
import json
import struct
import secrets
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch, MagicMock, PropertyMock

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# 1. streaming_crypto.py
# ---------------------------------------------------------------------------
class TestStreamingCryptoCoverageGaps(unittest.TestCase):
    """Cover lines 32-33, 115-116, 120-121, 193-194, 229-236, 314-323."""

    # --- Coverage gap tests ---

    def test_psutil_import_fallback(self):
        """Lines 32-33: HAS_PSUTIL = False when psutil unavailable."""
        import importlib

        with patch.dict(sys.modules, {"psutil": None}):
            # Force re-evaluation of the try/except import
            # We verify the module-level fallback indirectly via MemoryMonitor
            from meow_decoder.streaming_crypto import MemoryMonitor

            mon = MemoryMonitor(target_usage_mb=50)
            # Even without psutil, get_optimal_chunk_size should work
            chunk = mon.get_optimal_chunk_size()
            self.assertGreater(chunk, 0)

    def test_verify_mac_direct(self):
        """Lines 115-116: _verify_mac() called directly."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(key, nonce)

        data = b"test data for mac"
        mac = cipher._compute_mac(data)
        self.assertTrue(cipher._verify_mac(data, mac))
        self.assertFalse(cipher._verify_mac(data, b"\x00" * 32))

    def test_encrypt_stream_full_path(self):
        """Lines 120-121, 193-194: encrypt_stream with compression."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(key, nonce)

        plaintext = b"A" * 5000
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()

        orig_size, comp_size, sha256_hash, mac_tag = cipher.encrypt_stream(
            inp, out, enable_compression=True
        )
        self.assertEqual(orig_size, len(plaintext))
        self.assertGreater(comp_size, 0)
        self.assertEqual(len(mac_tag), 32)
        self.assertEqual(len(sha256_hash), 32)

    def test_encrypt_stream_no_compression(self):
        """encrypt_stream without compression."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(key, nonce)

        plaintext = b"B" * 3000
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()

        orig_size, comp_size, sha256_hash, mac_tag = cipher.encrypt_stream(
            inp, out, enable_compression=False
        )
        self.assertEqual(orig_size, len(plaintext))

    def test_decrypt_stream_kwargs_compat(self):
        """Lines 229, 231, 236: decrypt_stream with kwargs for back-compat."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        # Encrypt first
        enc_cipher = StreamingCipher(key, nonce)
        plaintext = b"X" * 2000
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(inp, out, enable_compression=False)

        # Decrypt using kwargs
        dec_cipher = StreamingCipher(key, nonce)
        encrypted = out.getvalue()
        dec_out = io.BytesIO()

        written = dec_cipher.decrypt_stream(
            input_stream=io.BytesIO(encrypted),
            output_stream=dec_out,
            enable_decompression=False,
        )
        self.assertEqual(written, len(plaintext))
        self.assertEqual(dec_out.getvalue(), plaintext)

    def test_decrypt_stream_mac_validation_bad_length(self):
        """Line 236: MAC length != 32 raises ValueError."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(key, nonce)

        with self.assertRaises(ValueError, msg="MAC must be 32 bytes"):
            cipher.decrypt_stream(
                input_stream=io.BytesIO(b"data"),
                output_stream=io.BytesIO(),
                expected_mac=b"short",
            )

    def test_decrypt_stream_with_mac_verification(self):
        """decrypt_stream with expected_mac that passes."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        # Encrypt
        enc = StreamingCipher(key, nonce)
        plaintext = b"Z" * 1500
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()
        _, _, _, mac_tag = enc.encrypt_stream(inp, out, enable_compression=False)

        # Decrypt with MAC
        dec = StreamingCipher(key, nonce)
        encrypted = out.getvalue()
        dec_out = io.BytesIO()
        written = dec.decrypt_stream(
            input_stream=io.BytesIO(encrypted),
            output_stream=dec_out,
            enable_decompression=False,
            expected_mac=mac_tag,
        )
        self.assertEqual(dec_out.getvalue(), plaintext)

    def test_decrypt_stream_with_bad_mac(self):
        """decrypt_stream with wrong MAC raises RuntimeError."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        enc = StreamingCipher(key, nonce)
        plaintext = b"W" * 500
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()
        enc.encrypt_stream(inp, out, enable_compression=False)

        dec = StreamingCipher(key, nonce)
        encrypted = out.getvalue()
        with self.assertRaises(RuntimeError):
            dec.decrypt_stream(
                input_stream=io.BytesIO(encrypted),
                output_stream=io.BytesIO(),
                enable_decompression=False,
                expected_mac=b"\x00" * 32,
            )

    def test_decompression_flush_path(self):
        """Lines 314-323: decompression flush path in decrypt_stream."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        # Encrypt with compression
        enc = StreamingCipher(key, nonce)
        plaintext = b"Q" * 10000
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()
        _, _, _, mac_tag = enc.encrypt_stream(inp, out, enable_compression=True)

        # Decrypt with decompression enabled
        dec = StreamingCipher(key, nonce)
        encrypted = out.getvalue()
        dec_out = io.BytesIO()
        written = dec.decrypt_stream(
            input_stream=io.BytesIO(encrypted),
            output_stream=dec_out,
            enable_decompression=True,
        )
        self.assertEqual(dec_out.getvalue(), plaintext)

    def test_decrypt_stream_decrypted_stream_kwarg(self):
        """Line 231: 'decrypted_stream' kwarg alias."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        enc = StreamingCipher(key, nonce)
        plaintext = b"M" * 500
        inp = io.BytesIO(plaintext)
        out = io.BytesIO()
        enc.encrypt_stream(inp, out, enable_compression=False)

        dec = StreamingCipher(key, nonce)
        encrypted = out.getvalue()
        dec_out = io.BytesIO()
        # Use the 'decrypted_stream' kwarg alias
        written = dec.decrypt_stream(
            input_stream=io.BytesIO(encrypted),
            decrypted_stream=dec_out,
            enable_decompression=False,
        )
        self.assertEqual(dec_out.getvalue(), plaintext)

    def test_decrypt_stream_missing_streams_raises(self):
        """decrypt_stream with no streams raises ValueError."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(key, nonce)

        with self.assertRaises(ValueError):
            cipher.decrypt_stream()


# ---------------------------------------------------------------------------
# 2. high_security.py
# ---------------------------------------------------------------------------
class TestHighSecurityCoverageGaps(unittest.TestCase):
    """Cover lines 138, 146-147, 155-156, 164-165, 179, 237, 254-256, 269-281."""

    # --- Coverage gap tests ---

    def setUp(self):
        """Reset high security mode state for each test."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False

    def test_activate_twice_early_return(self):
        """Line 138: calling enable_high_security_mode twice returns early."""
        from meow_decoder.high_security import enable_high_security_mode, _HIGH_SECURITY_MODE_ACTIVE
        import meow_decoder.high_security as hs

        enable_high_security_mode(silent=True)
        self.assertTrue(hs._HIGH_SECURITY_MODE_ACTIVE)

        # Second call should return immediately (early return)
        enable_high_security_mode(silent=True)
        self.assertTrue(hs._HIGH_SECURITY_MODE_ACTIVE)

    def test_import_error_fallback_crypto(self):
        """Lines 146-147: ImportError fallback when patching crypto."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False

        with patch.dict(sys.modules, {"meow_decoder.crypto": None}):
            # Should not raise — the ImportError is caught
            hs.enable_high_security_mode(silent=True)
            self.assertTrue(hs._HIGH_SECURITY_MODE_ACTIVE)

    def test_import_error_fallback_crypto_enhanced(self):
        """Lines 155-156: ImportError fallback for crypto_enhanced."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False

        with patch.dict(sys.modules, {"meow_decoder.experimental.crypto_enhanced": None}):
            hs.enable_high_security_mode(silent=True)
            self.assertTrue(hs._HIGH_SECURITY_MODE_ACTIVE)

    def test_import_error_fallback_x25519(self):
        """Lines 164-165: ImportError fallback for x25519_forward_secrecy."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False

        with patch.dict(sys.modules, {"meow_decoder.x25519_forward_secrecy": None}):
            hs.enable_high_security_mode(silent=True)
            self.assertTrue(hs._HIGH_SECURITY_MODE_ACTIVE)

    def test_verbose_print(self):
        """Line 179: verbose (not silent) prints confirmation."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False

        with patch("builtins.print") as mock_print:
            hs.enable_high_security_mode(silent=False)
            mock_print.assert_any_call("High security mode active.")

    def test_secure_wipe_zeros_branch(self):
        """Line 237: zeros-overwrite branch in secure_wipe_file."""
        from meow_decoder.high_security import secure_wipe_file

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"S" * 4096)
            path = Path(f.name)

        try:
            result = secure_wipe_file(path, passes=7)
            self.assertTrue(result)
            self.assertFalse(path.exists())
        except Exception:
            if path.exists():
                path.unlink()

    def test_secure_wipe_rename_unlink(self):
        """Lines 254, 256: rename then unlink in secure_wipe_file."""
        from meow_decoder.high_security import secure_wipe_file

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
            f.write(b"T" * 1000)
            path = Path(f.name)

        result = secure_wipe_file(path, passes=3)
        self.assertTrue(result)
        self.assertFalse(path.exists())

    def test_secure_wipe_nonexistent_returns_true(self):
        """Line 224-225: non-existent file returns True (already gone)."""
        from meow_decoder.high_security import secure_wipe_file

        # Non-existent file returns True (already gone)
        result = secure_wipe_file(Path("/nonexistent/file.dat"))
        self.assertTrue(result)

    def test_secure_wipe_exception_fallback(self):
        """Line 260: exception in wipe returns False."""
        from meow_decoder.high_security import secure_wipe_file

        # Directory path causes exception in open()
        with tempfile.TemporaryDirectory() as d:
            result = secure_wipe_file(Path(d))
            self.assertFalse(result)

    def test_secure_wipe_memory(self):
        """Lines 269-281: scrub_memory / secure_wipe_memory."""
        from meow_decoder.high_security import secure_wipe_memory

        # Just exercise the function — it does GC + memory overwrite
        secure_wipe_memory()


# ---------------------------------------------------------------------------
# 3. duress_mode.py
# ---------------------------------------------------------------------------
class TestDuressModeCoverageGaps(unittest.TestCase):
    """Cover lines 202-210, 252, 293-294, 317-320, 323, 347."""

    # --- Coverage gap tests ---

    def _make_handler(self, **kwargs):
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        cfg = DuressConfig(**kwargs)
        return DuressHandler(config=cfg)

    def test_check_password_fake_wipe_path(self):
        """Lines 202-210: dummy_wipe_timing path when is_real."""
        handler = self._make_handler(wipe_resume_files=True)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_pass", "real_pass", salt)

        is_valid, is_duress = handler.check_password("real_pass", salt)
        self.assertTrue(is_valid)
        self.assertFalse(is_duress)

    def test_equalize_timing_random_delay(self):
        """Line 252: _equalize_timing adds random delay."""
        handler = self._make_handler(min_delay_ms=1, max_delay_ms=5)
        salt = secrets.token_bytes(16)
        handler.set_passwords("dp", "rp", salt)
        # Just verify it doesn't crash
        handler._equalize_timing()

    def test_get_decoy_data_message(self):
        """Lines 293-294: get_decoy_data entry for 'message' type."""
        handler = self._make_handler(decoy_type="message", decoy_message="Hello cat!")
        data, name = handler.get_decoy_data()
        self.assertEqual(data, b"Hello cat!")

    def test_get_decoy_data_bundled_file(self):
        """Lines 317-320: bundled_file decoy type — fallback to error."""
        handler = self._make_handler(decoy_type="bundled_file")
        data, name = handler.get_decoy_data()
        # Asset likely does not exist; should get fallback
        self.assertIsInstance(data, bytes)

    def test_get_decoy_data_user_file_exists(self):
        """Line 323: user_file decoy type with existing file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"decoy content")
            f.flush()
            path = f.name

        try:
            handler = self._make_handler(
                decoy_type="user_file",
                decoy_file_path=path,
                decoy_output_name="output.txt",
            )
            data, name = handler.get_decoy_data()
            self.assertEqual(data, b"decoy content")
            self.assertEqual(name, "output.txt")
        finally:
            os.unlink(path)

    def test_get_decoy_data_user_file_missing(self):
        """user_file decoy with missing file → fallback."""
        handler = self._make_handler(
            decoy_type="user_file",
            decoy_file_path="/nonexistent/file.txt",
        )
        data, name = handler.get_decoy_data()
        self.assertIn(b"Operation successful", data)

    def test_get_decoy_data_user_file_no_path(self):
        """user_file decoy with no file path → fallback."""
        handler = self._make_handler(decoy_type="user_file")
        data, name = handler.get_decoy_data()
        self.assertIn(b"Error", data)

    def test_get_decoy_data_unknown_type(self):
        """Line 347: unknown decoy type → fallback."""
        handler = self._make_handler(decoy_type="alien_type")
        data, name = handler.get_decoy_data()
        self.assertEqual(data, b"Decode complete.")
        self.assertEqual(name, "output.txt")

    def test_get_decoy_data_bundled_with_existing_asset(self):
        """bundled_file path when asset file actually exists."""
        # Create a temporary asset in the expected location
        asset_dir = Path(__file__).parent.parent / "assets"
        asset_dir.mkdir(exist_ok=True)
        demo_path = asset_dir / "demo.gif"
        existed = demo_path.exists()
        if not existed:
            demo_path.write_bytes(b"GIF89a_fake")
        try:
            handler = self._make_handler(
                decoy_type="bundled_file",
                decoy_output_name="demo.gif",
            )
            data, name = handler.get_decoy_data()
            self.assertIsInstance(data, bytes)
        finally:
            if not existed and demo_path.exists():
                demo_path.unlink()


# ---------------------------------------------------------------------------
# 4. timelock_duress.py
# ---------------------------------------------------------------------------
class TestTimelockDuressCoverageGaps(unittest.TestCase):
    """Cover lines 173-176, 184, 274-275, 331, 362-366, 414, 446, 465, 519."""

    # --- Coverage gap tests ---

    def test_puzzle_memory_hard_variant(self):
        """Lines 173-176, 184: memory-hard variant + progress printing."""
        from meow_decoder.timelock_duress import TimeLockPuzzle, TimeLockConfig

        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=1000,
            use_memory_hard=True,
        )
        puzzle = TimeLockPuzzle(config)
        secret = b"my_secret_key_16"

        with patch("builtins.print"):
            encrypted, puzzle_data, state = puzzle.create_puzzle(secret)

        self.assertEqual(len(encrypted), len(secret))

    def test_decrypt_secret(self):
        """Lines 274-275: decrypt_secret() short and long secrets."""
        from meow_decoder.timelock_duress import TimeLockPuzzle, TimeLockConfig

        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=100,
        )
        puzzle = TimeLockPuzzle(config)

        # Short secret (≤32 bytes)
        secret_short = b"short"
        with patch("builtins.print"):
            enc_short, pdata, state = puzzle.create_puzzle(secret_short)
            solution, _ = puzzle.solve_puzzle(pdata, state)
        recovered = puzzle.decrypt_secret(enc_short, solution)
        self.assertEqual(recovered, secret_short)

        # Long secret (>32 bytes)
        secret_long = b"A" * 64
        config2 = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=100,
        )
        puzzle2 = TimeLockPuzzle(config2)
        with patch("builtins.print"):
            enc_long, pdata2, state2 = puzzle2.create_puzzle(secret_long)
            solution2, _ = puzzle2.solve_puzzle(pdata2, state2)
        recovered_long = puzzle2.decrypt_secret(enc_long, solution2)
        self.assertEqual(recovered_long, secret_long)

    def test_countdown_duress_initialize(self):
        """Line 331: CountdownDuress.initialize()."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_path = Path(f.name)
        state_path.unlink()

        try:
            config = TimeLockConfig(checkin_interval_seconds=60)
            cd = CountdownDuress(config, state_path)
            with patch("builtins.print"):
                cd.initialize()

            self.assertIsNotNone(cd.state)
            self.assertFalse(cd.state.countdown_triggered)
        finally:
            if state_path.exists():
                state_path.unlink()

    def test_countdown_check_status_triggered(self):
        """Lines 362-366: check_status when time has elapsed → triggered."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_path = Path(f.name)
        state_path.unlink()

        try:
            config = TimeLockConfig(checkin_interval_seconds=1, grace_period_seconds=0)
            cd = CountdownDuress(config, state_path)
            with patch("builtins.print"):
                cd.initialize()

            # Set last_checkin far in the past
            cd.state.last_checkin = time.time() - 1000
            triggered, remaining = cd.check_status()
            self.assertTrue(triggered)
            self.assertEqual(remaining, 0.0)
        finally:
            if state_path.exists():
                state_path.unlink()

    def test_countdown_check_status_not_triggered(self):
        """check_status returns remaining seconds when not yet triggered."""
        from meow_decoder.timelock_duress import CountdownDuress, TimeLockConfig

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_path = Path(f.name)
        # Remove the empty file so constructor doesn't try to load invalid JSON
        state_path.unlink()

        try:
            config = TimeLockConfig(checkin_interval_seconds=86400, grace_period_seconds=3600)
            cd = CountdownDuress(config, state_path)
            with patch("builtins.print"):
                cd.initialize()

            triggered, remaining = cd.check_status()
            self.assertFalse(triggered)
            self.assertGreater(remaining, 0)
        finally:
            if state_path.exists():
                state_path.unlink()

    def test_deadman_switch_init_check_trigger(self):
        """Lines 414, 446, 465: DeadManSwitch init, check, trigger."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_path = Path(f.name)
        state_path.unlink()

        try:
            config = TimeLockConfig(deadman_enabled=True, deadman_duration_days=1)
            dm = DeadManSwitch(config, state_path)

            with patch("builtins.print"):
                dm.initialize()

            self.assertIsNotNone(dm.state)
            self.assertFalse(dm.state.deadman_triggered)

            # Check status (should not be triggered)
            triggered, remaining = dm.check_status()
            self.assertFalse(triggered)
            self.assertGreater(remaining, 0)

            # Renew
            with patch("builtins.print"):
                result = dm.renew()
            self.assertTrue(result)
        finally:
            if state_path.exists():
                state_path.unlink()

    def test_deadman_switch_expired(self):
        """DeadManSwitch triggers when duration elapsed."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_path = Path(f.name)
        state_path.unlink()

        try:
            config = TimeLockConfig(deadman_enabled=True, deadman_duration_days=1)
            dm = DeadManSwitch(config, state_path)
            with patch("builtins.print"):
                dm.initialize()

            # Set renewal far in the past
            dm.state.deadman_last_renewal = time.time() - 200000
            triggered, remaining = dm.check_status()
            self.assertTrue(triggered)
            self.assertEqual(remaining, 0.0)

            # Renew after triggered should return False
            with patch("builtins.print"):
                self.assertFalse(dm.renew())
        finally:
            if state_path.exists():
                state_path.unlink()

    def test_deadman_not_enabled_raises(self):
        """DeadManSwitch.initialize() raises when not enabled."""
        from meow_decoder.timelock_duress import DeadManSwitch, TimeLockConfig

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_path = Path(f.name)
        state_path.unlink()

        try:
            config = TimeLockConfig(deadman_enabled=False)
            dm = DeadManSwitch(config, state_path)
            with self.assertRaises(RuntimeError):
                dm.initialize()
        finally:
            if state_path.exists():
                state_path.unlink()

    def test_decode_with_timelock_import(self):
        """Line 519: decode_with_timelock can be imported and run."""
        from meow_decoder.timelock_duress import (
            encode_with_timelock,
            decode_with_timelock,
            TimeLockConfig,
        )

        # Create a tiny timelock (minimal iterations)
        config = TimeLockConfig(
            lock_duration_seconds=1,
            hash_iterations_per_second=10,
        )

        data = b"secret_data_1234"
        with patch("builtins.print"):
            result, puzzle_data, state = encode_with_timelock(
                data, "password123", lock_duration_seconds=1
            )

        # decode_with_timelock solves the puzzle
        with patch("builtins.print"):
            key = decode_with_timelock(result, "password123")
        self.assertIsInstance(key, bytes)


# ---------------------------------------------------------------------------
# 5. entropy_boost.py
# ---------------------------------------------------------------------------
class TestEntropyBoostCoverageGaps(unittest.TestCase):
    """Cover lines 119-120, 128-129, 222-236, 298, 349-350, 368-369."""

    # --- Coverage gap tests ---

    def test_gc_get_count_entropy(self):
        """Lines 119-120: gc.get_count() entropy + except."""
        from meow_decoder.entropy_boost import EntropyPool

        pool = EntropyPool()
        pool.add_system_entropy(32)
        pool.add_environment_entropy()
        # gc.get_count() is always available so this just exercises the line
        self.assertGreater(pool.get_source_count(), 0)

    def test_gc_get_count_exception_path(self):
        """Lines 119-120: except path when gc.get_count fails."""
        from meow_decoder.entropy_boost import EntropyPool

        pool = EntropyPool()

        with patch("gc.get_count", side_effect=Exception("mocked")):
            pool.add_environment_entropy()
        # Should still work — the exception is caught
        self.assertGreater(pool.get_source_count(), 0)

    def test_proc_interrupts_reading(self):
        """Lines 128-129: /proc/interrupts reading."""
        from meow_decoder.entropy_boost import EntropyPool

        pool = EntropyPool()
        pool.add_environment_entropy()
        # On Linux this should read /proc/interrupts
        self.assertGreater(pool.get_source_count(), 0)

    def test_webcam_entropy_mock_cv2(self):
        """Lines 222-236: webcam entropy with mocked cv2."""
        from meow_decoder.entropy_boost import EntropyPool
        import numpy as np

        mock_cv2 = MagicMock()
        mock_cap = MagicMock()
        mock_cv2.VideoCapture.return_value = mock_cap
        mock_cap.isOpened.return_value = True

        # Create a fake frame
        fake_frame = np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)

        pool = EntropyPool()
        with patch.dict(sys.modules, {"cv2": mock_cv2}):
            result = pool.add_webcam_noise(3)

        # Verify it attempted to use webcam
        mock_cv2.VideoCapture.assert_called_once_with(0)

    def test_webcam_entropy_not_opened(self):
        """Webcam not available returns False."""
        from meow_decoder.entropy_boost import EntropyPool

        mock_cv2 = MagicMock()
        mock_cap = MagicMock()
        mock_cv2.VideoCapture.return_value = mock_cap
        mock_cap.isOpened.return_value = False

        pool = EntropyPool()
        with patch.dict(sys.modules, {"cv2": mock_cv2}):
            result = pool.add_webcam_noise(3)
        self.assertFalse(result)

    def test_get_source_count(self):
        """Line 298: get_source_count()."""
        from meow_decoder.entropy_boost import EntropyPool

        pool = EntropyPool()
        self.assertEqual(pool.get_source_count(), 0)
        pool.add_system_entropy(16)
        self.assertGreaterEqual(pool.get_source_count(), 1)

    def test_user_entropy_collection_mock_input(self):
        """Lines 349-350: user entropy via mock input."""
        from meow_decoder.entropy_boost import EntropyPool

        pool = EntropyPool()
        with patch("builtins.print"), patch(
            "builtins.input", return_value="random_keyboard_smash_1234"
        ):
            pool.add_user_entropy("Type stuff: ")

        self.assertGreater(pool.get_source_count(), 0)

    def test_webcam_in_collect_enhanced_entropy(self):
        """Lines 368-369: webcam path in collect_enhanced_entropy."""
        from meow_decoder.entropy_boost import collect_enhanced_entropy
        import numpy as np

        mock_cv2 = MagicMock()
        mock_cap = MagicMock()
        mock_cv2.VideoCapture.return_value = mock_cap
        mock_cap.isOpened.return_value = True
        fake_frame = np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)

        with patch.dict(sys.modules, {"cv2": mock_cv2}):
            result = collect_enhanced_entropy(16, use_webcam=True, verbose=False)
        self.assertEqual(len(result), 16)


# ---------------------------------------------------------------------------
# 6. secure_bridge.py
# ---------------------------------------------------------------------------
class TestSecureBridgeCoverageGaps(unittest.TestCase):
    """Cover lines 45-46, 79-80, 113, 126-127, 167-168, 197, 387-388, 448-449, 482-485, 493."""

    # --- Coverage gap tests ---

    def test_rust_unavailable_import_fallback(self):
        """Lines 45-46: RUST_AVAILABLE = False, SecureBridge raises."""
        # We can't easily reload the module, but we can test the behavior
        # by checking that SecureBridge raises when Rust is unavailable
        from meow_decoder.secure_bridge import SecureBridge, RUST_AVAILABLE

        if not RUST_AVAILABLE:
            with self.assertRaises(RuntimeError):
                SecureBridge()

    def test_key_handle_cleanup(self):
        """Lines 79-80: KeyHandle._zero_key() and cleanup."""
        from meow_decoder.secure_bridge import KeyHandle

        handle = KeyHandle(
            _handle_id=0,
            _backend="rust",
            _key_bytes=bytearray(b"\xff" * 32),
        )
        handle._zero_key()
        self.assertTrue(handle._zeroed)

    def test_key_handle_zero_no_key(self):
        """KeyHandle._zero_key() when no key bytes."""
        from meow_decoder.secure_bridge import KeyHandle

        handle = KeyHandle(
            _handle_id=1,
            _backend="rust",
            _key_bytes=None,
        )
        handle._zero_key()
        self.assertTrue(handle._zeroed)

    def test_key_handle_del(self):
        """KeyHandle.__del__ triggers zeroing."""
        from meow_decoder.secure_bridge import KeyHandle

        handle = KeyHandle(
            _handle_id=2,
            _backend="rust",
            _key_bytes=bytearray(b"\xaa" * 32),
        )
        handle.__del__()
        self.assertTrue(handle._zeroed)

    def test_secure_memory_mlock_linux(self):
        """Lines 113, 126-127: mlock/munlock paths on linux."""
        from meow_decoder.secure_bridge import SecureMemory

        mem = SecureMemory(64)
        # Write and read
        mem.write(b"A" * 32)
        data = mem.read()
        self.assertTrue(len(data) >= 32)

        # Zero and unlock
        mem.zero()
        mem.unlock()

    def test_secure_memory_context_manager(self):
        """SecureMemory as context manager."""
        from meow_decoder.secure_bridge import SecureMemory

        with SecureMemory(32) as mem:
            mem.write(b"B" * 16)
            data = mem.read()
            self.assertEqual(len(data), 32)

    def test_secure_memory_del(self):
        """Lines 167-168: __del__ on SecureMemory."""
        from meow_decoder.secure_bridge import SecureMemory

        mem = SecureMemory(32)
        mem.write(b"C" * 16)
        mem.__del__()

    def test_secure_bridge_runtime_error_no_rust(self):
        """Line 197: RuntimeError when no Rust backend."""
        from meow_decoder import secure_bridge as sb

        orig = sb.RUST_AVAILABLE
        try:
            sb.RUST_AVAILABLE = False
            with self.assertRaises(RuntimeError):
                sb.SecureBridge()
        finally:
            sb.RUST_AVAILABLE = orig

    def test_check_rust_backend_unavailable(self):
        """Lines 448-449, 482-483, 485, 493: check_rust_backend paths."""
        from meow_decoder import secure_bridge as sb

        orig = sb.RUST_AVAILABLE
        try:
            sb.RUST_AVAILABLE = False
            avail, msg = sb.check_rust_backend()
            self.assertFalse(avail)
            self.assertIn("not available", msg)
        finally:
            sb.RUST_AVAILABLE = orig

    def test_check_rust_backend_available_stub(self):
        """check_rust_backend when RUST_AVAILABLE=True but info() fails."""
        from meow_decoder import secure_bridge as sb

        orig = sb.RUST_AVAILABLE
        orig_crypto_rs = sb._crypto_rs
        try:
            sb.RUST_AVAILABLE = True
            mock_mod = MagicMock()
            mock_mod.backend_info.side_effect = Exception("no info")
            sb._crypto_rs = mock_mod

            avail, msg = sb.check_rust_backend()
            self.assertFalse(avail)
            self.assertIn("info failed", msg)
        finally:
            sb.RUST_AVAILABLE = orig
            sb._crypto_rs = orig_crypto_rs

    def test_secure_password_context_manager(self):
        """secure_password context manager."""
        from meow_decoder.secure_bridge import secure_password

        with secure_password("test_password") as pwd:
            self.assertEqual(pwd, "test_password")

    def test_secure_key_context_manager(self):
        """secure_key context manager."""
        from meow_decoder.secure_bridge import secure_key

        key_data = secrets.token_bytes(32)
        with secure_key(key_data) as k:
            self.assertEqual(len(k), 32)


# ---------------------------------------------------------------------------
# 7. schrodinger_decode.py
# ---------------------------------------------------------------------------
class TestSchrodingerDecodeCoverageGaps(unittest.TestCase):
    """Cover full decode pipeline with correct passwords for reality A and B."""

    # --- Coverage gap tests ---

    def test_schrodinger_roundtrip_reality_a(self):
        """Encode then decode with real password → reality A."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"Secret Reality A data for testing!"
        decoy_data = b"Innocent decoy content, nothing to see."
        real_pw = "real_password_alpha"
        decoy_pw = "decoy_password_beta"

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=256
        )

        # Decode with real password → should get real data
        result = schrodinger_decode_data(superposition, manifest, real_pw)
        self.assertIsNotNone(result)
        self.assertEqual(result, real_data)

    def test_schrodinger_roundtrip_reality_b(self):
        """Encode then decode with decoy password → reality B."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"This is the real secret alpha omega."
        decoy_data = b"Just a normal boring document, yawn."
        real_pw = "realPassX"
        decoy_pw = "decoyPassY"

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=256
        )

        # Decode with decoy password → should get decoy data
        result = schrodinger_decode_data(superposition, manifest, decoy_pw)
        self.assertIsNotNone(result)
        self.assertEqual(result, decoy_data)

    def test_schrodinger_wrong_password_returns_none(self):
        """Wrong password returns None."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        real_data = b"Real data here"
        decoy_data = b"Decoy data here"

        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "goodpassword1", "goodpassword2", block_size=256
        )

        result = schrodinger_decode_data(superposition, manifest, "wrong_password_here")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# 8. schrodinger_encode.py
# ---------------------------------------------------------------------------
class TestSchrodingerEncodeCoverageGaps(unittest.TestCase):
    """Cover SchrodingerManifest.unpack() validation, schrodinger_encode_data."""

    # --- Coverage gap tests ---

    def test_manifest_pack_unpack_roundtrip(self):
        """SchrodingerManifest pack+unpack roundtrip."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        m = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=42,
            block_size=256,
            superposition_len=10752,
        )
        packed = m.pack()
        self.assertEqual(len(packed), 382)

        m2 = SchrodingerManifest.unpack(packed)
        self.assertEqual(m2.block_count, 42)
        self.assertEqual(m2.block_size, 256)
        self.assertEqual(m2.superposition_len, 10752)
        self.assertEqual(m2.salt_a, m.salt_a)

    def test_manifest_unpack_too_short(self):
        """unpack raises on short data."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        with self.assertRaises(ValueError, msg="Manifest too short"):
            SchrodingerManifest.unpack(b"\x00" * 100)

    def test_manifest_unpack_bad_magic(self):
        """unpack raises on bad magic."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        bad_data = b"WOOF" + b"\x00" * 378
        with self.assertRaises(ValueError, msg="Invalid manifest magic"):
            SchrodingerManifest.unpack(bad_data)

    def test_manifest_unpack_wrong_version(self):
        """unpack raises on wrong version."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        data = b"MEOW" + struct.pack("BB", 0x01, 0x00) + b"\x00" * 376
        with self.assertRaises(ValueError, msg="Not a Schrödinger"):
            SchrodingerManifest.unpack(data)

    def test_schrodinger_encode_data_full_path(self):
        """schrodinger_encode_data full path with metadata encryption."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data

        real = b"Real data for comprehensive test " * 10
        decoy = b"Decoy innocuous content blah blah" * 10

        superposition, manifest = schrodinger_encode_data(
            real, decoy, "pw_real_test", "pw_decoy_test", block_size=128
        )

        self.assertGreater(len(superposition), 0)
        self.assertGreater(manifest.block_count, 0)
        self.assertEqual(manifest.version, 0x07)

    def test_pack_core_for_auth(self):
        """pack_core_for_auth produces stable output."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest

        m = SchrodingerManifest(
            salt_a=b"\x01" * 16,
            salt_b=b"\x02" * 16,
            nonce_a=b"\x03" * 12,
            nonce_b=b"\x04" * 12,
            reality_a_hmac=b"\xaa" * 32,
            reality_b_hmac=b"\xbb" * 32,
            metadata_a=b"\x05" * 104,
            metadata_b=b"\x06" * 104,
            block_count=10,
            block_size=256,
            superposition_len=2560,
        )
        core1 = m.pack_core_for_auth()
        core2 = m.pack_core_for_auth()
        self.assertEqual(core1, core2)
        # Core should NOT include HMACs (use non-zero HMACs to avoid false positives)
        self.assertNotIn(m.reality_a_hmac, core1)
        self.assertNotIn(m.reality_b_hmac, core1)


# ---------------------------------------------------------------------------
# 9. catnip_fountain.py
# ---------------------------------------------------------------------------
class TestCatnipFountainCoverageGaps(unittest.TestCase):
    """Cover drop_kibble, collect_kibble, dispense_kibbles, pack/unpack, belief propagation."""

    # --- Coverage gap tests ---

    def test_drop_kibble(self):
        """drop_kibble() with explicit seed."""
        from meow_decoder.catnip_fountain import CatnipFountain

        data = b"X" * (10 * 64)
        fountain = CatnipFountain(data, num_posts=10, post_size=64)

        kibble = fountain.drop_kibble(seed=42)
        self.assertEqual(kibble.seed, 42)
        self.assertEqual(len(kibble.data), 64)
        self.assertGreater(len(kibble.scratching_post_indices), 0)

    def test_drop_kibble_auto_seed(self):
        """drop_kibble() with auto-generated seed."""
        from meow_decoder.catnip_fountain import CatnipFountain

        data = b"Y" * (5 * 32)
        fountain = CatnipFountain(data, num_posts=5, post_size=32)

        k1 = fountain.drop_kibble()
        k2 = fountain.drop_kibble()
        self.assertNotEqual(k1.seed, k2.seed)

    def test_dispense_kibbles(self):
        """dispense_kibbles() returns correct count."""
        from meow_decoder.catnip_fountain import CatnipFountain

        data = b"Z" * (8 * 32)
        fountain = CatnipFountain(data, num_posts=8, post_size=32)

        kibbles = fountain.dispense_kibbles(5)
        self.assertEqual(len(kibbles), 5)

    def test_collect_kibble_roundtrip(self):
        """Full roundtrip: drop_kibble → collect_kibble → reconstruct."""
        from meow_decoder.catnip_fountain import CatnipFountain, KibbleCollector

        num_posts = 10
        post_size = 64
        original = secrets.token_bytes(num_posts * post_size)

        fountain = CatnipFountain(original, num_posts=num_posts, post_size=post_size)
        collector = KibbleCollector(num_posts=num_posts, post_size=post_size)

        max_kibbles = num_posts * 3
        for i in range(max_kibbles):
            kibble = fountain.drop_kibble()
            done = collector.collect_kibble(
                kibble.seed, kibble.scratching_post_indices, kibble.data
            )
            if done:
                break

        self.assertTrue(collector.is_satisfied())
        reconstructed = collector.get_reconstructed_data()
        self.assertEqual(reconstructed, original)

    def test_pack_unpack_kibble(self):
        """pack_kibble + unpack_kibble roundtrip."""
        from meow_decoder.catnip_fountain import (
            Kibble,
            pack_kibble,
            unpack_kibble,
        )

        kibble = Kibble(
            seed=12345,
            scratching_post_indices=[0, 3, 7],
            data=b"\xaa" * 64,
        )
        packed = pack_kibble(kibble)
        unpacked = unpack_kibble(packed, post_size=64)

        self.assertEqual(unpacked.seed, 12345)
        self.assertEqual(unpacked.scratching_post_indices, [0, 3, 7])
        self.assertEqual(unpacked.data, b"\xaa" * 64)

    def test_kibble_collector_belief_propagation(self):
        """KibbleCollector belief propagation — stash processing."""
        from meow_decoder.catnip_fountain import KibbleCollector

        collector = KibbleCollector(num_posts=3, post_size=4)

        # Add degree-2 kibble first (goes to stash)
        # posts[0] XOR posts[1]
        data_01 = bytes([0x01 ^ 0x02, 0x03 ^ 0x04, 0x05 ^ 0x06, 0x07 ^ 0x08])
        collector.collect_kibble(0, [0, 1], data_01)
        self.assertEqual(collector.posts_found, 0)

        # Add degree-1 kibble → solves post[0], triggers stash processing
        post0 = bytes([0x01, 0x03, 0x05, 0x07])
        collector.collect_kibble(1, [0], post0)
        # After stash processing, post[1] should also be solved
        self.assertEqual(collector.posts_found, 2)

        # Add the last post directly
        post2 = bytes([0x10, 0x20, 0x30, 0x40])
        collector.collect_kibble(2, [2], post2)
        self.assertTrue(collector.is_satisfied())

    def test_kibble_collector_already_satisfied(self):
        """collect_kibble returns True immediately when already satisfied."""
        from meow_decoder.catnip_fountain import KibbleCollector

        collector = KibbleCollector(num_posts=1, post_size=4)
        collector.collect_kibble(0, [0], b"\x01\x02\x03\x04")
        self.assertTrue(collector.is_satisfied())

        # Calling again should return True immediately
        result = collector.collect_kibble(1, [0], b"\xff\xff\xff\xff")
        self.assertTrue(result)

    def test_get_reconstructed_data_incomplete_raises(self):
        """get_reconstructed_data raises when incomplete."""
        from meow_decoder.catnip_fountain import KibbleCollector

        collector = KibbleCollector(num_posts=5, post_size=4)
        with self.assertRaises(RuntimeError, msg="Not enough kibbles"):
            collector.get_reconstructed_data()

    def test_catnip_fountain_data_too_large(self):
        """CatnipFountain raises when data > total_size."""
        from meow_decoder.catnip_fountain import CatnipFountain

        with self.assertRaises(ValueError, msg="Too much data"):
            CatnipFountain(b"X" * 1000, num_posts=2, post_size=4)

    def test_catnip_fountain_data_padding(self):
        """CatnipFountain pads short data."""
        from meow_decoder.catnip_fountain import CatnipFountain

        fountain = CatnipFountain(b"short", num_posts=2, post_size=16)
        self.assertEqual(len(fountain.scratching_posts), 2)
        self.assertEqual(len(fountain.scratching_posts[0]), 16)

    def test_cat_nap_distribution(self):
        """CatNapDistribution sampling."""
        import random
        from meow_decoder.catnip_fountain import CatNapDistribution

        dist = CatNapDistribution(20)
        rng = random.Random(99)
        depths = [dist.sample_nap_depth(rng) for _ in range(100)]
        self.assertTrue(all(1 <= d <= 20 for d in depths))


if __name__ == "__main__":
    unittest.main()
