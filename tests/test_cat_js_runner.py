"""Pytest wrapper to run cat mode JavaScript tests via Node.js subprocess.

This allows the JS test suites to be executed through pytest when
the terminal tool is unavailable.
"""

import subprocess
import sys
import os
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS_DIR = os.path.join(ROOT, "scripts", "dev")


class TestCatBinaryJS:
    """Run test_cat_binary.js (self-contained binary framing tests)."""

    def test_cat_binary_roundtrip(self):
        """Execute test_cat_binary.js and verify all 6 tests pass."""
        result = subprocess.run(
            ["node", os.path.join(JS_DIR, "test_cat_binary.js")],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=ROOT,
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        assert result.returncode == 0, (
            f"test_cat_binary.js failed (exit {result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "All tests passed" in result.stdout or "0 failed" in result.stdout


class TestCat5SpeedsJS:
    """Run test_cat_5speeds.js (full encode→signal→decode pipeline at 5 speeds)."""

    # Previously xfail'd for preamble/sync overlap (NRZ would skip 8 bits and
    # decode byte[0] as 0xca instead of 0xfe). Verified passing 5/5 runs after
    # the cat-mode audit fixes (623bdd9, 06ad9dc) — xfail removed.
    def test_cat_5speeds_pipeline(self):
        """Execute test_cat_5speeds.js and verify all 5 speeds pass."""
        result = subprocess.run(
            ["node", os.path.join(JS_DIR, "test_cat_5speeds.js")],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=ROOT,
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        assert result.returncode == 0, (
            f"test_cat_5speeds.js failed (exit {result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "All 5 speeds passed" in result.stdout
