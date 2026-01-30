#!/usr/bin/env python3
"""Run security invariant tests."""
import os
import subprocess
import sys

os.environ["MEOW_TEST_MODE"] = "1"

print("=" * 70)
print("TEST 1: tests/test_invariants.py")
print("=" * 70)
sys.stdout.flush()

result1 = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_invariants.py", "-v", "--no-header"],
    cwd="/workspaces/meow-decoder"
)

print("\n" + "=" * 70)
print("TEST 2: tests/test_schrodinger_security.py")
print("=" * 70)
sys.stdout.flush()

result2 = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_schrodinger_security.py", "-v", "--no-header"],
    cwd="/workspaces/meow-decoder"
)

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"test_invariants.py exit code: {result1.returncode}")
print(f"test_schrodinger_security.py exit code: {result2.returncode}")
