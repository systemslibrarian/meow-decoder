#!/usr/bin/env python3
"""Run tests and report results quickly."""

import subprocess, os, sys

env = os.environ.copy()
env["MEOW_TEST_MODE"] = "1"

files = [
    "tests/test_coverage_boost_remaining.py",
]

for f in files:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", f, "-q", "--tb=line", "--no-header"],
        capture_output=True,
        text=True,
        cwd="/workspaces/meow-decoder",
        env=env,
        timeout=300,
    )
    # Print just summary lines
    for line in r.stdout.strip().split("\n"):
        if line.strip() and (
            "FAILED" in line or "passed" in line or "error" in line or "ERROR" in line
        ):
            print(line)
    if r.returncode != 0:
        print(f"\n--- FULL OUTPUT for {f} ---")
        print(r.stdout[-1500:])
