"""Pytest wrapper that runs the standalone Node smoke tests in tests/.

The Node test files (test_cat_protocol.node.js, test_cat_signal.node.js)
exercise the web demo's cat-mode JS modules in pure Node — no browser,
no Playwright. They verify:

* cat-mode-protocol.js: CRC32, encode/decode round-trip (single + multi
  packet), out-of-order delivery, large messages (60 KB / 235 packets,
  used to crash on Math.max spread), seq=65535 sanity, session-lock
  recovery, truncation/CRC bit-flip detection, reset.
* quality-metrics.js, adaptive-threshold.js, hysteresis.js,
  preamble-calibration.js, nrz-decoder.js: confidence clamps, off-by-one
  in detectPreamble, R² stability, findValley adjacent-peak fix,
  hysteresis negative/zero threshold, NRZ empty/NaN guards, etc.

This wrapper just shells out to `node` so the tests run inside the
repo's normal pytest run (and therefore in CI).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def node_path():
    path = shutil.which("node")
    if path is None:
        pytest.skip("node not installed in this environment")
    return path


@pytest.mark.parametrize(
    "script",
    [
        "test_cat_protocol.node.js",
        "test_cat_signal.node.js",
    ],
)
def test_node_smoke(node_path, script):
    """Run a Node smoke-test script; fail if it exits non-zero."""
    script_path = TESTS_DIR / script
    assert script_path.exists(), f"missing {script_path}"

    result = subprocess.run(
        [node_path, str(script_path)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(TESTS_DIR.parent),
    )
    if result.returncode != 0:
        pytest.fail(
            f"{script} failed (exit {result.returncode}):\n"
            f"--- STDOUT ---\n{result.stdout}\n"
            f"--- STDERR ---\n{result.stderr}"
        )
