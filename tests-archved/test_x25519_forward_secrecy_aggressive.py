#!/usr/bin/env python3
"""
⚠️ DEPRECATION STUB - Tests moved to test_x25519_forward_secrecy.py

This file is a stub to prevent import errors during migration.
All tests have been consolidated into the canonical test file.

Migration: test_x25519_forward_secrecy_aggressive.py → test_x25519_forward_secrecy.py
Status: ✅ MIGRATED (2026-01-30)
Coverage: x25519_forward_secrecy.py at 98%
"""

import pytest
import warnings


def test_stub_redirect_notice():
    """Stub test that redirects to canonical file."""
    warnings.warn(
        "⚠️ Tests moved to test_x25519_forward_secrecy.py - run that file instead",
        DeprecationWarning,
        stacklevel=2
    )
    assert True, "Stub test - real tests are in test_x25519_forward_secrecy.py"


if __name__ == "__main__":
    print("⚠️ DEPRECATED: Use pytest tests/test_x25519_forward_secrecy.py instead")
    pytest.main(["tests/test_x25519_forward_secrecy.py", "-v"])
