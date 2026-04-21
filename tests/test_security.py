#!/usr/bin/env python3
"""
🔒 Security Test Suite - Entry Point

Tests have been split into three focused files for consecutive execution:

  test_security_crypto.py    — Tamper detection + authentication failures (10 tests)
  test_security_frame_mac.py — Frame MAC integrity and replay prevention (5 tests)
  test_security_manifest.py  — Duress tags + manifest parsing invariants (5 tests)

Re-export all classes for backward compatibility with any direct imports.
"""

from tests.test_security_crypto import TestTamperDetection, TestAuthenticationFailures  # noqa: F401
from tests.test_security_frame_mac import TestFrameMACSecurityInvariants  # noqa: F401
from tests.test_security_manifest import TestDuressSecurityInvariants, TestManifestParsingSecurityInvariants  # noqa: F401
