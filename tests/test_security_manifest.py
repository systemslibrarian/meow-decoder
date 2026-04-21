#!/usr/bin/env python3
"""
🔒 Security Test Suite - Part 3 of 3: Duress & Manifest Parsing

Tests duress password security and manifest parsing rejection invariants.
Run consecutively with test_security_crypto.py and test_security_frame_mac.py.

1. Duress tag verification
2. Duress tag rejection on wrong password / manifest tampering
3. Manifest too-short / wrong-magic rejection
"""

from meow_decoder.crypto import (
    unpack_manifest,
    compute_duress_tag,
    check_duress_password,
)
import secrets
import pytest

pytestmark = pytest.mark.security


# =============================================================================
# DURESS SECURITY TESTS (3 tests)
# =============================================================================


class TestDuressSecurityInvariants:
    """Test duress password security invariants."""

    def test_duress_tag_verifies_correctly(self):
        """Duress tag should verify with correct password."""
        duress_password = "duresspass123"
        salt = secrets.token_bytes(16)
        manifest_core = b"fake_manifest_core_data_for_testing"

        # Compute duress tag
        tag = compute_duress_tag(duress_password, salt, manifest_core)

        # Should verify correctly
        assert check_duress_password(duress_password, salt, tag, manifest_core) is True

    def test_duress_tag_rejects_wrong_password(self):
        """Duress tag should reject wrong password."""
        duress_password = "duresspass123"
        wrong_password = "wrongpass456"
        salt = secrets.token_bytes(16)
        manifest_core = b"fake_manifest_core_data"

        tag = compute_duress_tag(duress_password, salt, manifest_core)

        # Wrong password should fail
        assert check_duress_password(wrong_password, salt, tag, manifest_core) is False

    def test_duress_tag_detects_manifest_tampering(self):
        """Duress tag should detect manifest tampering."""
        duress_password = "duresspass123"
        salt = secrets.token_bytes(16)
        original_core = b"original_manifest_core_data"
        tampered_core = b"tampered_manifest_core_data"

        tag = compute_duress_tag(duress_password, salt, original_core)

        # Tampered manifest should fail verification
        assert check_duress_password(duress_password, salt, tag, tampered_core) is False


# =============================================================================
# MANIFEST PARSING SECURITY TESTS (2 tests)
# =============================================================================


class TestManifestParsingSecurityInvariants:
    """Test manifest parsing security invariants."""

    def test_manifest_too_short_rejected(self):
        """Manifest shorter than minimum should be rejected."""
        short_manifest = b"MEOW3" + b"\x00" * 50  # Too short

        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(short_manifest)

    def test_manifest_wrong_magic_rejected(self):
        """Manifest with wrong magic bytes should be rejected."""
        # Valid length but wrong magic
        fake_manifest = b"FAKE" + b"3" + b"\x00" * 110

        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(fake_manifest)
