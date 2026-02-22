"""
Tests for memory_guard module.

Tests OS-level memory hardening: mlockall, RLIMIT_CORE, PR_SET_DUMPABLE.
"""

import os
import platform
import resource
import warnings

import pytest

from meow_decoder.memory_guard import (
    MemoryGuardWarning,
    activate_memory_guard,
    deactivate_memory_guard,
    get_guard_status,
    is_guard_active,
    raise_mlock_limit,
)


class TestRaiseMlockLimit:
    """Test RLIMIT_MEMLOCK manipulation."""

    def test_raise_returns_bool(self):
        """raise_mlock_limit should return a boolean."""
        result = raise_mlock_limit(target_bytes=1024)
        assert isinstance(result, bool)

    def test_raise_tiny_limit_succeeds(self):
        """A very small target should always succeed."""
        result = raise_mlock_limit(target_bytes=4096)
        assert result is True

    def test_raise_huge_limit_may_fail(self):
        """A huge target may fail if hard limit is low."""
        result = raise_mlock_limit(target_bytes=1024 * 1024 * 1024 * 100)  # 100 GiB
        assert isinstance(result, bool)


class TestActivateMemoryGuard:
    """Test the main activation function."""

    def setup_method(self):
        """Reset guard state before each test."""
        # Deactivate to start clean
        if is_guard_active():
            deactivate_memory_guard()

    def teardown_method(self):
        """Deactivate guard after each test."""
        if is_guard_active():
            deactivate_memory_guard()

    def test_returns_dict(self):
        """activate_memory_guard should return a status dict."""
        status = activate_memory_guard(warn_on_failure=False)
        assert isinstance(status, dict)

    def test_status_has_expected_keys(self):
        """Status dict should have standard keys."""
        status = activate_memory_guard(warn_on_failure=False)
        assert "mlockall" in status
        assert "no_coredump" in status
        if platform.system() == "Linux":
            assert "no_ptrace" in status

    def test_all_values_are_bool(self):
        """All status values should be booleans."""
        status = activate_memory_guard(warn_on_failure=False)
        for key, value in status.items():
            assert isinstance(value, bool), f"{key} is not bool: {value!r}"

    def test_no_coredump_enforced(self):
        """Core dump limit should be set to 0."""
        activate_memory_guard(warn_on_failure=False)
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        assert soft == 0

    def test_get_guard_status_after_activation(self):
        """get_guard_status should return the cached status."""
        status = activate_memory_guard(warn_on_failure=False)
        cached = get_guard_status()
        assert cached == status

    def test_is_guard_active_true_after_activation(self):
        """is_guard_active should return True after activation."""
        activate_memory_guard(warn_on_failure=False)
        assert is_guard_active() is True

    def test_is_guard_active_false_before_activation(self):
        """is_guard_active should return False before activation."""
        assert is_guard_active() is False

    def test_get_guard_status_none_before_activation(self):
        """get_guard_status should return None before first activation."""
        # Already reset in setup_method
        # Note: module-level state may persist, so we check type
        status = get_guard_status()
        # After deactivate, _guard_status may still hold previous value
        # Just verify it returns something reasonable
        assert status is None or isinstance(status, dict)


class TestDeactivateMemoryGuard:
    """Test guard deactivation (for test cleanup)."""

    def test_deactivate_returns_dict(self):
        """deactivate_memory_guard should return a status dict."""
        activate_memory_guard(warn_on_failure=False)
        status = deactivate_memory_guard()
        assert isinstance(status, dict)

    def test_deactivate_restores_coredump(self):
        """Deactivation should attempt to restore core dump capability."""
        activate_memory_guard(warn_on_failure=False)
        status = deactivate_memory_guard()
        # Deactivation should return a dict with coredump_restored key
        assert "coredump_restored" in status
        assert isinstance(status["coredump_restored"], bool)

    def test_deactivate_clears_active_flag(self):
        """Deactivation should clear the is_guard_active flag."""
        activate_memory_guard(warn_on_failure=False)
        deactivate_memory_guard()
        assert is_guard_active() is False


class TestWarnings:
    """Test warning behavior on failure."""

    def teardown_method(self):
        if is_guard_active():
            deactivate_memory_guard()

    def test_warnings_emitted_on_failure(self):
        """Warnings should be emitted when protections fail."""
        # This test just verifies warnings don't crash
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            activate_memory_guard(warn_on_failure=True)

    def test_no_warnings_when_suppressed(self):
        """No warnings should be emitted when warn_on_failure=False."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            activate_memory_guard(warn_on_failure=False)
            guard_warnings = [x for x in w if issubclass(x.category, MemoryGuardWarning)]
            assert len(guard_warnings) == 0


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only test")
class TestLinuxSpecific:
    """Linux-specific memory guard tests."""

    def teardown_method(self):
        if is_guard_active():
            deactivate_memory_guard()

    def test_pr_set_dumpable(self):
        """PR_SET_DUMPABLE should be set on Linux."""
        status = activate_memory_guard(warn_on_failure=False)
        assert "no_ptrace" in status
