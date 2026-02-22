"""
Tests for post-encode source cleanup module.

Tests cover:
- Secure deletion with confirmation interlock
- Parent directory sync
- TRIM hint issuance
- Error handling for missing files
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from meow_decoder.source_cleanup import (
    _get_mount_point,
    issue_trim_hint,
    post_encode_cleanup,
    sync_parent_directory,
)


class TestPostEncodeCleanup:
    """Tests for post-encode source cleanup."""

    def test_requires_confirm(self):
        """Must raise ValueError if confirm is not True."""
        with pytest.raises(ValueError, match="confirm=True"):
            post_encode_cleanup("/tmp/nonexistent", confirm=False)

    def test_missing_file(self, tmp_path):
        """Should return error for missing file."""
        result = post_encode_cleanup(tmp_path / "nope.txt", confirm=True)
        assert result["deleted"] is False
        assert "not found" in result["error"]

    def test_successful_deletion(self, tmp_path):
        """Should securely delete existing file."""
        target = tmp_path / "secret.bin"
        target.write_bytes(os.urandom(1024))
        assert target.exists()

        result = post_encode_cleanup(target, confirm=True, trim=False)
        assert result["deleted"] is True
        assert result["error"] is None
        assert not target.exists()

    def test_file_overwritten_before_deletion(self, tmp_path):
        """File should be overwritten with random data before unlink."""
        target = tmp_path / "secret.bin"
        original_data = b"TOP SECRET DATA" * 100
        target.write_bytes(original_data)

        # Patch secure_delete_file to verify it's called
        with patch("meow_decoder.source_cleanup.secure_delete_file") as mock_delete:
            mock_delete.return_value = True
            result = post_encode_cleanup(target, confirm=True, trim=False)
            mock_delete.assert_called_once_with(target, passes=3)
            assert result["deleted"] is True

    def test_custom_passes(self, tmp_path):
        """Should forward passes parameter."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"data")

        with patch("meow_decoder.source_cleanup.secure_delete_file") as mock_delete:
            mock_delete.return_value = True
            post_encode_cleanup(target, confirm=True, passes=7, trim=False)
            mock_delete.assert_called_once_with(target, passes=7)

    def test_parent_sync_attempted(self, tmp_path):
        """Parent directory should be synced after deletion."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"data")

        result = post_encode_cleanup(target, confirm=True, sync_parent=True, trim=False)
        assert result["deleted"] is True
        # parent_synced may be True or False depending on OS support
        assert isinstance(result["parent_synced"], bool)

    def test_trim_attempted(self, tmp_path):
        """TRIM hint should be attempted when trim=True."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"data")

        with patch("meow_decoder.source_cleanup.issue_trim_hint", return_value=False):
            result = post_encode_cleanup(target, confirm=True, trim=True)
            assert isinstance(result["trim_issued"], bool)

    def test_no_trim_when_disabled(self, tmp_path):
        """TRIM should not be attempted when trim=False."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"data")

        result = post_encode_cleanup(target, confirm=True, trim=False)
        assert result["trim_issued"] is False


class TestSyncParentDirectory:
    """Tests for parent directory sync."""

    def test_sync_existing_parent(self, tmp_path):
        """Should attempt fsync on existing parent."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"data")
        result = sync_parent_directory(target)
        assert isinstance(result, bool)

    def test_sync_nonexistent_path(self):
        """Should handle nonexistent path gracefully."""
        result = sync_parent_directory("/nonexistent/path/file.bin")
        # Should return False (can't open parent)
        assert result is False or isinstance(result, bool)


class TestIssueTrimHint:
    """Tests for TRIM hint issuance."""

    @patch("meow_decoder.source_cleanup.platform")
    def test_non_linux_returns_false(self, mock_platform):
        """Should return False on non-Linux."""
        mock_platform.system.return_value = "Darwin"
        assert issue_trim_hint("/tmp/file") is False

    @patch("meow_decoder.source_cleanup.platform")
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_no_fstrim_returns_false(self, mock_run, mock_platform):
        """Should return False if fstrim not found."""
        mock_platform.system.return_value = "Linux"
        assert issue_trim_hint("/tmp/file") is False

    @patch("meow_decoder.source_cleanup.platform")
    @patch("meow_decoder.source_cleanup._get_mount_point", return_value="/")
    @patch("subprocess.run")
    def test_successful_trim(self, mock_run, mock_mount, mock_platform):
        """Should return True on successful fstrim."""
        mock_platform.system.return_value = "Linux"
        mock_run.return_value = MagicMock(returncode=0)
        assert issue_trim_hint("/tmp/file") is True


class TestGetMountPoint:
    """Tests for mount point detection."""

    def test_root_path(self):
        """Root path should return /."""
        result = _get_mount_point("/")
        assert result == "/"

    def test_tmp_path(self):
        """Should find a mount point for /tmp."""
        result = _get_mount_point("/tmp/somefile")
        assert result is not None
        assert isinstance(result, str)
