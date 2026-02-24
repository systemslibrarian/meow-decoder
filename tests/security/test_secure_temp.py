"""
Tests for secure_temp module.

Tests tmpfs detection, secure temp directory creation, and secure file deletion.
"""

import os
import platform
import tempfile
import warnings
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

from meow_decoder.secure_temp import (
    SecureTempDir,
    SecureTempWarning,
    get_secure_temp_dir,
    is_tmpfs,
    secure_delete_file,
)


class TestIsTmpfs:
    """Test tmpfs detection."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only")
    def test_dev_shm_is_tmpfs(self):
        """On Linux, /dev/shm should be tmpfs."""
        if os.path.isdir("/dev/shm"):
            assert is_tmpfs("/dev/shm") is True

    def test_nonexistent_path(self):
        """Non-existent path should return False."""
        assert is_tmpfs("/nonexistent/path/xyz") is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only")
    def test_root_is_not_tmpfs(self):
        """Root filesystem is typically not tmpfs."""
        # / is usually ext4 or similar, not tmpfs
        # This could theoretically fail on a tmpfs-root system, but very unlikely
        result = is_tmpfs("/")
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Linux", reason="Non-Linux test")
    def test_non_linux_returns_false(self):
        """Non-Linux systems should always return False."""
        assert is_tmpfs("/tmp") is False


class TestSecureDeleteFile:
    """Test secure file deletion."""

    def test_delete_existing_file(self, tmp_path):
        """Should securely delete an existing file."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"secret data" * 100)
        assert f.exists()
        result = secure_delete_file(f)
        assert result is True
        assert not f.exists()

    def test_delete_nonexistent_file(self, tmp_path):
        """Should return False for non-existent file."""
        f = tmp_path / "doesnt_exist.bin"
        result = secure_delete_file(f)
        assert result is False

    def test_delete_empty_file(self, tmp_path):
        """Should handle empty files."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = secure_delete_file(f)
        assert result is True
        assert not f.exists()

    def test_delete_large_file(self, tmp_path):
        """Should handle larger files (written in chunks)."""
        f = tmp_path / "large.bin"
        f.write_bytes(os.urandom(200_000))  # 200KB
        result = secure_delete_file(f)
        assert result is True
        assert not f.exists()

    def test_multiple_passes(self, tmp_path):
        """Should accept custom pass count."""
        f = tmp_path / "multi.bin"
        f.write_bytes(b"X" * 1024)
        result = secure_delete_file(f, passes=5)
        assert result is True


class TestGetSecureTempDir:
    """Test secure temp directory creation."""

    def test_returns_string(self):
        """Should return a string path."""
        path = get_secure_temp_dir()
        try:
            assert isinstance(path, str)
            assert os.path.isdir(path)
        finally:
            os.rmdir(path)

    def test_permissions_restrictive(self):
        """Directory should have restrictive permissions (0o700)."""
        path = get_secure_temp_dir()
        try:
            stat = os.stat(path)
            mode = stat.st_mode & 0o777
            assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"
        finally:
            os.rmdir(path)

    def test_custom_prefix(self):
        """Should use custom prefix."""
        path = get_secure_temp_dir(prefix="test_meow_")
        try:
            basename = os.path.basename(path)
            assert basename.startswith("test_meow_")
        finally:
            os.rmdir(path)

    @pytest.mark.skipif(not os.path.isdir("/dev/shm"), reason="No /dev/shm available")
    def test_prefers_dev_shm(self):
        """Should prefer /dev/shm when available."""
        path = get_secure_temp_dir()
        try:
            assert path.startswith("/dev/shm"), f"Expected /dev/shm, got {path}"
        finally:
            os.rmdir(path)

    def test_unique_paths(self):
        """Each call should produce a unique directory."""
        paths = []
        try:
            for _ in range(5):
                paths.append(get_secure_temp_dir())
            assert len(set(paths)) == 5
        finally:
            for p in paths:
                if os.path.isdir(p):
                    os.rmdir(p)


class TestSecureTempDir:
    """Test the SecureTempDir context manager."""

    def test_context_creates_dir(self):
        """Entering context should create directory."""
        with SecureTempDir() as tmp:
            assert os.path.isdir(tmp.path)

    def test_context_removes_dir(self):
        """Exiting context should remove directory."""
        with SecureTempDir() as tmp:
            path = tmp.path
        assert not os.path.exists(path)

    def test_write_and_read(self):
        """Should be able to write and read files."""
        data = b"secret payload data"
        with SecureTempDir() as tmp:
            filepath = tmp.write("test.bin", data)
            assert filepath.exists()
            read_data = tmp.read("test.bin")
            assert read_data == data

    def test_files_cleaned_on_exit(self):
        """Files should be deleted when context exits."""
        with SecureTempDir() as tmp:
            filepath = tmp.write("secret.bin", b"classified")
            path = Path(tmp.path)
        # Both file and directory should be gone
        assert not filepath.exists()
        assert not path.exists()

    def test_path_traversal_rejected(self):
        """Filenames with path separators should be rejected."""
        with SecureTempDir() as tmp:
            with pytest.raises(ValueError, match="path separator"):
                tmp.write("../escape.bin", b"evil")

    def test_path_before_enter_raises(self):
        """Accessing path before entering context should raise."""
        tmp = SecureTempDir()
        with pytest.raises(RuntimeError, match="not entered"):
            _ = tmp.path

    def test_nested_writes(self):
        """Multiple files should work."""
        with SecureTempDir() as tmp:
            tmp.write("file1.bin", b"data1")
            tmp.write("file2.bin", b"data2")
            assert tmp.read("file1.bin") == b"data1"
            assert tmp.read("file2.bin") == b"data2"
