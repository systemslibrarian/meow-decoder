"""
Tests for forensic_cleanup module.

Tests OS artifact cleanup: thumbnails, history, clipboard, temp files.
"""

import os
import platform
import tempfile
from pathlib import Path

import pytest

from meow_decoder.forensic_cleanup import (
    ForensicCleaner,
    ForensicCleanupWarning,
    _scrub_file_lines,
    clean_clipboard,
    clean_shell_history,
)


class TestScrubFileLines:
    """Test the line-scrubbing helper function."""

    def test_removes_matching_lines(self, tmp_path):
        """Lines containing patterns should be removed."""
        f = tmp_path / "history"
        f.write_text(
            "cd /home/user\n"
            "meow-encode -i secret.pdf -o out.gif -p pass123\n"
            "ls -la\n"
            "meow-decode-gif -i out.gif -o result.pdf\n"
            "echo done\n"
        )
        removed = _scrub_file_lines(str(f), ["meow-encode", "meow-decode"])
        assert removed == 2

        content = f.read_text()
        assert "meow-encode" not in content
        assert "meow-decode" not in content
        assert "cd /home/user" in content
        assert "ls -la" in content
        assert "echo done" in content

    def test_no_matches_no_change(self, tmp_path):
        """File should be unchanged if no patterns match."""
        f = tmp_path / "history"
        original = "ls\ncd\npwd\n"
        f.write_text(original)
        removed = _scrub_file_lines(str(f), ["meow-encode"])
        assert removed == 0
        assert f.read_text() == original

    def test_empty_file(self, tmp_path):
        """Should handle empty files."""
        f = tmp_path / "empty"
        f.write_text("")
        removed = _scrub_file_lines(str(f), ["anything"])
        assert removed == 0

    def test_nonexistent_file(self, tmp_path):
        """Should return 0 for nonexistent file."""
        removed = _scrub_file_lines(str(tmp_path / "nope"), ["anything"])
        assert removed == 0

    def test_password_patterns_removed(self, tmp_path):
        """Password-related patterns should be caught."""
        f = tmp_path / "history"
        f.write_text(
            "safe command\n"
            'command -p "mysecretpassword"\n'
            "another safe command\n"
            "command --password=secret\n"
        )
        removed = _scrub_file_lines(str(f), ["-p ", "--password"])
        assert removed == 2

    def test_all_lines_removed(self, tmp_path):
        """Should handle removing all lines."""
        f = tmp_path / "history"
        f.write_text("meow-encode a\nmeow-decode b\n")
        removed = _scrub_file_lines(str(f), ["meow-"])
        assert removed == 2
        assert f.read_text() == ""


class TestForensicCleaner:
    """Test the ForensicCleaner class."""

    def test_clean_all_returns_report(self):
        """clean_all should return a dict with all categories."""
        cleaner = ForensicCleaner()
        report = cleaner.clean_all()
        assert isinstance(report, dict)
        expected_keys = {"thumbnails", "recent_files", "clipboard", "shell_history", "temp_files", "gvfs_metadata"}
        assert expected_keys == set(report.keys())

    def test_each_category_has_standard_keys(self):
        """Each category should have success, items_cleaned, error."""
        cleaner = ForensicCleaner()
        report = cleaner.clean_all()
        for category, status in report.items():
            assert "success" in status, f"{category} missing 'success'"
            assert "items_cleaned" in status, f"{category} missing 'items_cleaned'"
            assert "error" in status, f"{category} missing 'error'"

    def test_report_property(self):
        """Should cache report for later access."""
        cleaner = ForensicCleaner()
        report = cleaner.clean_all()
        assert cleaner.report == report

    def test_custom_keywords(self):
        """Should accept custom keywords."""
        cleaner = ForensicCleaner(keywords=["custom_keyword"])
        assert "custom_keyword" in cleaner.keywords

    def test_file_paths_stored(self):
        """Should store file paths."""
        paths = ["/tmp/test1.gif", "/tmp/test2.pdf"]
        cleaner = ForensicCleaner(file_paths=paths)
        assert cleaner.file_paths == paths

    def test_clean_temp_files(self, tmp_path):
        """Should clean meow_* temp files."""
        # Create some temp files in /tmp
        tmpdir = tempfile.gettempdir()
        test_files = []
        for i in range(3):
            f = Path(tmpdir) / f"meow_test_{i}.tmp"
            f.write_bytes(b"test data")
            test_files.append(f)

        try:
            cleaner = ForensicCleaner()
            result = cleaner._clean_temp_files()
            assert result["success"] is True
            assert result["items_cleaned"] >= 3

            # Verify files are gone
            for f in test_files:
                assert not f.exists()
        finally:
            # Cleanup any remaining files
            for f in test_files:
                if f.exists():
                    f.unlink()


class TestCleanClipboard:
    """Test clipboard cleaning."""

    def test_returns_dict(self):
        """Should return a status dict."""
        result = clean_clipboard()
        assert isinstance(result, dict)
        assert "success" in result

    def test_non_fatal_on_failure(self):
        """Should not raise exceptions even if clipboard tools unavailable."""
        result = clean_clipboard()
        # success=True even if no clipboard tool found (non-fatal)
        assert result["success"] is True


class TestCleanShellHistory:
    """Test shell history cleaning."""

    def test_returns_dict(self):
        """Should return a status dict."""
        result = clean_shell_history()
        assert isinstance(result, dict)
        assert result["success"] is True

    def test_custom_keywords(self):
        """Should accept custom keywords."""
        result = clean_shell_history(keywords=["nonexistent_pattern_xyz"])
        assert result["success"] is True

    def test_dont_corrupt_real_history(self, tmp_path, monkeypatch):
        """Ensure we don't accidentally corrupt real shell history.

        This test uses monkeypatch to redirect history files to temp dir.
        """
        # Create a fake history file
        fake_history = tmp_path / ".bash_history"
        fake_history.write_text(
            "cd /home\n"
            "meow-encode -p secret\n"
            "git status\n"
        )

        # Monkeypatch expanduser to redirect to tmp_path
        original_expanduser = os.path.expanduser

        def mock_expanduser(path):
            if path.startswith("~/"):
                return str(tmp_path / path[2:])
            return original_expanduser(path)

        monkeypatch.setattr(os.path, "expanduser", mock_expanduser)

        result = clean_shell_history()
        assert result["success"] is True
        assert result["items_cleaned"] >= 1

        content = fake_history.read_text()
        assert "meow-encode" not in content
        assert "cd /home" in content
        assert "git status" in content
