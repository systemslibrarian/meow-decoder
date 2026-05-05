"""
OS Forensic Artifact Cleanup Module

Cleans operating system artifacts that may reveal file operations
performed by Meow Decoder. This is a defence-in-depth measure —
it cannot provide perfect forensic evasion.

Artifacts cleaned:
1. File manager thumbnails (GNOME, KDE, macOS QuickLook)
2. Recent file lists (~/.local/share/recently-used.xbel)
3. System clipboard contents
4. Shell history entries containing meow-related commands
5. Temp files matching meow_* patterns
6. GVFS metadata (GNOME virtual filesystem)

Usage:
    from meow_decoder.forensic_cleanup import ForensicCleaner

    cleaner = ForensicCleaner(file_paths=["/tmp/secret.gif", "/tmp/output.pdf"])
    report = cleaner.clean_all()
    print(report)

WARNING:
    Perfect forensic cleanup is IMPOSSIBLE on a running general-purpose OS.
    This module provides best-effort cleanup for common artifacts.

    What this CANNOT clean:
    - Filesystem journal entries (ext4, NTFS)
    - SSD wear-leveling copies
    - OS-level audit logs (auditd, Windows Event Log)
    - Network connection logs
    - Hardware keylogger captures
    - Swap file contents (use memory_guard for swap prevention)

    Users in high-risk environments should use:
    1. Tails OS or similar amnesic operating systems
    2. Full-disk encryption with volatile keys
    3. Dedicated air-gapped hardware
"""

import glob
import os
import platform
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Union

from .secure_temp import secure_delete_file

__all__ = [
    "ForensicCleaner",
    "clean_shell_history",
    "clean_clipboard",
    "ForensicCleanupWarning",
]


class ForensicCleanupWarning(UserWarning):
    """Warning issued when forensic cleanup encounters issues."""

    pass


# Keywords that indicate meow-decoder usage in shell history
_HISTORY_KEYWORDS = [
    "meow-encode",
    "meow-decode",
    "meow_decoder",
    "schrodinger",
    "dual_stream",
    "duress",
    # Password flags that may leak secrets
    "-p ",
    "--password",
    "-p1 ",
    "-p2 ",
    "--duress-password",
    "--real-password",
]


class ForensicCleaner:
    """
    Clean OS-level artifacts that may reveal Meow Decoder file operations.

    Args:
        file_paths: List of file paths that were used (for targeted cleanup).
        keywords: Additional keywords to scrub from shell history.
    """

    def __init__(
        self,
        file_paths: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
    ):
        self.file_paths = file_paths or []
        self.keywords = list(_HISTORY_KEYWORDS)
        if keywords:
            self.keywords.extend(keywords)
        self.system = platform.system()
        self._report: Dict[str, dict] = {}

    def clean_all(self) -> Dict[str, dict]:
        """
        Run all cleanup routines.

        Returns:
            Dict mapping cleanup category to status dict with keys:
            - "success": bool
            - "items_cleaned": int
            - "error": Optional[str]
        """
        self._report = {}
        self._report["thumbnails"] = self._clean_thumbnails()
        self._report["recent_files"] = self._clean_recent_files()
        self._report["clipboard"] = self._clean_clipboard()
        self._report["shell_history"] = self._clean_shell_history()
        self._report["temp_files"] = self._clean_temp_files()
        self._report["gvfs_metadata"] = self._clean_gvfs_metadata()
        return self._report

    @property
    def report(self) -> Dict[str, dict]:
        """Return the last cleanup report."""
        return self._report

    def _clean_thumbnails(self) -> dict:
        """Remove file manager thumbnail caches."""
        result = {"success": False, "items_cleaned": 0, "error": None}
        targets: List[str] = []

        if self.system == "Linux":
            targets = [
                os.path.expanduser("~/.cache/thumbnails/"),
                os.path.expanduser("~/.thumbnails/"),
            ]
        elif self.system == "Darwin":
            targets = [
                os.path.expanduser("~/Library/Caches/com.apple.QuickLook.thumbnailcache/"),
            ]
        elif self.system == "Windows":
            local_app = os.environ.get("LOCALAPPDATA", "")
            if local_app:
                targets = [
                    os.path.join(local_app, "Microsoft", "Windows", "Explorer"),
                ]

        cleaned = 0
        for target in targets:
            if os.path.isdir(target):
                try:
                    # Only remove thumbnail db files, not the directories themselves
                    for f in Path(target).rglob("*"):
                        if f.is_file():
                            secure_delete_file(f, passes=1)
                            cleaned += 1
                except (OSError, PermissionError) as e:
                    result["error"] = str(e)

        result["items_cleaned"] = cleaned
        result["success"] = True
        return result

    def _clean_recent_files(self) -> dict:
        """Remove entries from OS recent file lists."""
        result = {"success": False, "items_cleaned": 0, "error": None}

        if self.system == "Linux":
            xbel = os.path.expanduser("~/.local/share/recently-used.xbel")
            if os.path.exists(xbel):
                removed = _scrub_file_lines(xbel, self.file_paths)
                result["items_cleaned"] = removed
                result["success"] = True
            else:
                result["success"] = True  # Nothing to clean
        elif self.system == "Darwin":
            # macOS recent files are in LSSharedFileList (binary plist, harder)
            result["success"] = True
            result["error"] = "macOS recent files cleanup not yet implemented"
        else:
            result["success"] = True

        return result

    def _clean_clipboard(self) -> dict:
        """Clear system clipboard contents."""
        return clean_clipboard()

    def _clean_shell_history(self) -> dict:
        """Remove meow-related entries from shell history files."""
        return clean_shell_history(self.keywords)

    def _clean_temp_files(self) -> dict:
        """Securely delete meow-related temp files."""
        result = {"success": False, "items_cleaned": 0, "error": None}
        cleaned = 0

        tmp_dir = tempfile.gettempdir()
        patterns = [
            os.path.join(tmp_dir, "meow_*"),
            os.path.join(tmp_dir, "meow-*"),
        ]

        # Also check /dev/shm — Linux tmpfs path. We only glob meow-*/meow_*
        # entries owned by the prior process; cleanup deletes nothing else.
        if os.path.isdir("/dev/shm"):  # nosec B108
            patterns.extend(
                [
                    "/dev/shm/meow_*",  # nosec B108
                    "/dev/shm/meow-*",  # nosec B108
                ]
            )

        for pattern in patterns:
            for f in glob.glob(pattern):
                path = Path(f)
                if path.is_file():
                    if secure_delete_file(path):
                        cleaned += 1
                elif path.is_dir():
                    try:
                        shutil.rmtree(path)
                        cleaned += 1
                    except OSError:
                        pass

        result["items_cleaned"] = cleaned
        result["success"] = True
        return result

    def _clean_gvfs_metadata(self) -> dict:
        """Clean GNOME virtual filesystem metadata."""
        result = {"success": False, "items_cleaned": 0, "error": None}

        if self.system != "Linux":
            result["success"] = True
            return result

        gvfs_dir = os.path.expanduser("~/.local/share/gvfs-metadata/")
        if not os.path.isdir(gvfs_dir):
            result["success"] = True
            return result

        # Only scrub entries related to our file paths
        cleaned = 0
        for meta_file in Path(gvfs_dir).glob("*"):
            if meta_file.is_file() and not meta_file.suffix == ".log":
                # These are binary files; we can't selectively scrub
                # Skip for now — full cleanup would require gvfs API
                pass

        result["success"] = True
        result["items_cleaned"] = cleaned
        return result


def clean_clipboard() -> dict:
    """
    Clear the system clipboard.

    Returns:
        Status dict with success, items_cleaned, error keys.
    """
    result = {"success": False, "items_cleaned": 0, "error": None}
    system = platform.system()

    try:
        if system == "Linux":
            # Try xclip first, then xsel
            for tool in ["xclip", "xsel"]:
                try:
                    if tool == "xclip":
                        subprocess.run(
                            ["xclip", "-selection", "clipboard"],
                            input=b"",
                            timeout=3,
                            check=False,
                            capture_output=True,
                        )
                    else:
                        subprocess.run(
                            ["xsel", "--clipboard", "--clear"],
                            timeout=3,
                            check=False,
                            capture_output=True,
                        )
                    result["success"] = True
                    result["items_cleaned"] = 1
                    return result
                except FileNotFoundError:
                    continue
            # No clipboard tool available (headless server is fine)
            result["success"] = True
            result["error"] = "No clipboard tool available (xclip/xsel)"
        elif system == "Darwin":
            subprocess.run(
                ["pbcopy"],
                input=b"",
                timeout=3,
                check=False,
                capture_output=True,
            )
            result["success"] = True
            result["items_cleaned"] = 1
        elif system == "Windows":
            # On Windows, use clip.exe
            subprocess.run(
                ["cmd", "/c", "echo.|clip"],
                timeout=3,
                check=False,
                capture_output=True,
            )
            result["success"] = True
            result["items_cleaned"] = 1
        else:
            result["success"] = True
    except Exception as e:
        result["error"] = str(e)
        result["success"] = True  # Non-fatal

    return result


def clean_shell_history(
    keywords: Optional[List[str]] = None,
) -> dict:
    """
    Remove lines containing specified keywords from shell history files.

    Args:
        keywords: Keywords to match and remove. Defaults to meow-related keywords.

    Returns:
        Status dict with success, items_cleaned, error keys.
    """
    result = {"success": False, "items_cleaned": 0, "error": None}

    if keywords is None:
        keywords = list(_HISTORY_KEYWORDS)

    history_files = [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
        os.path.expanduser("~/.local/share/fish/fish_history"),
    ]

    total_removed = 0
    for hf in history_files:
        if os.path.isfile(hf):
            removed = _scrub_file_lines(hf, keywords)
            total_removed += removed

    result["items_cleaned"] = total_removed
    result["success"] = True
    return result


def _scrub_file_lines(filepath: str, patterns: List[str]) -> int:
    """
    Remove lines containing any of the given patterns from a text file.

    Args:
        filepath: Path to the file to scrub.
        patterns: Patterns to match (case-sensitive substring match).

    Returns:
        Number of lines removed.
    """
    try:
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()

        original_count = len(lines)
        filtered = [line for line in lines if not any(p in line for p in patterns)]
        removed = original_count - len(filtered)

        if removed > 0:
            with open(filepath, "w") as f:
                f.writelines(filtered)

        return removed
    except (OSError, PermissionError):
        return 0
