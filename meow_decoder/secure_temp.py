"""
Secure Temporary File Management

Ensures all temporary files are stored in RAM-backed filesystems (tmpfs)
to prevent sensitive data from being written to persistent storage.

Features:
1. Prefer /dev/shm (always tmpfs on Linux)
2. Fall back to /tmp if it's tmpfs-backed
3. Warn if no tmpfs is available
4. Automatic cleanup on context exit
5. Secure deletion (zero + unlink)

Usage:
    from meow_decoder.secure_temp import SecureTempDir, get_secure_temp_dir

    # Context manager (recommended)
    with SecureTempDir() as tmp:
        path = tmp.write("secret.bin", plaintext_bytes)
        # ... use path ...
    # Directory is securely wiped on exit

    # Simple function
    tmpdir = get_secure_temp_dir()

Security Properties:
    - Data stored only in RAM (tmpfs), never on disk
    - Securely zeroed before deletion
    - Directory permissions set to 0o700 (owner only)
    - Falls back gracefully with warnings if tmpfs unavailable

WARNING:
    - /dev/shm may be size-limited (typically 50% of RAM)
    - tmpfs eviction (memory pressure) writes pages to swap unless mlockall is active
    - Use memory_guard.activate_memory_guard() alongside this module
"""

import os
import platform
import secrets
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path
from typing import Optional, Union

__all__ = [
    "SecureTempDir",
    "get_secure_temp_dir",
    "secure_delete_file",
    "is_tmpfs",
    "SecureTempWarning",
]


class SecureTempWarning(UserWarning):
    """Warning issued when secure temp storage is unavailable."""

    pass


def is_tmpfs(path: str) -> bool:
    """
    Check if a path resides on a tmpfs filesystem.

    Args:
        path: Filesystem path to check.

    Returns:
        True if the path is on tmpfs, False otherwise or if undetermined.
    """
    if platform.system() != "Linux":
        return False
    try:
        result = subprocess.run(
            ["stat", "-f", "-c", "%T", path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "tmpfs" in result.stdout.strip().lower()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def secure_delete_file(path: Union[str, Path], passes: int = 3) -> bool:
    """
    Securely overwrite a file with random data, then delete it.

    Args:
        path: Path to the file to securely delete.
        passes: Number of overwrite passes (default: 3).

    Returns:
        True if the file was securely deleted, False otherwise.

    Security:
        - Overwrites with os.urandom data on each pass
        - Calls fsync to flush to storage before unlinking
        - 3 passes is sufficient for RAM-backed storage (overkill, but safe)
    """
    path = Path(path)
    if not path.is_file():
        return False
    try:
        size = path.stat().st_size
        if size == 0:
            path.unlink()
            return True
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # Write in chunks to handle large files without OOM
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, 65536)
                    f.write(os.urandom(chunk))
                    remaining -= chunk
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        return True
    except (OSError, PermissionError):
        # Best-effort: try unlinking even if overwrite failed
        try:
            path.unlink()
        except OSError:
            pass
        return False


def _secure_delete_dir(dirpath: Path) -> None:
    """Securely delete all files in a directory, then remove it."""
    if not dirpath.is_dir():
        return
    for item in dirpath.iterdir():
        if item.is_file():
            secure_delete_file(item)
        elif item.is_dir():
            _secure_delete_dir(item)
    try:
        dirpath.rmdir()
    except OSError:
        pass


def get_secure_temp_dir(prefix: str = "meow_") -> str:
    """
    Return a tmpfs-backed temporary directory path.

    Creates a new directory with restrictive permissions.
    Caller is responsible for cleanup (use SecureTempDir for auto-cleanup).

    Args:
        prefix: Directory name prefix.

    Returns:
        Path to the secure temporary directory.

    Raises:
        SecureTempWarning: If no tmpfs is available.
    """
    # Strategy: prefer /dev/shm (always tmpfs on Linux) > /tmp (if tmpfs)
    candidates = []

    # 1. /dev/shm — guaranteed RAM-backed on Linux
    if os.path.isdir("/dev/shm"):
        candidates.append("/dev/shm")

    # 2. /tmp — often tmpfs on modern systems
    if is_tmpfs("/tmp"):
        candidates.append("/tmp")

    # 3. XDG_RUNTIME_DIR — typically tmpfs (e.g., /run/user/1000)
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime and os.path.isdir(xdg_runtime) and is_tmpfs(xdg_runtime):
        candidates.append(xdg_runtime)

    if candidates:
        base = candidates[0]
        # Use a random suffix to prevent directory name prediction
        dirname = f"{prefix}{os.getpid()}_{secrets.token_hex(8)}"
        dirpath = os.path.join(base, dirname)
        os.makedirs(dirpath, mode=0o700, exist_ok=True)
        return dirpath

    # Fallback: regular /tmp (not tmpfs)
    warnings.warn(
        "No tmpfs available — temp files may be written to persistent storage. "
        "Consider mounting tmpfs: sudo mount -t tmpfs -o size=256m,noexec,nosuid tmpfs /tmp/meow",
        SecureTempWarning,
        stacklevel=2,
    )
    dirpath = tempfile.mkdtemp(prefix=prefix)
    os.chmod(dirpath, 0o700)
    return dirpath


class SecureTempDir:
    """
    Context manager for secure temporary directory operations.

    Creates a tmpfs-backed temp directory on enter, securely wipes it on exit.

    Usage:
        with SecureTempDir() as tmp:
            path = tmp.write("secret.bin", data)
            content = tmp.read("secret.bin")
        # Everything securely wiped
    """

    def __init__(self, prefix: str = "meow_"):
        self.prefix = prefix
        self._path: Optional[str] = None

    @property
    def path(self) -> str:
        """Return the temp directory path."""
        if self._path is None:
            raise RuntimeError("SecureTempDir not entered (use 'with' statement)")
        return self._path

    def write(self, filename: str, data: bytes) -> Path:
        """
        Write data to a file in the secure temp directory.

        Args:
            filename: Name of the file (no path separators allowed).
            data: Data to write.

        Returns:
            Path to the written file.
        """
        if os.sep in filename or "/" in filename:
            raise ValueError("Filename must not contain path separators")
        filepath = Path(self.path) / filename
        filepath.write_bytes(data)
        return filepath

    def read(self, filename: str) -> bytes:
        """
        Read data from a file in the secure temp directory.

        Args:
            filename: Name of the file.

        Returns:
            File contents as bytes.
        """
        filepath = Path(self.path) / filename
        return filepath.read_bytes()

    def __enter__(self) -> "SecureTempDir":
        self._path = get_secure_temp_dir(prefix=self.prefix)
        return self

    def __exit__(self, *args) -> None:
        if self._path is not None:
            _secure_delete_dir(Path(self._path))
            self._path = None

    def __del__(self):
        """Safety net: clean up if context manager wasn't used."""
        if self._path is not None and Path(self._path).exists():
            _secure_delete_dir(Path(self._path))
