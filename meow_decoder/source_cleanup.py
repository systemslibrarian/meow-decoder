"""
Post-Encode Source Cleanup

Securely deletes the original source file after successful encoding.
This prevents forensic recovery of the plaintext from persistent storage.

Usage:
    from meow_decoder.source_cleanup import post_encode_cleanup

    # After successful encode:
    post_encode_cleanup(input_path, confirm=True)

Security Properties:
    - Multi-pass random overwrite via secure_delete_file()
    - Parent directory metadata sync (fsync) to flush inode changes
    - Optional TRIM hint for SSD storage
    - Requires explicit confirm=True to prevent accidental deletion
    - Returns detailed status for audit logging

WARNING:
    - Only call AFTER verifying the encoded output is valid
    - On copy-on-write filesystems (btrfs, ZFS), overwrite may not
      destroy all copies — consider full-disk encryption as a layer
    - SSD wear-leveling may retain old data in spare blocks
"""

import os
import platform
from pathlib import Path
from typing import Optional, Union

from .secure_temp import secure_delete_file

__all__ = [
    "post_encode_cleanup",
    "sync_parent_directory",
    "issue_trim_hint",
]


def sync_parent_directory(path: Union[str, Path]) -> bool:
    """
    Sync the parent directory's metadata to storage.

    After unlinking a file, the directory entry removal may be
    buffered. fsync on the parent directory forces the metadata
    update to persistent storage.

    Args:
        path: Path whose parent directory should be synced.

    Returns:
        True if sync succeeded, False otherwise.
    """
    try:
        parent = Path(path).parent
        fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
            return True
        finally:
            os.close(fd)
    except (OSError, PermissionError):
        return False


def issue_trim_hint(path: Union[str, Path]) -> bool:
    """
    Issue a TRIM/discard hint for the filesystem containing the given path.

    On SSDs, TRIM tells the controller that deleted blocks are no longer
    in use, allowing the firmware to erase them. Without TRIM, deleted
    data may persist in spare blocks indefinitely.

    Args:
        path: A path on the filesystem to TRIM.

    Returns:
        True if TRIM was issued, False otherwise.

    Note:
        Requires root privileges for fstrim. Returns False gracefully
        if unavailable or unprivileged.
    """
    if platform.system() != "Linux":
        return False

    import subprocess

    try:
        mount_point = _get_mount_point(path)
        if mount_point is None:
            return False

        result = subprocess.run(
            ["fstrim", "-v", mount_point],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, PermissionError):
        return False


def _get_mount_point(path: Union[str, Path]) -> Optional[str]:
    """
    Find the mount point for a given path by walking up the tree.

    Args:
        path: Path to find mount point for.

    Returns:
        Mount point string, or None if undetermined.
    """
    path = Path(path).resolve()
    while path != path.parent:
        if path.is_mount():
            return str(path)
        path = path.parent
    return str(path)  # Root


def post_encode_cleanup(
    source_path: Union[str, Path],
    confirm: bool = False,
    passes: int = 3,
    trim: bool = True,
    sync_parent: bool = True,
) -> dict:
    """
    Securely delete the source file after encoding.

    Args:
        source_path: Path to the original source file.
        confirm: Must be True to actually delete. Safety interlock.
        passes: Number of random overwrite passes (default: 3).
        trim: Issue TRIM hint after deletion (default: True).
        sync_parent: Sync parent directory metadata (default: True).

    Returns:
        dict with keys:
            - deleted (bool): Whether file was successfully deleted
            - trim_issued (bool): Whether TRIM hint was sent
            - parent_synced (bool): Whether parent dir was synced
            - error (str or None): Error message if any

    Raises:
        ValueError: If confirm is not True.
    """
    source_path = Path(source_path)

    if not confirm:
        raise ValueError(
            "post_encode_cleanup() requires confirm=True. "
            "This is a safety interlock to prevent accidental deletion."
        )

    result = {
        "deleted": False,
        "trim_issued": False,
        "parent_synced": False,
        "error": None,
    }

    if not source_path.is_file():
        result["error"] = f"Source file not found: {source_path}"
        return result

    # Step 1: Secure multi-pass overwrite + unlink
    deleted = secure_delete_file(source_path, passes=passes)
    result["deleted"] = deleted

    if not deleted:
        result["error"] = f"Failed to securely delete: {source_path}"
        return result

    # Step 2: Sync parent directory metadata
    if sync_parent:
        result["parent_synced"] = sync_parent_directory(source_path)

    # Step 3: TRIM hint for SSD
    if trim:
        result["trim_issued"] = issue_trim_hint(source_path)

    return result
