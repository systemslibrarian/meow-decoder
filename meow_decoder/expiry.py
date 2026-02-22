"""
Timed Content Expiry Module

Provides time-limited content that self-destructs after a specified duration.
Expiry is enforced at the manifest level — the recipient's decoder checks
the expiry timestamp BEFORE decrypting the payload.

Manifest Field:
    expiry_unix_u64: 8 bytes, big-endian UTC Unix timestamp
    0x0000000000000000 = no expiry (content lives forever)

Usage:
    # Encoding — set a 24-hour expiry
    from meow_decoder.expiry import ExpiryManager

    expiry_bytes = ExpiryManager.encode_expiry(ttl_seconds=86400)
    # Include expiry_bytes in manifest frame 0

    # Decoding — check before decrypt
    if not ExpiryManager.check_expiry(expiry_bytes):
        ExpiryManager.self_destruct(gif_path)
        raise ContentExpiredError("Content has expired and been destroyed")

    # Query remaining time
    remaining = ExpiryManager.time_remaining(expiry_bytes)
    print(f"Content expires in {remaining} seconds")

Security Properties:
    - Expiry is checked BEFORE decryption (no plaintext exposed)
    - Self-destruct overwrites the file with random data before unlinking
    - Expiry timestamp is included in AAD (tamper-resistant)
    - Clock skew tolerance is configurable (default: 60 seconds)

WARNING:
    - Relies on system clock integrity (NTP manipulation can defeat expiry)
    - Self-destruct is best-effort on non-tmpfs storage (SSD wear leveling)
    - A determined adversary can copy the file before expiry
    - Offline systems may have stale clocks
"""

import os
import struct
import time
from pathlib import Path
from typing import Optional, Union

__all__ = [
    "ExpiryManager",
    "ContentExpiredError",
    "ExpiryPolicy",
]


class ContentExpiredError(Exception):
    """Raised when attempting to decode content that has expired."""
    pass


class ExpiryPolicy:
    """
    Named expiry policies for common use cases.

    Usage:
        policy = ExpiryPolicy.EPHEMERAL
        expiry_bytes = ExpiryManager.encode_expiry(policy.ttl_seconds)
    """

    def __init__(self, name: str, ttl_seconds: int, description: str = ""):
        self.name = name
        self.ttl_seconds = ttl_seconds
        self.description = description

    def __repr__(self) -> str:
        return f"ExpiryPolicy({self.name!r}, ttl={self.ttl_seconds}s)"

    # Preset policies
    EPHEMERAL = None  # Set below after class definition
    SHORT = None
    MEDIUM = None
    LONG = None
    PERMANENT = None


# Initialize preset policies
ExpiryPolicy.EPHEMERAL = ExpiryPolicy("ephemeral", 300, "5 minutes — read and destroy")
ExpiryPolicy.SHORT = ExpiryPolicy("short", 3600, "1 hour — quick exchange")
ExpiryPolicy.MEDIUM = ExpiryPolicy("medium", 86400, "24 hours — daily handoff")
ExpiryPolicy.LONG = ExpiryPolicy("long", 604800, "7 days — weekly window")
ExpiryPolicy.PERMANENT = ExpiryPolicy("permanent", 0, "No expiry")


# Expiry field size in bytes
EXPIRY_FIELD_SIZE = 8

# Default clock skew tolerance (seconds)
DEFAULT_CLOCK_SKEW_TOLERANCE = 60


class ExpiryManager:
    """Manage timed expiry for encoded content."""

    @staticmethod
    def encode_expiry(ttl_seconds: int) -> bytes:
        """
        Encode an expiry timestamp as 8-byte big-endian.

        Args:
            ttl_seconds: Time-to-live in seconds from now.
                         0 or negative means no expiry.

        Returns:
            8-byte big-endian expiry timestamp.
        """
        if ttl_seconds <= 0:
            return b"\x00" * EXPIRY_FIELD_SIZE
        expiry = int(time.time()) + ttl_seconds
        return struct.pack(">Q", expiry)

    @staticmethod
    def encode_absolute(expiry_timestamp: float) -> bytes:
        """
        Encode an absolute expiry timestamp.

        Args:
            expiry_timestamp: Unix timestamp when content expires.
                              0 means no expiry.

        Returns:
            8-byte big-endian expiry timestamp.
        """
        if expiry_timestamp <= 0:
            return b"\x00" * EXPIRY_FIELD_SIZE
        return struct.pack(">Q", int(expiry_timestamp))

    @staticmethod
    def decode_expiry(expiry_bytes: bytes) -> int:
        """
        Decode expiry bytes to Unix timestamp.

        Args:
            expiry_bytes: 8-byte big-endian expiry timestamp.

        Returns:
            Unix timestamp (0 = no expiry).

        Raises:
            ValueError: If expiry_bytes is not exactly 8 bytes.
        """
        if len(expiry_bytes) != EXPIRY_FIELD_SIZE:
            raise ValueError(
                f"Expiry field must be {EXPIRY_FIELD_SIZE} bytes, "
                f"got {len(expiry_bytes)}"
            )
        return struct.unpack(">Q", expiry_bytes)[0]

    @staticmethod
    def check_expiry(
        expiry_bytes: bytes,
        clock_skew_tolerance: int = DEFAULT_CLOCK_SKEW_TOLERANCE,
    ) -> bool:
        """
        Check if content has NOT expired.

        Args:
            expiry_bytes: 8-byte big-endian expiry timestamp.
            clock_skew_tolerance: Seconds of clock skew to tolerate.

        Returns:
            True if content is still valid, False if expired.
        """
        expiry = ExpiryManager.decode_expiry(expiry_bytes)
        if expiry == 0:
            return True  # No expiry set
        return time.time() < (expiry + clock_skew_tolerance)

    @staticmethod
    def time_remaining(expiry_bytes: bytes) -> Optional[float]:
        """
        Return seconds until content expires, or None if no expiry.

        Args:
            expiry_bytes: 8-byte big-endian expiry timestamp.

        Returns:
            Seconds remaining (may be negative if expired), or None if no expiry.
        """
        expiry = ExpiryManager.decode_expiry(expiry_bytes)
        if expiry == 0:
            return None  # No expiry
        return float(expiry) - time.time()

    @staticmethod
    def is_permanent(expiry_bytes: bytes) -> bool:
        """
        Check if content has no expiry (permanent).

        Args:
            expiry_bytes: 8-byte big-endian expiry timestamp.

        Returns:
            True if content has no expiry.
        """
        return ExpiryManager.decode_expiry(expiry_bytes) == 0

    @staticmethod
    def no_expiry() -> bytes:
        """Return the 'no expiry' sentinel value."""
        return b"\x00" * EXPIRY_FIELD_SIZE

    @staticmethod
    def self_destruct(
        file_path: Union[str, Path],
        passes: int = 3,
    ) -> bool:
        """
        Securely overwrite and delete an expired file.

        Args:
            file_path: Path to the file to destroy.
            passes: Number of random-data overwrite passes.

        Returns:
            True if the file was successfully destroyed.

        Security:
            - Overwrites with random data on each pass
            - fsync after each pass to ensure physical write
            - Unlinks the file after overwriting
            - Syncs parent directory to flush metadata
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            return False

        try:
            size = file_path.stat().st_size
            if size == 0:
                file_path.unlink()
                return True

            with open(file_path, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    remaining = size
                    while remaining > 0:
                        chunk = min(remaining, 65536)
                        f.write(os.urandom(chunk))
                        remaining -= chunk
                    f.flush()
                    os.fsync(f.fileno())

            file_path.unlink()

            # Sync parent directory metadata
            try:
                parent_fd = os.open(str(file_path.parent), os.O_RDONLY)
                os.fsync(parent_fd)
                os.close(parent_fd)
            except OSError:
                pass

            return True
        except (OSError, PermissionError):
            # Best-effort: try unlinking even if overwrite failed
            try:
                file_path.unlink()
            except OSError:
                pass
            return False

    @staticmethod
    def check_and_destroy(
        expiry_bytes: bytes,
        file_path: Union[str, Path],
        clock_skew_tolerance: int = DEFAULT_CLOCK_SKEW_TOLERANCE,
    ) -> bool:
        """
        Check expiry and self-destruct if expired.

        Convenience method combining check_expiry + self_destruct.

        Args:
            expiry_bytes: 8-byte big-endian expiry timestamp.
            file_path: Path to the GIF file.
            clock_skew_tolerance: Seconds of clock skew to tolerate.

        Returns:
            True if content is still valid.

        Raises:
            ContentExpiredError: If content has expired (file destroyed).
        """
        if ExpiryManager.check_expiry(expiry_bytes, clock_skew_tolerance):
            return True

        # Content expired — destroy it
        ExpiryManager.self_destruct(file_path)

        expiry_ts = ExpiryManager.decode_expiry(expiry_bytes)
        expired_ago = time.time() - expiry_ts
        raise ContentExpiredError(
            f"Content expired {expired_ago:.0f} seconds ago and has been destroyed"
        )

    @staticmethod
    def get_policy(name: str) -> ExpiryPolicy:
        """
        Get a named expiry policy.

        Args:
            name: Policy name (ephemeral, short, medium, long, permanent).

        Returns:
            ExpiryPolicy instance.

        Raises:
            ValueError: If policy name is unknown.
        """
        policies = {
            "ephemeral": ExpiryPolicy.EPHEMERAL,
            "short": ExpiryPolicy.SHORT,
            "medium": ExpiryPolicy.MEDIUM,
            "long": ExpiryPolicy.LONG,
            "permanent": ExpiryPolicy.PERMANENT,
        }
        policy = policies.get(name.lower())
        if policy is None:
            raise ValueError(
                f"Unknown expiry policy: {name!r}. "
                f"Available: {', '.join(policies.keys())}"
            )
        return policy
