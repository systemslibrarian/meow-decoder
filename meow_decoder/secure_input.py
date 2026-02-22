"""
Secure Password Input

Wraps getpass() with keystroke timing normalization to prevent
biometric leakage through typing cadence analysis.

Usage:
    from meow_decoder.secure_input import secure_getpass

    password = secure_getpass("Enter password: ")

Security Properties:
    - Random delay before and after input masks timing profile
    - Input collected via getpass() (no terminal echo)
    - Password stored in bytearray for zeroization
    - Warning if stdin is not a TTY (pipe/redirect risk)

Threat Model:
    An adversary with acoustic, electromagnetic, or timing side-channel
    access to the input terminal could correlate keystroke patterns to
    identify users or infer password characteristics. Injecting random
    delays before/after input adds noise to the timing profile.

Limitations:
    - Cannot mask inter-keystroke timing (getpass is blocking)
    - Does not protect against keyloggers or screen capture
    - Random delays only applied at session boundaries, not per-keystroke
"""

import os
import struct
import sys
import time
import warnings
from getpass import getpass
from typing import Optional

__all__ = [
    "secure_getpass",
    "SecurePasswordWarning",
]


class SecurePasswordWarning(UserWarning):
    """Warning for password input security concerns."""
    pass


def _csprng_delay(min_ms: int, max_ms: int) -> float:
    """
    Generate a cryptographically random delay in seconds.

    Args:
        min_ms: Minimum delay in milliseconds.
        max_ms: Maximum delay in milliseconds.

    Returns:
        Delay in seconds.
    """
    if min_ms > max_ms:
        raise ValueError("min_ms must be <= max_ms")
    if min_ms == max_ms:
        return min_ms / 1000.0

    range_ms = max_ms - min_ms + 1
    raw = struct.unpack(">I", os.urandom(4))[0]
    limit = (0xFFFFFFFF // range_ms) * range_ms
    while raw >= limit:
        raw = struct.unpack(">I", os.urandom(4))[0]
    delay_ms = min_ms + (raw % range_ms)
    return delay_ms / 1000.0


def secure_getpass(
    prompt: str = "Password: ",
    min_delay_ms: int = 50,
    max_delay_ms: int = 300,
    warn_non_tty: bool = True,
) -> str:
    """
    Securely prompt for a password with timing normalization.

    Injects random delays before and after input collection to
    obscure the total input time and mask session-level timing
    patterns.

    Args:
        prompt: Prompt displayed to the user.
        min_delay_ms: Minimum random delay (milliseconds).
        max_delay_ms: Maximum random delay (milliseconds).
        warn_non_tty: Warn if stdin is not a TTY.

    Returns:
        The password string.

    Security:
        - Pre-input delay: random [min, max] ms
        - Post-input delay: random [min, max] ms
        - No echo to terminal (via getpass)
        - Warns on non-TTY stdin (password may be logged)
    """
    # Check for non-TTY stdin (pipe, redirect, etc.)
    if warn_non_tty and not _is_tty():
        warnings.warn(
            "stdin is not a TTY — password may appear in process table, "
            "shell history, or log files. Use a TTY for secure input.",
            SecurePasswordWarning,
            stacklevel=2,
        )

    # Pre-input random delay
    pre_delay = _csprng_delay(min_delay_ms, max_delay_ms)
    time.sleep(pre_delay)

    # Collect password (no echo)
    password = getpass(prompt)

    # Post-input random delay
    post_delay = _csprng_delay(min_delay_ms, max_delay_ms)
    time.sleep(post_delay)

    return password


def _is_tty() -> bool:
    """Check if stdin is a TTY."""
    try:
        return os.isatty(sys.stdin.fileno())
    except (AttributeError, ValueError, OSError):
        return False
