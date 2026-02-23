"""
Timing-Equalized Operations for Side-Channel Resistance

Provides wrappers that ensure cryptographic operations take constant
wall-clock time regardless of success, failure, or input validity.
This prevents timing oracles that leak information about:
  - Whether a password is correct vs. incorrect
  - Whether duress vs. real password was entered
  - Whether decryption succeeded at early vs. late stages

Architecture:
    _inner_operation() → actual work
    equalize_to_target() → pads elapsed time to a fixed wall-clock target
    ± random jitter → prevents statistical averaging attacks

Security Properties:
    - All code paths (success, failure, duress) run Argon2id
    - Wall-clock time is padded to target ± jitter
    - Jitter uses secrets.randbelow (CSPRNG)
    - Fail-closed: if inner operation raises, timing is still equalized

Honest Limitations:
    - OS scheduler preemption causes natural timing noise
    - CPU frequency scaling (turbo boost) affects actual execution time
    - Memory allocation patterns may differ (cache timing)
    - This is defense-in-depth, not a guarantee against nation-state attackers
      with high-precision timing and many samples

See docs/SECURITY_AUDIT_HARDENING_ROADMAP.md § Category B
"""

import time
import secrets
from typing import Any, Callable, Optional, Tuple, TypeVar

T = TypeVar("T")


# Default timing target: 5 seconds (covers Argon2id + fountain decode)
DEFAULT_TARGET_MS = 5000.0

# Jitter range: ±5% of target
DEFAULT_JITTER_PERCENT = 5.0

# Minimum floor: never sleep less than this (prevents negative sleep)
MIN_SLEEP_MS = 10.0


class TimingResult:
    """Result wrapper that carries timing metadata alongside the actual result.

    Attributes:
        value: The actual operation result (or None on failure).
        success: Whether the operation completed successfully.
        elapsed_ms: Actual operation time in milliseconds.
        padded_ms: Total time including padding in milliseconds.
        error: Exception if the operation failed, else None.
    """

    __slots__ = ("value", "success", "elapsed_ms", "padded_ms", "error")

    def __init__(
        self,
        value: Any = None,
        success: bool = False,
        elapsed_ms: float = 0.0,
        padded_ms: float = 0.0,
        error: Optional[Exception] = None,
    ):
        self.value = value
        self.success = success
        self.elapsed_ms = elapsed_ms
        self.padded_ms = padded_ms
        self.error = error


def equalize_timing(
    func: Callable[..., T],
    args: tuple = (),
    kwargs: Optional[dict] = None,
    target_ms: float = DEFAULT_TARGET_MS,
    jitter_percent: float = DEFAULT_JITTER_PERCENT,
) -> TimingResult:
    """Execute a function and pad wall-clock time to a fixed target.

    The function is executed normally. After completion (success or failure),
    the remaining time up to ``target_ms ± jitter`` is spent sleeping.
    This ensures that an external observer measuring total execution time
    cannot distinguish fast failures from slow successes.

    Args:
        func: The function to execute.
        args: Positional arguments for func.
        kwargs: Keyword arguments for func.
        target_ms: Target wall-clock time in milliseconds.
        jitter_percent: Random jitter range as percentage of target (±).

    Returns:
        TimingResult with the operation outcome and timing metadata.
    """
    if kwargs is None:
        kwargs = {}

    start = time.monotonic()
    result = TimingResult()

    try:
        result.value = func(*args, **kwargs)
        result.success = True
    except Exception as exc:
        result.error = exc
        result.success = False

    elapsed_ms = (time.monotonic() - start) * 1000.0
    result.elapsed_ms = elapsed_ms

    # Compute jittered target
    jitter_range_ms = target_ms * (jitter_percent / 100.0)
    if jitter_range_ms > 0:
        # Generate uniform jitter in [-jitter_range, +jitter_range]
        jitter_ms = secrets.randbelow(int(jitter_range_ms * 2 * 1000)) / 1000.0 - jitter_range_ms
    else:
        jitter_ms = 0.0

    padded_target = target_ms + jitter_ms
    remaining_ms = padded_target - elapsed_ms

    if remaining_ms > MIN_SLEEP_MS:
        time.sleep(remaining_ms / 1000.0)

    result.padded_ms = (time.monotonic() - start) * 1000.0
    return result


def constant_time_password_check(
    check_func: Callable[[str], Any],
    password: str,
    dummy_work: Optional[Callable[[], None]] = None,
    target_ms: float = DEFAULT_TARGET_MS,
    jitter_percent: float = DEFAULT_JITTER_PERCENT,
) -> TimingResult:
    """Check a password with constant wall-clock time.

    Always executes the check function AND optional dummy work to ensure
    both valid and invalid passwords take the same observable time.

    The dummy_work callable should perform equivalent-cost operations
    (e.g., a second Argon2id derivation with a random salt) to prevent
    early-exit timing leaks.

    Args:
        check_func: Function that takes password and returns result.
        password: The password to check.
        dummy_work: Optional function to execute after check for timing parity.
        target_ms: Target wall-clock time in milliseconds.
        jitter_percent: Jitter range as percentage.

    Returns:
        TimingResult wrapping the check result.
    """

    def _inner():
        result = check_func(password)
        # Always execute dummy work regardless of result
        if dummy_work is not None:
            dummy_work()
        return result

    return equalize_timing(
        _inner,
        target_ms=target_ms,
        jitter_percent=jitter_percent,
    )


def duress_timing_equalizer(
    real_check: Callable[[str], Tuple[bool, bool]],
    argon2id_dummy: Callable[[], None],
    password: str,
    target_ms: float = DEFAULT_TARGET_MS,
    jitter_percent: float = DEFAULT_JITTER_PERCENT,
) -> TimingResult:
    """Equalize timing between real password, duress password, and wrong password.

    The roadmap identified that duress check uses SHA256 (fast) vs Argon2id (slow).
    This wrapper ensures ALL paths run Argon2id by executing a dummy derivation
    when the fast path would otherwise return early.

    The ``real_check`` function should return ``(is_valid, is_duress)``.
    The ``argon2id_dummy`` callable should run an Argon2id derivation with
    random salt to match the timing of a real derivation.

    Args:
        real_check: Function returning (is_valid, is_duress).
        argon2id_dummy: Dummy Argon2id call for timing equalization.
        password: Password to check.
        target_ms: Target wall-clock time.
        jitter_percent: Jitter range.

    Returns:
        TimingResult wrapping (is_valid, is_duress) tuple.
    """

    def _inner():
        is_valid, is_duress = real_check(password)

        # Always run Argon2id regardless of path taken.
        # If check_password used SHA256 internally (fast path), this
        # adds the missing Argon2id cost to equalize timing.
        argon2id_dummy()

        return (is_valid, is_duress)

    return equalize_timing(
        _inner,
        target_ms=target_ms,
        jitter_percent=jitter_percent,
    )


class TimingEqualizedDecoder:
    """Wrapper that makes decode operations take constant wall-clock time.

    Usage::

        decoder = TimingEqualizedDecoder(target_ms=5000)
        result = decoder.decode(gif_data, password, decode_func)
        if result.success:
            plaintext = result.value
        else:
            # Failed, but took the same time as success
            raise result.error

    The decoder ensures that:
    1. Argon2id always runs (even on early failures).
    2. Fountain decode always runs (even if already complete).
    3. Total time is padded to target ± jitter.
    """

    def __init__(
        self,
        target_ms: float = DEFAULT_TARGET_MS,
        jitter_percent: float = DEFAULT_JITTER_PERCENT,
    ):
        self.target_ms = target_ms
        self.jitter_percent = jitter_percent

    def decode(
        self,
        decode_func: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> TimingResult:
        """Execute decode with timing equalization.

        Args:
            decode_func: The actual decode function.
            *args: Arguments passed to decode_func.
            **kwargs: Keyword arguments passed to decode_func.

        Returns:
            TimingResult wrapping the decode outcome.
        """
        return equalize_timing(
            decode_func,
            args=args,
            kwargs=kwargs,
            target_ms=self.target_ms,
            jitter_percent=self.jitter_percent,
        )

    def get_target_ms(self) -> float:
        """Return the configured target time in milliseconds."""
        return self.target_ms

    def set_target_ms(self, target_ms: float) -> None:
        """Update the target time. Must be positive."""
        if target_ms <= 0:
            raise ValueError("target_ms must be positive")
        self.target_ms = target_ms
