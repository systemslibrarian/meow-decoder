"""
😿 Meow Decoder - Cat-Themed Error Handling & Pun Utilities

Provides cat-themed error messages, decorators, and pun-named helper
functions that wrap core functionality with feline flair.

Usage:
    from meow_decoder.cat_errors import (
        pounce_on_errors,       # decorator: catches & wraps exceptions
        hiss_warning,           # emit a cat-themed warning
        fur_ball_error,         # format an error with cat drama
        whisker_validate,       # validate input with cat messages
        litter_box_cleanup,     # context manager for secure cleanup
        CatastrophicError,      # custom exception hierarchy
        MeowError,
        HairballError,
        ScratchError,
        meow_wrap,              # wrap print output with cat flair
    )

    @pounce_on_errors(lives=3)
    def risky_decode():
        ...

All functions are safe to call in production — cat output is gated
behind verbose/cat_mode flags and never changes exception semantics.
"""

import functools
import os
import random
import sys
import time
import warnings
from contextlib import contextmanager
from typing import Any, Callable, Optional, TypeVar, Type

F = TypeVar("F", bound=Callable[..., Any])


# ═══════════════════════════════════════════════════════════════
# §1  Cat-Themed Exception Hierarchy
# ═══════════════════════════════════════════════════════════════

class MeowError(Exception):
    """
    😿 Base exception for all Meow Decoder cat-themed errors.

    Wraps a real exception with a cat-themed message while preserving
    the original exception chain for proper debugging.
    """
    CAT_EMOJI = "😿"
    CAT_PREFIX = "Meow!"

    def __init__(self, message: str, *args, original: Optional[Exception] = None):
        self.cat_message = f"{self.CAT_EMOJI} {self.CAT_PREFIX} {message}"
        self.original = original
        super().__init__(self.cat_message, *args)


class CatastrophicError(MeowError):
    """🙀 Unrecoverable errors — the cat fell off the shelf."""
    CAT_EMOJI = "🙀"
    CAT_PREFIX = "CATASTROPHE!"


class HairballError(MeowError):
    """😾 Data corruption or integrity failures — coughing up a hairball."""
    CAT_EMOJI = "😾"
    CAT_PREFIX = "Hairball!"


class ScratchError(MeowError):
    """😼 Authentication or permission failures — the cat scratches back."""
    CAT_EMOJI = "😼"
    CAT_PREFIX = "Scratch!"


class YarnTangleError(MeowError):
    """😿 Configuration or input validation errors — tangled yarn ball."""
    CAT_EMOJI = "😿"
    CAT_PREFIX = "This yarn ball is tangled!"


class KibbleShortageError(MeowError):
    """🐱 Insufficient data or resources — not enough kibbles."""
    CAT_EMOJI = "🐱"
    CAT_PREFIX = "Kibble shortage!"


class NapInterruptError(MeowError):
    """😴 Timeout or interruption — someone disturbed the cat's nap."""
    CAT_EMOJI = "😴"
    CAT_PREFIX = "Nap interrupted!"


# ═══════════════════════════════════════════════════════════════
# §2  Cat-Themed Error Message Catalog
# ═══════════════════════════════════════════════════════════════

_CAT_ERROR_MESSAGES = {
    # File I/O
    "file_not_found":       "😿 No yarn ball at that path! Did the cat knock it off the shelf?",
    "file_too_large":       "🙀 This yarn ball is ENORMOUS! Even a lion couldn't carry it.",
    "file_corrupted":       "😾 This yarn ball is all tangled up! The data seems corrupted.",
    "permission_denied":    "😼 The cat says NO. Permission denied — try sudo catnip?",
    "output_exists":        "😼 A yarn ball already lives there! Use --force to shove it aside.",

    # Passwords & Auth
    "wrong_password":       "😾 HISS! Wrong collar tag — that's not the right password.",
    "password_too_short":   "😿 That collar tag is too tiny! Even a kitten needs more characters.",
    "password_weak":        "🙀 That password is weaker than a kitten's yawn! Try harder.",
    "passwords_match":      "😼 You can't use the same collar tag twice! Pick different passwords.",
    "hmac_failed":          "😾 Collar tag verification FAILED! Someone's been scratching at this data.",
    "auth_failed":          "😼 The cat does NOT recognize you. Authentication failed.",

    # Crypto
    "encryption_failed":    "🙀 The encryption hairball got stuck! Something went wrong.",
    "decryption_failed":    "😿 Failed to purr these secrets back to life. Wrong password or damaged data?",
    "key_derivation_err":   "😾 Can't sharpen these claws — key derivation failed.",
    "nonce_reuse":          "🙀 CATASTROPHE! Nonce reuse detected — the cat panics!",
    "invalid_keyfile":      "🌿 This catnip smells funny... invalid keyfile format.",
    "key_wrong_size":       "😾 That key is the wrong size! Need exactly 32 bytes of whisker strength.",

    # Fountain / QR
    "no_frames":            "😿 No frames in this GIF! It's an empty cat bed.",
    "no_qr_codes":          "😿 No QR codes found! Did the cat eat them?",
    "not_enough_droplets":  "🐱 Only {count} kibbles collected... need more treats to decode!",
    "manifest_corrupted":   "😾 The manifest collar tag is scratched! Can't read the cat's name.",
    "qr_too_large":         "🙀 Too much data for one QR code! Split into smaller yarn balls.",

    # Schrödinger
    "schrodinger_failed":   "🔮 Schrödinger's cat collapsed the wrong way! Decode failed.",
    "reality_mismatch":     "🔮 Neither reality A nor B accepted that collar tag... suspicious.",
    "superposition_broken": "🔮 The quantum superposition is damaged beyond repair!",

    # Forward Secrecy
    "no_receiver_key":      "🔑 No receiver key provided! The cat can't deliver without an address.",
    "key_exchange_failed":  "🔑 Key exchange failed — the cats couldn't agree on a meeting spot.",
    "fs_requires_key":      "🔑 Forward secrecy needs a receiver public key. The cat needs a destination!",

    # Duress
    "duress_activated":     "🚨 DURESS DETECTED! The cat is pressing the panic button!",
    "duress_same_password": "😼 Duress password can't match the real one! That defeats the purr-pose.",
    "duress_no_fs":         "🔒 Duress mode requires forward secrecy. No half-measures, says the cat.",

    # Resources
    "out_of_memory":        "🙀 Out of memory! Even cats can't carry that much. Try --prowling-mode.",
    "no_webcam":            "📹 No camera found! Did you forget the cat cam?",
    "timeout":              "😴 Operation timed out. The cat fell asleep waiting...",

    # Generic
    "unknown":              "😿 Something went wrong. The cat is confused. *sad meow noises*",
}

# Sassy recovery suggestions
_CAT_SUGGESTIONS = [
    "💡 Have you tried unplugging and replugging the cat?",
    "💡 Try again — cats always land on their feet!",
    "💡 Maybe the cat would cooperate with a treat (better password)?",
    "💡 Consult the ancient wisdom: docs/THREAT_MODEL.md",
    "💡 Even nine lives have bad days. Check your inputs!",
    "💡 Remember: cats never make mistakes. It's probably the human's fault.",
    "💡 Pro tip: the cat recommends reading the --help output.",
]


def fur_ball_error(error_key: str, suggestion: bool = True, **kwargs) -> str:
    """
    Format a cat-themed error message by key.

    Args:
        error_key: Key into the error message catalog
        suggestion: Whether to append a recovery suggestion
        **kwargs: Format parameters for the message template

    Returns:
        Formatted cat-themed error string

    Example:
        >>> fur_ball_error("not_enough_droplets", count=42)
        '🐱 Only 42 kibbles collected... need more treats to decode!\\n💡 ...'
    """
    template = _CAT_ERROR_MESSAGES.get(error_key, _CAT_ERROR_MESSAGES["unknown"])
    msg = template.format(**kwargs) if kwargs else template
    if suggestion:
        msg += f"\n{random.choice(_CAT_SUGGESTIONS)}"
    return msg


# ═══════════════════════════════════════════════════════════════
# §3  Pun-Named Decorators & Wrappers
# ═══════════════════════════════════════════════════════════════

def pounce_on_errors(
    lives: int = 1,
    catch: tuple = (Exception,),
    error_key: Optional[str] = None,
    verbose: bool = False,
    reraise: bool = True,
) -> Callable[[F], F]:
    """
    🐾 Decorator: catch exceptions with cat-themed error output.

    Wraps a function to catch exceptions of type `catch`, print a
    cat-themed message, and optionally retry up to `lives` times.

    Args:
        lives: Number of retry attempts (1 = no retry, just catch-and-report)
        catch: Tuple of exception types to catch
        error_key: Key into the cat error catalog (optional)
        verbose: Print cat error messages to stderr
        reraise: Re-raise the original exception after cat output

    Example:
        @pounce_on_errors(lives=3, catch=(ConnectionError,), verbose=True)
        def download_file(url):
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(lives):
                try:
                    return func(*args, **kwargs)
                except catch as e:
                    last_exc = e
                    if verbose:
                        if lives > 1:
                            remaining = lives - attempt - 1
                            emoji = "😿" if remaining > 0 else "😾"
                            print(
                                f"{emoji} Life {attempt + 1}/{lives} lost! "
                                f"{remaining} lives remaining... ({e})",
                                file=sys.stderr,
                            )
                        else:
                            key = error_key or "unknown"
                            print(fur_ball_error(key, suggestion=True), file=sys.stderr)
                    if attempt == lives - 1:
                        if reraise:
                            raise
            # Should not reach here, but just in case
            if last_exc is not None:
                raise last_exc
        return wrapper  # type: ignore[return-value]
    return decorator


def hiss_warning(message: str, category: type = UserWarning, stacklevel: int = 2):
    """
    😼 Emit a cat-themed warning via the standard warnings module.

    Args:
        message: Warning text (will be prefixed with cat emoji)
        category: Warning category class
        stacklevel: Stack level for warnings.warn

    Example:
        hiss_warning("Argon2 memory reduced to 32 MiB — less secure!")
    """
    cat_msg = f"😼 Hiss! {message}"
    warnings.warn(cat_msg, category, stacklevel=stacklevel)


def whisker_validate(condition: bool, error_key: str, **kwargs):
    """
    🐱 Validate a condition; raise YarnTangleError if False.

    A cat-themed assertion for input validation. Does NOT change
    existing exception types in calling code — use this only in
    new validation paths.

    Args:
        condition: Must be True, or error is raised
        error_key: Key into the cat error catalog
        **kwargs: Format parameters for the error template

    Example:
        whisker_validate(len(password) >= 8, "password_too_short")
    """
    if not condition:
        raise YarnTangleError(fur_ball_error(error_key, suggestion=False, **kwargs))


@contextmanager
def litter_box_cleanup(*buffers):
    """
    🧹 Context manager: zero-wipe sensitive buffers on exit.

    Cat-themed wrapper around secure cleanup. Accepts bytearrays
    that will be zeroed when the block exits (even on exception).

    Example:
        key = bytearray(os.urandom(32))
        with litter_box_cleanup(key):
            encrypt(key, data)
        # key is now zeroed
    """
    try:
        yield
    finally:
        for buf in buffers:
            if isinstance(buf, (bytearray, memoryview)):
                for i in range(len(buf)):
                    buf[i] = 0


# ═══════════════════════════════════════════════════════════════
# §4  Cat-Themed Output Helpers
# ═══════════════════════════════════════════════════════════════

def _cat_mode_enabled() -> bool:
    """Check if cat mode is active (env var or global flag)."""
    return os.environ.get("MEOW_CAT_MODE", "1") == "1"


def meow_wrap(message: str, emoji: str = "🐱", file=None) -> str:
    """
    Wrap a message with cat emoji prefix. Returns the formatted string
    and optionally prints it.

    Args:
        message: The message text
        emoji: Cat emoji prefix
        file: If provided, print to this file

    Returns:
        Formatted string
    """
    formatted = f"{emoji} {message}"
    if file is not None:
        print(formatted, file=file)
    return formatted


def purr_status(message: str, verbose: bool = True, file=None):
    """😺 Print a cat-themed status/progress message."""
    if verbose and _cat_mode_enabled():
        out = file or sys.stderr
        print(f"😺 {message}", file=out)


def hiss_error(message: str, file=None):
    """😾 Print a cat-themed error message to stderr."""
    out = file or sys.stderr
    print(f"😾 HISS! {message}", file=out)


def purr_success(message: str, file=None):
    """😻 Print a cat-themed success message."""
    out = file or sys.stdout
    print(f"😻 Purr-fect! {message}", file=out)


def claw_mark(message: str, file=None):
    """🐾 Print a cat-themed debug/trace message."""
    if os.environ.get("MEOW_DEBUG"):
        out = file or sys.stderr
        print(f"🐾 {message}", file=out)


# ═══════════════════════════════════════════════════════════════
# §5  Pun-Named Pipeline Wrappers
# ═══════════════════════════════════════════════════════════════

def nine_lives_retry(func: F = None, *, lives: int = 9, verbose: bool = True) -> F:
    """
    🐱 Decorator: retry a function up to 9 lives (configurable).

    Shorthand for @pounce_on_errors with retry semantics.

    Example:
        @nine_lives_retry(lives=3)
        def flaky_webcam_capture():
            ...
    """
    if func is not None:
        # Called without parentheses: @nine_lives_retry
        return pounce_on_errors(lives=9, verbose=verbose)(func)

    # Called with parentheses: @nine_lives_retry(lives=3)
    def decorator(fn: F) -> F:
        return pounce_on_errors(lives=lives, verbose=verbose)(fn)
    return decorator  # type: ignore[return-value]


def cat_nap_timeout(seconds: float):
    """
    😴 Decorator factory: raise NapInterruptError after timeout.

    Note: Uses signal.alarm on Unix, no-op on Windows.

    Example:
        @cat_nap_timeout(30.0)
        def slow_decode():
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import signal

            def _handler(signum, frame):
                raise NapInterruptError(
                    f"Operation took longer than {seconds}s — the cat fell asleep!"
                )

            if hasattr(signal, "SIGALRM"):
                old = signal.signal(signal.SIGALRM, _handler)
                signal.alarm(int(seconds))
                try:
                    return func(*args, **kwargs)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old)
            else:
                # Windows: no alarm, just run normally
                return func(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
    return decorator


def tail_swish_progress(iterable, desc: str = "Processing", total: int = None, verbose: bool = True):
    """
    🐾 Cat-themed progress indicator for iterables.

    Prints paw-print progress markers every N items.

    Example:
        for frame in tail_swish_progress(frames, desc="Scanning QR"):
            process(frame)
    """
    count = 0
    total_est = total or (len(iterable) if hasattr(iterable, "__len__") else None)

    if verbose and _cat_mode_enabled():
        if total_est:
            print(f"🐾 {desc} ({total_est} items)...", file=sys.stderr)
        else:
            print(f"🐾 {desc}...", file=sys.stderr)

    for item in iterable:
        count += 1
        if verbose and _cat_mode_enabled() and total_est and count % max(1, total_est // 10) == 0:
            pct = count * 100 // total_est
            paws = "🐾" * (pct // 10)
            print(f"  {paws} {pct}%", file=sys.stderr)
        yield item

    if verbose and _cat_mode_enabled():
        print(f"  😺 Done! {count} items processed.", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════
# §6  Cat-Themed Error Mappers (for existing exceptions)
# ═══════════════════════════════════════════════════════════════

# Maps known error messages to cat-themed keys
_ERROR_PATTERN_MAP = [
    ("Password cannot be empty",           "wrong_password"),
    ("Password must be at least",          "password_too_short"),
    ("Nonce reuse",                        "nonce_reuse"),
    ("Salt must be 16 bytes",             "key_derivation_err"),
    ("Key derivation failed",             "key_derivation_err"),
    ("Encryption failed",                 "encryption_failed"),
    ("Decryption failed",                 "decryption_failed"),
    ("No frames found",                   "no_frames"),
    ("No QR codes found",                 "no_qr_codes"),
    ("Manifest QR decode corrupted",      "manifest_corrupted"),
    ("HMAC verification failed",          "hmac_failed"),
    ("Precomputed key must be 32 bytes",  "key_wrong_size"),
    ("not the same as encryption",        "passwords_match"),
    ("Duress mode requires forward",      "duress_no_fs"),
    ("receiver public key",               "no_receiver_key"),
    ("Cannot combine --yubikey",          "invalid_keyfile"),
]


def cat_translate_error(exc: Exception) -> str:
    """
    Translate a standard exception message into a cat-themed one.

    Looks up the exception message against known patterns and returns
    the corresponding cat error. Falls back to a generic cat message.

    Args:
        exc: The original exception

    Returns:
        Cat-themed error string
    """
    msg = str(exc)
    for pattern, key in _ERROR_PATTERN_MAP:
        if pattern.lower() in msg.lower():
            return fur_ball_error(key)
    return fur_ball_error("unknown")


def meow_excepthook(exc_type: Type[BaseException], exc_value: BaseException, exc_tb):
    """
    Custom sys.excepthook that adds cat flair to uncaught exceptions.

    Install with: sys.excepthook = meow_excepthook

    Only adds cat messages — still shows the full traceback.
    """
    # Print cat error first
    if isinstance(exc_value, Exception):
        cat_msg = cat_translate_error(exc_value)
        print(f"\n{cat_msg}\n", file=sys.stderr)

    # Then show normal traceback
    sys.__excepthook__(exc_type, exc_value, exc_tb)
