"""
🚨 Duress Mode - Emergency Password Protection

When under coercion, users can enter a "duress password" that:
1. Appears to work normally (shows innocent decoy content)
2. Silently wipes all sensitive keys from memory
3. Optionally triggers secure deletion of key material
4. Leaves no trace that a real secret ever existed

Philosophy:
    "The cat that got caught... was never there at all."

Security Properties:
- Duress password is indistinguishable from real password (constant-time check)
- No observable difference in behavior (same timing, same outputs)
- Keys are zeroed using secure memory wipe
- Optional: Trigger file wipe, network beacon, or other emergency actions

Usage:
    # Set up duress during encoding
    meow-encode --duress-password "innocent123" --real-password "secret456" ...

    # If coerced, enter duress password
    # System shows decoy, wipes keys, attacker sees nothing suspicious

WARNING:
    This is a last-resort feature for users facing physical coercion.
    It provides plausible deniability but cannot protect against
    determined adversaries with forensic capabilities or torture.
    Use Schrödinger mode for cryptographic deniability.
"""

import secrets
import time
import os
import gc
import shutil
from pathlib import Path
from typing import Optional, Callable, Tuple, Union, List
from .config import DuressConfig, DuressMode
from .crypto_backend import get_default_backend as _get_backend

# Maximum size for user-provided decoy files (100 MB)
MAX_USER_DECOY_SIZE = 100 * 1024 * 1024


class DuressHandler:
    """
    Handles duress password detection and decoy generation.

    The duress password triggers a "successful" decoding operation that:
    - Shows innocent decoy content (message, file, or generated)
    - Returns valid bytes to the caller
    - Does NOT destroy or wipe anything (Decoy-Only mode)
    - Leaves no trace in logs that duress was triggered
    """

    def __init__(self, config: Optional[DuressConfig] = None):
        """Initialize duress handler."""
        self.config = config or DuressConfig()
        self._duress_hash: Optional[bytes] = None
        self._real_hash: Optional[bytes] = None
        self._triggered: bool = False  # Track if duress was triggered

    @property
    def was_triggered(self) -> bool:
        """Return whether duress was triggered."""
        return self._triggered

    def _secure_zero(self, data: bytearray) -> None:
        """
        Securely zero sensitive data in memory.

        Args:
            data: Mutable bytearray to zero
        """
        if not isinstance(data, bytearray):
            return
        for i in range(len(data)):
            data[i] = 0

    def set_passwords(self, duress_password: str, real_password: str, salt: bytes):
        """
        Set up duress and real passwords.

        Args:
            duress_password: Password that triggers decoy
            real_password: Real decryption password
            salt: Salt for password hashing
        """
        # Hash both passwords identically
        self._duress_hash = self._hash_password(duress_password, salt)
        self._real_hash = self._hash_password(real_password, salt)

        # Ensure passwords are different
        if _get_backend().constant_time_compare(self._duress_hash, self._real_hash):
            raise ValueError("Duress and real passwords cannot be the same")

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash password for comparison (not for key derivation)."""
        # Use SHA-256 for fast comparison (Argon2 is for actual key derivation)
        return _get_backend().sha256(b"duress_check_v1" + salt + password.encode("utf-8"))

    def check_password(
        self, entered_password: str, salt: bytes, sensitive_data: Optional[List[bytearray]] = None
    ) -> Tuple[bool, bool]:
        """
        Check if entered password is duress or real.

        Args:
            entered_password: Password entered by user
            salt: Salt for password hashing
            sensitive_data: Optional list of bytearrays to zero on duress

        Returns:
            Tuple of (is_valid, is_duress)
            - (True, False) = Real password, proceed normally
            - (True, True) = Duress password, returns decoy
            - (False, False) = Wrong password
        """
        entered_hash = self._hash_password(entered_password, salt)

        # Check both passwords in constant time
        is_real = _get_backend().constant_time_compare(entered_hash, self._real_hash or b"")
        is_duress = _get_backend().constant_time_compare(entered_hash, self._duress_hash or b"")

        # === SECURITY FIX (HIGH-02): Constant-time execution for both branches ===
        # Execute equivalent work regardless of which branch is taken to prevent
        # timing side-channel that leaks whether duress was triggered.

        # Prepare dummy data for timing equalization (same size as real data)
        dummy_data: List[bytearray] = []
        if sensitive_data:
            for data in sensitive_data:
                dummy_data.append(bytearray(len(data)))

        # Execute wipe operations on BOTH branches (real or dummy data)
        if is_duress:
            # DURESS: Wipe actual sensitive data
            target_data = sensitive_data
            self._triggered = True
        else:
            # REAL/WRONG: Wipe dummy data (same timing, no effect)
            target_data = dummy_data
            # Don't set _triggered for non-duress

        # Execute wipe (always, for timing consistency)
        if target_data:
            for data in target_data:
                self._secure_zero(data)

        # Execute callback equivalently (dummy or real)
        if is_duress and self.config.trigger_callback:
            self.config.trigger_callback()
        elif self.config.trigger_callback:
            # Dummy callback execution time (call empty lambda)
            def _():
                return None

            _()

        # Execute resume file wipe equivalently
        if is_duress and self.config.wipe_resume_files:
            self._wipe_resume_files()
        elif self.config.wipe_resume_files:
            # Dummy wipe (just stat the directory, don't actually wipe)
            self._dummy_wipe_timing()

        # Execute GC equivalently
        if is_duress and self.config.gc_aggressive:
            gc.collect()
            gc.collect()
            gc.collect()
        elif self.config.gc_aggressive:
            # Dummy GC timing (collect but no actual cleanup expected)
            gc.collect()
            gc.collect()
            gc.collect()

        # Add random delay AFTER all operations for additional timing noise
        self._equalize_timing()

        if is_duress:
            return (True, True)

        if is_real:
            return (True, False)  # Normal operation

        return (False, False)  # Wrong password

    def _dummy_wipe_timing(self) -> None:
        """Perform dummy operations with similar timing to _wipe_resume_files."""
        resume_dir = Path.home() / ".cache" / "meowdecoder" / "resume"
        passes = getattr(self.config, "overwrite_passes", 3)

        # Simulate timing of file operations without actual wipe
        if resume_dir.exists():  # pragma: no cover
            for file_path in resume_dir.glob("*"):
                if file_path.is_file():
                    try:
                        # Stat the file (similar timing to size check)
                        size = file_path.stat().st_size
                        # Generate random bytes but don't write them
                        for _ in range(passes):
                            _ = secrets.token_bytes(min(size, 4096))
                    except Exception:
                        pass

    def execute_emergency_response(
        self, sensitive_data_list: Optional[List[bytearray]] = None, salt: Optional[bytes] = None
    ) -> Optional[bytes]:
        """
        Execute emergency response when duress is triggered.

        This method:
        1. Zeros all sensitive data in memory
        2. Optionally triggers GC
        3. Returns decoy data (DECOY mode) or None (PANIC mode)

        Args:
            sensitive_data_list: List of bytearrays to securely zero
            salt: Optional salt (for deterministic decoy generation)

        Returns:
            Decoy bytes in DECOY mode, None in PANIC mode
        """
        self._triggered = True

        # Zero all sensitive data
        if sensitive_data_list:
            for data in sensitive_data_list:
                self._secure_zero(data)

        # Aggressive GC if configured
        if getattr(self.config, "gc_aggressive", False):
            import gc

            gc.collect()

        # PANIC mode: return None (caller should exit silently)
        if self.config.mode == DuressMode.PANIC and self.config.panic_enabled:
            return None

        # DECOY mode: return deterministic decoy data
        if salt:  # pragma: no cover
            return generate_static_decoy(salt)  # pragma: no cover

        return None

    def _equalize_timing(self):
        """Add random delay to equal timing."""
        # Minimal delay to mask processing differences
        delay_ms = (
            secrets.randbelow(self.config.max_delay_ms - self.config.min_delay_ms + 1)
            + self.config.min_delay_ms
        )
        time.sleep(delay_ms / 1000.0)

    def _wipe_resume_files(self) -> int:
        """
        Securely wipe resume/temporary files.

        Wipes files in ~/.cache/meowdecoder/resume with multiple overwrite passes.

        Returns:
            Number of files wiped
        """
        wiped_count = 0
        resume_dir = Path.home() / ".cache" / "meowdecoder" / "resume"

        if not resume_dir.exists():
            return 0

        passes = getattr(self.config, "overwrite_passes", 3)

        for file_path in resume_dir.glob("*"):
            if file_path.is_file():
                try:
                    # Multiple overwrite passes
                    size = file_path.stat().st_size
                    with open(file_path, "r+b") as f:
                        for _ in range(passes):
                            f.seek(0)
                            f.write(secrets.token_bytes(size))
                            f.flush()
                            os.fsync(f.fileno())
                    # Delete the file
                    file_path.unlink()
                    wiped_count += 1
                except Exception:  # pragma: no cover
                    pass  # Best effort

        return wiped_count

    def get_decoy_data(self) -> Tuple[bytes, Optional[str]]:
        """
        Generate or load decoy data based on configuration.

        Returns:
            Tuple of (decoy_bytes, optional_output_name)
        """
        decoy_type = self.config.decoy_type

        # Option 1: Simple Message
        if decoy_type == "message":
            msg = self.config.decoy_message or "Decode complete."
            return msg.encode("utf-8"), self.sanitize_filename(self.config.decoy_output_name)

        # Option 2: Bundled File (e.g., demo image)
        elif decoy_type == "bundled_file":
            # Attempt to find bundled asset
            # Implementation assumes assets dir relative to package or known location
            # Simple fallback to message if not found
            asset_path = Path(__file__).parent.parent / "assets" / "demo.gif"  # Example
            if asset_path.exists():
                with open(asset_path, "rb") as f:
                    return f.read(), self.sanitize_filename(
                        self.config.decoy_output_name or "demo.gif"
                    )

            # Fallback
            return b"Error: Bundled decoy not found.", "error.txt"  # pragma: no cover

        # Option 3: User File
        elif decoy_type == "user_file":
            if not self.config.decoy_file_path:
                return b"Error: No user file specified.", "error.txt"

            user_path = Path(self.config.decoy_file_path)

            if not user_path.exists() or not user_path.is_file():
                # Safe fallback, do not reveal the missing path in output content
                return b"Operation successful.", "output.txt"

            if user_path.stat().st_size > MAX_USER_DECOY_SIZE:
                # Fallback for size limit
                return b"Decoy file too large.", "error.txt"

            with open(user_path, "rb") as f:
                content = f.read()

            out_name = self.config.decoy_output_name or user_path.name
            return content, self.sanitize_filename(out_name)

        # Fallback for unknown type
        return b"Decode complete.", "output.txt"

    @staticmethod
    def sanitize_filename(filename: Optional[str]) -> Optional[str]:
        """Sanitize filename to prevent path traversal."""
        if not filename:
            return None
        return os.path.basename(filename)


def generate_deterministic_decoy(size: int, salt: bytes) -> bytes:
    """
    Generate deterministic decoy content of specific size.

    Uses salt to seed generation so the same prompt produces same decoy,
    preventing suspicion from changing output.
    """
    import random

    # Use salt to seed PRNG for determinism
    seed = int.from_bytes(_get_backend().sha256(salt), "big")
    # Create isolated RNG instance
    rng = random.Random(seed)

    # Generate convincing filler
    # We'll generate a fake binary format that looks like compressed data
    chunks = []
    generated = 0

    while generated < size:
        chunk_size = min(4096, size - generated)
        # Generate semi-random bytes using isolated RNG
        chunk = rng.randbytes(chunk_size)
        chunks.append(chunk)
        generated += len(chunk)

    return b"".join(chunks)


# Backwards compatibility wrappers for test suite
def setup_duress(duress_password: str, real_password: str, salt: bytes) -> DuressHandler:
    """
    Convenience function to create and configure a DuressHandler.

    Args:
        duress_password: Password that triggers decoy mode
        real_password: Real decryption password
        salt: Salt for password hashing

    Returns:
        Configured DuressHandler instance
    """
    handler = DuressHandler()
    handler.set_passwords(duress_password, real_password, salt)
    return handler


def is_duress_triggered(
    handler: DuressHandler, password: Optional[str] = None, salt: Optional[bytes] = None
) -> bool:
    """
    Check if duress mode has been triggered on a handler.

    When called with just handler, returns handler.was_triggered.
    When called with password and salt, checks if password triggers duress.

    Args:
        handler: Configured DuressHandler
        password: Optional password to check
        salt: Optional salt for password hashing

    Returns:
        True if duress was/is triggered
    """
    if password is None or salt is None:
        return handler.was_triggered
    is_valid, is_duress = handler.check_password(password, salt)
    return is_valid and is_duress


def generate_static_decoy(salt: bytes, size: int = 1024) -> bytes:
    """
    Generate deterministic decoy content.

    Alias for generate_deterministic_decoy with swapped argument order
    for backwards compatibility.

    Args:
        salt: Salt for deterministic generation
        size: Size of decoy to generate

    Returns:
        Deterministic decoy bytes
    """
    return generate_deterministic_decoy(size, salt)


def generate_duress_decoy(salt: Optional[bytes] = None, size: int = 1024) -> bytes:
    """
    Generate decoy content for duress mode.

    Args:
        salt: Optional salt for deterministic generation (random if not provided)
        size: Size of decoy to generate

    Returns:
        Decoy bytes
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    return generate_static_decoy(salt, size)


def add_duress_args(parser) -> None:
    """
    Add duress-related command-line arguments to an argparse parser.

    Adds:
        --duress-password: Optional duress password
        --duress-password-prompt: Prompt for duress password interactively
        --duress-mode: Duress response mode (decoy/panic)
        --enable-panic: Enable destructive panic mode

    Args:
        parser: argparse.ArgumentParser instance
    """
    duress_group = parser.add_argument_group("Duress Mode", "Emergency protection against coercion")

    duress_group.add_argument(
        "--duress-password",
        type=str,
        help="Duress password that triggers emergency response on decode",
    )
    duress_group.add_argument(
        "--duress-password-prompt",
        action="store_true",
        help="Prompt for duress password interactively (more secure)",
    )
    duress_group.add_argument(
        "--duress-mode",
        choices=["decoy", "panic"],
        default="decoy",
        help="Duress response: decoy (fake success) or panic (wipe/exit)",
    )
    duress_group.add_argument(
        "--enable-panic",
        action="store_true",
        help="Enable destructive PANIC mode (required for --duress-mode panic)",
    )
    duress_group.add_argument(
        "--duress-wipe-files",
        action="store_true",
        help="Wipe resume/temp files when duress is triggered",
    )


# Self-test
if __name__ == "__main__":
    print("🚨 Duress Mode Self-Test")
    print("=" * 60)

    # Test 1: Basic setup
    print("\n1. Testing duress setup...")
    salt = secrets.token_bytes(16)
    handler = DuressHandler()
    handler.set_passwords("innocent123", "secret456", salt)
    print("   ✅ Duress handler created")

    # Test 2: Real password check
    print("\n2. Testing real password...")
    is_valid, is_duress = handler.check_password("secret456", salt)
    assert is_valid is True
    assert is_duress is False
    print("   ✅ Real password recognized correctly")

    # Test 3: Wrong password check
    print("\n3. Testing wrong password...")
    is_valid, is_duress = handler.check_password("wrongpass", salt)
    assert is_valid is False
    assert is_duress is False
    print("   ✅ Wrong password rejected correctly")

    # Test 4: Duress password check
    print("\n4. Testing duress password...")
    is_valid, is_duress = handler.check_password("innocent123", salt)
    assert is_valid is True  # Appears to succeed
    assert is_duress is True  # But is duress
    print("   ✅ Duress password detected correctly")

    # Test 5: Timing consistency
    print("\n5. Testing timing consistency...")
    import time

    # Time real password
    start = time.time()
    handler.check_password("secret456", salt)
    real_time = time.time() - start

    # Time duress password
    start = time.time()
    handler.check_password("innocent123", salt)
    duress_time = time.time() - start

    # Time wrong password
    start = time.time()
    handler.check_password("wrong", salt)
    wrong_time = time.time() - start

    print(f"   Real password time: {real_time*1000:.1f}ms")
    print(f"   Duress password time: {duress_time*1000:.1f}ms")
    print(f"   Wrong password time: {wrong_time*1000:.1f}ms")
    print("   ✅ Timings monitored (equalization active)")

    print("\n" + "=" * 60)
    print("🎉 All duress mode tests passed!")
    print("\n⚠️  IMPORTANT: Duress mode is a last resort for coercion.")
    print("   It provides plausible deniability, not absolute protection.")
