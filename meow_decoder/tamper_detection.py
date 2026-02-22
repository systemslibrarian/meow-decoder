"""
Tamper Detection + Silent Poisoning Module.

Provides active integrity monitoring with silent poison output on tampering.
Security Invariant: Tampered binaries must never produce valid output that
an adversary could use against the user.

Key features:
- Runtime integrity verification of critical module hashes
- Silent mode: Returns plausible-looking but cryptographically useless output
- Checkpoint file with HMAC-protected state
- Detects modification to:
  * Python source files
  * Compiled .pyc files
  * Rust shared libraries
  * Configuration files
- Cross-platform (Windows, Linux, macOS)

SECURITY NOTE: This is defense-in-depth. An attacker with full code execution
can disable this module. The goal is to catch casual tampering and make
forensic analysis harder.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "TamperDetector",
    "TamperState",
    "compute_file_hash",
    "compute_module_hashes",
    "silent_poison_bytes",
    "get_tamper_detector",
    "CRITICAL_MODULES",
]

# Critical modules to monitor (relative to meow_decoder package)
CRITICAL_MODULES = [
    "crypto.py",
    "crypto_enhanced.py",
    "fountain.py",
    "encode.py",
    "decode_gif.py",
    "forward_secrecy.py",
    "x25519_forward_secrecy.py",
    "pq_hybrid.py",
    "ratchet.py",
    "memory_guard.py",
    "constant_time.py",
    "forensic_cleanup.py",
    "secure_temp.py",
    "shamir_split.py",
]

# Rust library names by platform
RUST_LIB_NAMES = {
    "Linux": "libmeow_crypto_rs.so",
    "Darwin": "libmeow_crypto_rs.dylib",
    "Windows": "meow_crypto_rs.dll",
}


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file. Returns empty string if file doesn't exist."""
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, IOError):
        return ""


def compute_module_hashes(package_dir: Optional[Path] = None) -> Dict[str, str]:
    """
    Compute hashes of all critical modules.

    Args:
        package_dir: Directory containing meow_decoder package.
                     If None, auto-detect from this module's location.

    Returns:
        Dict mapping module name to SHA-256 hash.
    """
    if package_dir is None:
        package_dir = Path(__file__).parent

    hashes: Dict[str, str] = {}

    # Hash Python modules
    for module in CRITICAL_MODULES:
        module_path = package_dir / module
        if module_path.exists():
            hashes[module] = compute_file_hash(module_path)

    # Hash Rust library if present
    system = platform.system()
    lib_name = RUST_LIB_NAMES.get(system)
    if lib_name:
        # Check common locations
        for search_dir in [
            package_dir,
            package_dir.parent / "target" / "release",
            package_dir.parent / "target" / "debug",
            package_dir.parent / "crypto_core" / "pkg",
        ]:
            lib_path = search_dir / lib_name
            if lib_path.exists():
                hashes[f"rust:{lib_name}"] = compute_file_hash(lib_path)
                break

    return hashes


def silent_poison_bytes(length: int, seed: Optional[bytes] = None) -> bytes:
    """
    Generate cryptographically plausible but useless poison bytes.

    The output looks like random encrypted data but:
    - Has no relationship to any actual secret
    - Cannot be decrypted to anything meaningful
    - Is deterministic if seed is provided (for testing)

    Args:
        length: Number of bytes to generate.
        seed: Optional seed for deterministic output.

    Returns:
        Poison bytes that look encrypted but are useless.
    """
    if seed is not None:
        # Deterministic for testing
        hasher = hashlib.sha256(seed)
        result = bytearray()
        counter = 0
        while len(result) < length:
            hasher.update(struct.pack("<Q", counter))
            result.extend(hasher.digest())
            counter += 1
        return bytes(result[:length])
    else:
        # Use CSPRNG for production
        return secrets.token_bytes(length)


@dataclass
class TamperState:
    """
    Persistent tamper detection state.

    Stored in a checkpoint file with HMAC protection.
    """

    # Module hashes at initialization time
    baseline_hashes: Dict[str, str] = field(default_factory=dict)

    # Timestamp of baseline creation
    baseline_timestamp: float = 0.0

    # Number of tamper events detected
    tamper_count: int = 0

    # Last tamper detection timestamp
    last_tamper_time: float = 0.0

    # Modules that have been tampered with
    tampered_modules: List[str] = field(default_factory=list)

    # Secret key for state HMAC (regenerated each session)
    state_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def compute_state_hmac(self) -> bytes:
        """Compute HMAC of state for integrity verification."""
        state_data = json.dumps({
            "baseline_hashes": self.baseline_hashes,
            "baseline_timestamp": self.baseline_timestamp,
            "tamper_count": self.tamper_count,
            "last_tamper_time": self.last_tamper_time,
            "tampered_modules": self.tampered_modules,
        }, sort_keys=True).encode()
        return hmac.new(self.state_key, state_data, hashlib.sha256).digest()

    def to_bytes(self) -> bytes:
        """Serialize state with HMAC protection."""
        state_data = json.dumps({
            "baseline_hashes": self.baseline_hashes,
            "baseline_timestamp": self.baseline_timestamp,
            "tamper_count": self.tamper_count,
            "last_tamper_time": self.last_tamper_time,
            "tampered_modules": self.tampered_modules,
        }, sort_keys=True).encode()

        mac = hmac.new(self.state_key, state_data, hashlib.sha256).digest()

        # Format: key (32) + mac (32) + length (4) + data
        return (
            self.state_key +
            mac +
            struct.pack("<I", len(state_data)) +
            state_data
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["TamperState"]:
        """Deserialize state with HMAC verification."""
        if len(data) < 68:  # 32 + 32 + 4
            return None

        try:
            state_key = data[:32]
            stored_mac = data[32:64]
            length = struct.unpack("<I", data[64:68])[0]

            if len(data) < 68 + length:
                return None

            state_data = data[68:68 + length]

            # Verify HMAC
            computed_mac = hmac.new(state_key, state_data, hashlib.sha256).digest()
            if not hmac.compare_digest(stored_mac, computed_mac):
                return None

            state_dict = json.loads(state_data.decode())

            return cls(
                baseline_hashes=state_dict["baseline_hashes"],
                baseline_timestamp=state_dict["baseline_timestamp"],
                tamper_count=state_dict["tamper_count"],
                last_tamper_time=state_dict["last_tamper_time"],
                tampered_modules=state_dict["tampered_modules"],
                state_key=state_key,
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None


class TamperDetector:
    """
    Active tamper detection with silent poisoning.

    Usage:
        detector = TamperDetector()
        detector.initialize_baseline()

        # In encryption/decryption operations:
        if detector.is_tampered():
            # Return poison output instead of real data
            return detector.poison_output(expected_length)
    """

    def __init__(
        self,
        package_dir: Optional[Path] = None,
        checkpoint_file: Optional[Path] = None,
        auto_initialize: bool = True,
    ):
        """
        Initialize tamper detector.

        Args:
            package_dir: Directory containing meow_decoder package.
            checkpoint_file: File to store persistent state.
            auto_initialize: If True, initialize baseline on first run.
        """
        self.package_dir = package_dir or Path(__file__).parent

        if checkpoint_file is None:
            # Store in user's app data directory
            if platform.system() == "Windows":
                app_data = Path(os.environ.get("LOCALAPPDATA", ""))
                if not app_data.exists():
                    app_data = Path.home() / "AppData" / "Local"
            else:
                app_data = Path.home() / ".local" / "share"

            checkpoint_dir = app_data / "meow_decoder"
            checkpoint_dir.mkdir(parents=True, exist_ok=True)
            self.checkpoint_file = checkpoint_dir / ".tamper_state"
        else:
            self.checkpoint_file = checkpoint_file

        self.state: Optional[TamperState] = None
        self._tampered = False
        self._tamper_hooks: List[Callable[[str], None]] = []

        # Try to load existing state
        self._load_state()

        if self.state is None and auto_initialize:
            self.initialize_baseline()

    def _load_state(self) -> None:
        """Load state from checkpoint file."""
        if self.checkpoint_file.exists():
            try:
                data = self.checkpoint_file.read_bytes()
                self.state = TamperState.from_bytes(data)
            except (OSError, IOError):
                self.state = None

    def _save_state(self) -> None:
        """Save state to checkpoint file."""
        if self.state is not None:
            try:
                self.checkpoint_file.write_bytes(self.state.to_bytes())
            except (OSError, IOError):
                pass  # Silent failure - don't reveal tamper detection

    def initialize_baseline(self, force: bool = False) -> None:
        """
        Initialize baseline hashes for all critical modules.

        Args:
            force: If True, reinitialize even if baseline exists.
        """
        if self.state is not None and not force:
            return

        hashes = compute_module_hashes(self.package_dir)

        self.state = TamperState(
            baseline_hashes=hashes,
            baseline_timestamp=time.time(),
        )

        self._save_state()

    def check_integrity(self) -> Tuple[bool, List[str]]:
        """
        Check integrity of all monitored modules.

        Returns:
            Tuple of (integrity_ok, list_of_tampered_modules)
        """
        if self.state is None:
            return (False, ["<no baseline>"])

        current_hashes = compute_module_hashes(self.package_dir)
        tampered: List[str] = []

        for module, baseline_hash in self.state.baseline_hashes.items():
            current_hash = current_hashes.get(module, "")

            # Module was deleted or modified
            if current_hash != baseline_hash:
                tampered.append(module)

        # Check for new modules that weren't in baseline
        for module in current_hashes:
            if module not in self.state.baseline_hashes:
                # New module added - could be injection
                tampered.append(f"+{module}")

        if tampered:
            self._tampered = True
            self.state.tamper_count += 1
            self.state.last_tamper_time = time.time()
            self.state.tampered_modules = list(set(
                self.state.tampered_modules + tampered
            ))
            self._save_state()

            # Call tamper hooks
            for hook in self._tamper_hooks:
                try:
                    for module in tampered:
                        hook(module)
                except Exception:
                    pass  # Don't let hook failures reveal detection

        return (len(tampered) == 0, tampered)

    def is_tampered(self) -> bool:
        """
        Quick check if tampering has been detected.

        This caches the result to avoid repeated hash computations.
        Call check_integrity() to force a fresh check.
        """
        if self._tampered:
            return True

        ok, _ = self.check_integrity()
        return not ok

    def poison_output(
        self,
        length: int,
        deterministic: bool = False,
    ) -> bytes:
        """
        Generate poison output that looks like valid encrypted data.

        Call this instead of returning real output when tampering is detected.

        Args:
            length: Number of bytes to generate.
            deterministic: If True, use consistent seed (for testing).

        Returns:
            Cryptographically plausible poison bytes.
        """
        if deterministic:
            seed = b"meow_poison_seed" + struct.pack("<Q", length)
            return silent_poison_bytes(length, seed)
        else:
            return silent_poison_bytes(length)

    def add_tamper_hook(self, hook: Callable[[str], None]) -> None:
        """
        Add callback to be called when tampering is detected.

        The hook receives the name of the tampered module.
        Hooks should be silent - don't log or raise exceptions.
        """
        self._tamper_hooks.append(hook)

    def get_tamper_report(self) -> Dict:
        """
        Get detailed tamper report.

        WARNING: Only use for debugging. Don't expose to users in production
        as it reveals detection capabilities.
        """
        if self.state is None:
            return {"status": "uninitialized"}

        ok, tampered = self.check_integrity()

        return {
            "status": "ok" if ok else "TAMPERED",
            "baseline_timestamp": self.state.baseline_timestamp,
            "monitored_modules": len(self.state.baseline_hashes),
            "tamper_count": self.state.tamper_count,
            "tampered_modules": tampered,
            "historical_tampers": self.state.tampered_modules,
        }

    def reset(self) -> None:
        """Reset tamper state and reinitialize baseline."""
        self._tampered = False
        if self.checkpoint_file.exists():
            try:
                self.checkpoint_file.unlink()
            except (OSError, IOError):
                pass
        self.state = None
        self.initialize_baseline()


# Global singleton
_global_detector: Optional[TamperDetector] = None


def get_tamper_detector() -> TamperDetector:
    """Get the global tamper detector instance."""
    global _global_detector
    if _global_detector is None:
        _global_detector = TamperDetector()
    return _global_detector


def protect_function(func: Callable) -> Callable:
    """
    Decorator to protect a function with tamper detection.

    If tampering is detected, this decorator will raise a RuntimeError
    BEFORE the decorated function is executed, preventing any side effects.

    Usage:
        @protect_function
        def encrypt(data: bytes, password: str) -> bytes:
            ...
    """
    from functools import wraps

    detector = get_tamper_detector()
    # Eagerly check for tampering when the module is loaded and decorated
    if detector.is_tampered():
        raise RuntimeError(
            "Tampering detected during initial module load. "
            "Execution of protected functions is blocked."
        )

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Re-check at runtime in case of dynamic tampering
        if detector.is_tampered():
            raise RuntimeError("Tampering detected before function execution.")

        # If we passed the check, execute the real function
        return func(*args, **kwargs)

    return wrapper


# Self-integrity check on module load
def _self_check() -> None:
    """
    Perform self-integrity check on module load.

    This runs silently and sets internal tamper state.
    """
    try:
        detector = get_tamper_detector()
        # Silent check - don't reveal status
        detector.is_tampered()
    except Exception:
        pass  # Silent failure


# Don't run self-check during testing
if not os.environ.get("MEOW_TEST_MODE"):
    _self_check()
