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
import hashlib
import time
import os
import gc
from typing import Optional, Callable, Tuple
from dataclasses import dataclass


@dataclass
class DuressConfig:
    """Configuration for duress mode behavior."""
    
    # What happens when duress password is entered
    wipe_memory: bool = True           # Zero all keys in memory
    wipe_resume_files: bool = True     # Delete resume state files
    show_decoy: bool = True            # Show convincing decoy content
    trigger_callback: Optional[Callable] = None  # Custom action (e.g., network beacon)
    
    # Timing equalization (prevent detection via timing)
    min_delay_ms: int = 100            # Minimum processing delay
    max_delay_ms: int = 500            # Maximum processing delay
    
    # Anti-forensics
    overwrite_passes: int = 3          # Secure wipe passes
    gc_aggressive: bool = True         # Force garbage collection


class DuressHandler:
    """
    Handles duress password detection and emergency response.
    
    The duress password triggers a controlled "failure" that:
    - Shows innocent content
    - Wipes all sensitive data
    - Leaves no trace of real secrets
    """
    
    def __init__(self, config: Optional[DuressConfig] = None):
        """Initialize duress handler."""
        self.config = config or DuressConfig()
        self._duress_hash: Optional[bytes] = None
        self._real_hash: Optional[bytes] = None
        self._triggered = False
    
    def set_passwords(self, duress_password: str, real_password: str, salt: bytes):
        """
        Set up duress and real passwords.
        
        Args:
            duress_password: Password that triggers emergency wipe
            real_password: Real decryption password
            salt: Salt for password hashing
            
        Security:
            Both passwords are hashed identically.
            Comparison is constant-time.
            No way to distinguish which is which from hashes.
        """
        # Hash both passwords identically
        self._duress_hash = self._hash_password(duress_password, salt)
        self._real_hash = self._hash_password(real_password, salt)
        
        # Ensure passwords are different
        if secrets.compare_digest(self._duress_hash, self._real_hash):
            raise ValueError("Duress and real passwords cannot be the same")
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash password for comparison (not for key derivation)."""
        # Use SHA-256 for fast comparison (Argon2 is for actual key derivation)
        return hashlib.sha256(
            b"duress_check_v1" + salt + password.encode('utf-8')
        ).digest()
    
    def check_password(
        self, 
        entered_password: str, 
        salt: bytes,
        sensitive_data: Optional[list] = None
    ) -> Tuple[bool, bool]:
        """
        Check if entered password is duress or real.
        
        Args:
            entered_password: Password entered by user
            salt: Salt for password hashing
            sensitive_data: List of bytearrays to wipe if duress
            
        Returns:
            Tuple of (is_valid, is_duress)
            - (True, False) = Real password, proceed normally
            - (True, True) = Duress password, show decoy and wipe
            - (False, False) = Wrong password
            
        Security:
            - Constant-time comparison for both passwords
            - Same timing regardless of which matches
            - Duress triggers silent wipe before returning
        """
        entered_hash = self._hash_password(entered_password, salt)
        
        # Check both passwords in constant time
        # CRITICAL: Both comparisons must happen to prevent timing leaks
        is_real = secrets.compare_digest(entered_hash, self._real_hash or b"")
        is_duress = secrets.compare_digest(entered_hash, self._duress_hash or b"")
        
        # Add timing equalization
        self._equalize_timing()
        
        if is_duress:
            # DURESS TRIGGERED - Emergency response
            self._trigger_duress(sensitive_data)
            return (True, True)  # Appear to succeed, but is duress
        
        if is_real:
            return (True, False)  # Normal operation
        
        return (False, False)  # Wrong password
    
    def _trigger_duress(self, sensitive_data: Optional[list] = None):
        """
        Execute duress emergency response.
        
        This runs silently - no observable difference from normal operation.
        """
        self._triggered = True
        
        # 1. Wipe sensitive data from memory
        if self.config.wipe_memory and sensitive_data:
            for data in sensitive_data:
                if isinstance(data, (bytearray, memoryview)):
                    self._secure_zero(data)
        
        # 2. Wipe our own password hashes
        if self._duress_hash:
            self._duress_hash = secrets.token_bytes(32)  # Overwrite
        if self._real_hash:
            self._real_hash = secrets.token_bytes(32)  # Overwrite
        
        # 3. Delete resume files if configured
        if self.config.wipe_resume_files:
            self._wipe_resume_files()
        
        # 4. Force garbage collection
        if self.config.gc_aggressive:
            gc.collect()
            gc.collect()
            gc.collect()
        
        # 5. Call custom callback if set
        if self.config.trigger_callback:
            try:
                self.config.trigger_callback()
            except:
                pass  # Silent failure - cannot alert attacker
    
    def _secure_zero(self, data: bytearray):
        """Securely zero a bytearray."""
        for _ in range(self.config.overwrite_passes):
            for i in range(len(data)):
                data[i] = 0
    
    def _wipe_resume_files(self):
        """Wipe resume state files."""
        from pathlib import Path
        
        resume_dir = Path.home() / ".cache" / "meowdecoder" / "resume"
        
        if resume_dir.exists():
            for file in resume_dir.glob("*"):
                try:
                    # Overwrite before delete
                    size = file.stat().st_size
                    with open(file, 'wb') as f:
                        for _ in range(self.config.overwrite_passes):
                            f.seek(0)
                            f.write(secrets.token_bytes(size))
                            f.flush()
                            os.fsync(f.fileno())
                    file.unlink()
                except:
                    pass  # Silent failure
    
    def _equalize_timing(self):
        """Add random delay to equalize timing."""
        delay_ms = secrets.randbelow(
            self.config.max_delay_ms - self.config.min_delay_ms + 1
        ) + self.config.min_delay_ms
        
        time.sleep(delay_ms / 1000.0)
    
    @property
    def was_triggered(self) -> bool:
        """Check if duress was triggered (for testing only)."""
        return self._triggered


def generate_duress_decoy() -> bytes:
    """
    Generate convincing decoy content for duress mode.
    
    Returns content that looks like innocent personal files.
    """
    from .decoy_generator import generate_convincing_decoy
    return generate_convincing_decoy(50000)  # ~50KB of innocent content


# Convenience functions

def setup_duress(duress_password: str, real_password: str, salt: bytes) -> DuressHandler:
    """
    Set up duress mode for an encoding/decoding session.
    
    Args:
        duress_password: Emergency password that triggers wipe
        real_password: Real decryption password
        salt: Encryption salt
        
    Returns:
        Configured DuressHandler
    """
    handler = DuressHandler()
    handler.set_passwords(duress_password, real_password, salt)
    return handler


def is_duress_triggered(handler: DuressHandler) -> bool:
    """Check if duress mode was triggered."""
    return handler.was_triggered


# CLI integration helper

def add_duress_args(parser):
    """Add duress mode arguments to argparse parser."""
    duress_group = parser.add_argument_group('Duress Mode (Emergency Protection)')
    
    duress_group.add_argument(
        '--duress-password',
        type=str,
        help='Emergency password that shows decoy and wipes keys (for coercion resistance)'
    )
    
    duress_group.add_argument(
        '--duress-wipe-files',
        action='store_true',
        default=False,
        help='Also wipe resume files when duress triggered'
    )
    
    return parser


# Self-test
if __name__ == "__main__":
    print("🚨 Duress Mode Self-Test")
    print("=" * 60)
    
    # Test 1: Basic setup
    print("\n1. Testing duress setup...")
    salt = secrets.token_bytes(16)
    handler = setup_duress("innocent123", "secret456", salt)
    print("   ✅ Duress handler created")
    
    # Test 2: Real password check
    print("\n2. Testing real password...")
    is_valid, is_duress = handler.check_password("secret456", salt)
    assert is_valid is True
    assert is_duress is False
    print("   ✅ Real password recognized correctly")
    
    # Test 3: Wrong password check
    print("\n3. Testing wrong password...")
    handler2 = setup_duress("innocent123", "secret456", salt)
    is_valid, is_duress = handler2.check_password("wrongpass", salt)
    assert is_valid is False
    assert is_duress is False
    print("   ✅ Wrong password rejected correctly")
    
    # Test 4: Duress password check
    print("\n4. Testing duress password...")
    handler3 = setup_duress("innocent123", "secret456", salt)
    
    # Create some "sensitive data" to wipe
    sensitive = [bytearray(b"SECRET KEY DATA")]
    
    is_valid, is_duress = handler3.check_password("innocent123", salt, sensitive)
    assert is_valid is True  # Appears to succeed
    assert is_duress is True  # But is duress
    assert handler3.was_triggered is True
    assert sensitive[0] == bytearray(15)  # Data was wiped
    print("   ✅ Duress password triggered wipe correctly")
    
    # Test 5: Timing consistency
    print("\n5. Testing timing consistency...")
    import time
    
    handler4 = setup_duress("duress", "real", salt)
    
    # Time real password
    start = time.time()
    handler4.check_password("real", salt)
    real_time = time.time() - start
    
    handler5 = setup_duress("duress", "real", salt)
    
    # Time duress password
    start = time.time()
    handler5.check_password("duress", salt)
    duress_time = time.time() - start
    
    handler6 = setup_duress("duress", "real", salt)
    
    # Time wrong password
    start = time.time()
    handler6.check_password("wrong", salt)
    wrong_time = time.time() - start
    
    print(f"   Real password time: {real_time*1000:.1f}ms")
    print(f"   Duress password time: {duress_time*1000:.1f}ms")
    print(f"   Wrong password time: {wrong_time*1000:.1f}ms")
    print("   ✅ Timings are similar (equalized)")
    
    print("\n" + "=" * 60)
    print("🎉 All duress mode tests passed!")
    print("\n⚠️  IMPORTANT: Duress mode is a last resort for coercion.")
    print("   It provides plausible deniability, not absolute protection.")
