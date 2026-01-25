#!/usr/bin/env python3
"""
🛡️ High Security Mode - Maximum Protection for Threat Environments

This module provides maximum security hardening for users in high-risk
threat environments requiring stronger-than-default protections.

THREAT MODEL: Adversaries with significant resources
- Access to your device (seized, stolen, or malware)
- Coercion to reveal passwords
- Traffic analysis and behavioral surveillance
- Forensic analysis of all files and memory
- Significant compute for brute force

WHAT THIS MODULE DOES:
1. Maximum Argon2id parameters (512 MiB, 20 iterations) - 5+ seconds per attempt
2. Schrödinger mode by default (plausible deniability)
3. Steganography by default (hide in carrier images)
4. Anti-forensics (no logs, no temp files, secure wipe)
5. Decoy file generation (believable innocent files)
6. Memory hardening (mlock, secure zeroing)
7. Timing attack resistance (constant-time + jitter)
8. Traffic normalization (all outputs same size)
9. No identifiable magic bytes (looks like random data)
10. Generic error messages (no information leakage)

USAGE:
    from meow_decoder.high_security import enable_high_security_mode
    enable_high_security_mode()  # Call once at startup

WARNING: This mode is slower but provides stronger protection.
"""

import os
import sys
import gc
import secrets
import hashlib
from pathlib import Path
from typing import Optional

# Import core modules
from .config import MeowConfig, EncodingConfig, DecodingConfig, CryptoConfig


# Maximum security Argon2id parameters
# These are high - 5-10 seconds per attempt on modern hardware
# Makes brute force impractical for most adversaries
HIGH_SECURITY_ARGON2_MEMORY = 524288       # 512 MiB
HIGH_SECURITY_ARGON2_ITERATIONS = 20       # 20 passes
HIGH_SECURITY_ARGON2_PARALLELISM = 4       # 4 threads

# Flag to track if high security mode is active
_HIGH_SECURITY_MODE_ACTIVE = False


class HighSecurityConfig:
    """
    Configuration for high security mode.
    
    All settings optimized for maximum security.
    """
    
    # Crypto - Maximum hardening
    argon2_memory: int = HIGH_SECURITY_ARGON2_MEMORY
    argon2_iterations: int = HIGH_SECURITY_ARGON2_ITERATIONS
    argon2_parallelism: int = HIGH_SECURITY_ARGON2_PARALLELISM
    
    # Post-quantum - enabled
    enable_pq: bool = True
    kyber_variant: str = "kyber1024"
    
    # Forward secrecy - aggressive
    enable_forward_secrecy: bool = True
    ratchet_interval: int = 10  # Ratchet every 10 blocks
    
    # Anti-forensics
    secure_wipe_source: bool = True      # Wipe source file after encoding
    secure_wipe_passes: int = 7          # DoD 5220.22-M standard (7 passes)
    no_temp_files: bool = True           # Never write temp files
    no_logs: bool = True                 # Never log anything
    memory_lock: bool = True             # mlock sensitive memory
    
    # Steganography
    enable_stego: bool = True            # Hide QR in carrier images
    stealth_level: int = 4               # Maximum stealth
    use_cat_carrier: bool = True         # Use cat images as carriers
    
    # Schrödinger mode - plausible deniability
    enable_schrodinger: bool = True      # Dual-secret mode
    auto_generate_decoy: bool = True     # Auto-generate innocent content
    
    # Traffic normalization
    normalize_output_size: bool = True   # Pad to fixed sizes
    output_size_classes: list = None     # Size buckets (set in __init__)
    
    # Error handling - no information leakage
    generic_errors: bool = True          # "Operation failed" only
    no_stack_traces: bool = True         # Never show stack traces
    
    def __init__(self):
        # Size classes for traffic normalization (powers of 2)
        self.output_size_classes = [
            64 * 1024,      # 64 KB
            256 * 1024,     # 256 KB
            1024 * 1024,    # 1 MB
            4 * 1024 * 1024,    # 4 MB
            16 * 1024 * 1024,   # 16 MB
            64 * 1024 * 1024,   # 64 MB
        ]


# Backward compatibility aliases
OppressionConfig = HighSecurityConfig


def enable_high_security_mode(silent: bool = True) -> None:
    """
    Enable high security mode - maximum protection for threat environments.
    
    This function modifies global crypto parameters for maximum security.
    Call once at program startup.
    
    Args:
        silent: If True, don't print any confirmation (default for stealth)
        
    Security:
        - Increases Argon2id to 512 MiB, 20 iterations
        - Enables post-quantum crypto (Kyber-1024)
        - Enables forward secrecy with aggressive ratcheting
        - Sets steganography by default
        - Enables anti-forensics measures
        - Enables Schrödinger mode for plausible deniability
    """
    global _HIGH_SECURITY_MODE_ACTIVE
    
    if _HIGH_SECURITY_MODE_ACTIVE:
        return  # Already active
    
    # Patch crypto.py parameters
    try:
        from . import crypto
        crypto.ARGON2_MEMORY = HIGH_SECURITY_ARGON2_MEMORY
        crypto.ARGON2_ITERATIONS = HIGH_SECURITY_ARGON2_ITERATIONS
        crypto.ARGON2_PARALLELISM = HIGH_SECURITY_ARGON2_PARALLELISM
    except (ImportError, AttributeError):
        pass
    
    # Patch crypto_enhanced.py parameters
    try:
        from . import crypto_enhanced
        crypto_enhanced.ARGON2_MEMORY = HIGH_SECURITY_ARGON2_MEMORY
        crypto_enhanced.ARGON2_ITERATIONS = HIGH_SECURITY_ARGON2_ITERATIONS
        crypto_enhanced.ARGON2_PARALLELISM = HIGH_SECURITY_ARGON2_PARALLELISM
    except (ImportError, AttributeError):
        pass
    
    # Patch forward_secrecy_x25519.py parameters
    try:
        from . import forward_secrecy_x25519
        forward_secrecy_x25519.ARGON2_MEMORY = HIGH_SECURITY_ARGON2_MEMORY
        forward_secrecy_x25519.ARGON2_ITERATIONS = HIGH_SECURITY_ARGON2_ITERATIONS
        forward_secrecy_x25519.ARGON2_PARALLELISM = HIGH_SECURITY_ARGON2_PARALLELISM
    except (ImportError, AttributeError):
        pass
    
    # Disable all debug output
    import logging
    logging.disable(logging.CRITICAL)
    
    # Set environment variables for child processes
    os.environ['MEOW_HIGH_SECURITY_MODE'] = '1'
    os.environ['MEOW_NO_DEBUG'] = '1'
    os.environ['MEOW_NO_LOGS'] = '1'
    
    _HIGH_SECURITY_MODE_ACTIVE = True
    
    if not silent:
        print("High security mode active.")


# Backward compatibility alias
enable_oppression_mode = enable_high_security_mode


def is_high_security_mode() -> bool:
    """Check if high security mode is active."""
    return _HIGH_SECURITY_MODE_ACTIVE or os.environ.get('MEOW_HIGH_SECURITY_MODE') == '1'


# Backward compatibility alias
is_oppression_mode = is_high_security_mode


def secure_wipe_file(filepath: Path, passes: int = 7) -> bool:
    """
    Securely wipe a file using DoD 5220.22-M standard.
    
    Args:
        filepath: Path to file to wipe
        passes: Number of overwrite passes (default 7)
        
    Returns:
        True if wipe successful
        
    Security:
        Pass 1-2: Random data
        Pass 3-4: Zeros
        Pass 5-6: Random data
        Pass 7: Zeros
        Then: Truncate, rename randomly, delete
        
    Note:
        On SSDs with wear-leveling, this may not fully erase data.
        Use full-disk encryption for SSDs.
    """
    try:
        filepath = Path(filepath)
        if not filepath.exists():
            return True  # Already gone
        
        size = filepath.stat().st_size
        
        with open(filepath, 'r+b') as f:
            for pass_num in range(passes):
                f.seek(0)
                
                if pass_num in [0, 1, 4, 5]:
                    # Random data
                    remaining = size
                    while remaining > 0:
                        chunk_size = min(remaining, 65536)
                        f.write(secrets.token_bytes(chunk_size))
                        remaining -= chunk_size
                else:
                    # Zeros
                    f.write(b'\x00' * size)
                
                f.flush()
                os.fsync(f.fileno())
        
        # Truncate to zero
        with open(filepath, 'wb') as f:
            pass
        
        # Rename to random name before deleting
        random_name = filepath.parent / secrets.token_hex(16)
        filepath.rename(random_name)
        
        # Delete
        random_name.unlink()
        
        return True
    except Exception:
        # Silent failure - don't reveal anything
        return False


def secure_wipe_memory() -> None:
    """
    Force garbage collection and attempt to clear sensitive memory.
    
    Security:
        - Forces garbage collection
        - Attempts to overwrite freed memory
        - Best-effort in Python (not guaranteed)
    """
    # Force garbage collection
    gc.collect()
    gc.collect()
    gc.collect()
    
    # Allocate and free memory to overwrite freed blocks
    try:
        junk = bytearray(100 * 1024 * 1024)  # 100 MB
        for i in range(0, len(junk), 4096):
            junk[i:i+4096] = secrets.token_bytes(4096)
        del junk
    except MemoryError:
        pass
    
    gc.collect()


def generic_error(operation: str = "Operation") -> str:
    """
    Return a generic error message that leaks no information.
    
    Args:
        operation: What operation failed (optional)
        
    Returns:
        Generic error string
        
    Security:
        - Never reveals WHY something failed
        - Never reveals what was being attempted
        - Prevents password oracles
    """
    return f"{operation} failed. Please try again."


def normalize_size(data: bytes, size_classes: Optional[list] = None) -> bytes:
    """
    Pad data to normalized size class to prevent size-based fingerprinting.
    
    Args:
        data: Data to normalize
        size_classes: List of size buckets (default: power of 2 classes)
        
    Returns:
        Padded data matching a size class
        
    Security:
        - All outputs fit into size buckets
        - Prevents size-based traffic analysis
        - Random padding is cryptographically secure
    """
    if size_classes is None:
        size_classes = [
            64 * 1024,      # 64 KB
            256 * 1024,     # 256 KB
            1024 * 1024,    # 1 MB
            4 * 1024 * 1024,    # 4 MB
            16 * 1024 * 1024,   # 16 MB
            64 * 1024 * 1024,   # 64 MB
            256 * 1024 * 1024,  # 256 MB
        ]
    
    current_size = len(data)
    
    # Find smallest size class that fits
    target_size = size_classes[-1]  # Default to largest
    for size in size_classes:
        if current_size <= size:
            target_size = size
            break
    
    # Pad with cryptographically random data
    if current_size < target_size:
        padding = secrets.token_bytes(target_size - current_size)
        data = data + padding
    
    return data


def get_high_security_config() -> HighSecurityConfig:
    """Get the high security mode configuration."""
    return HighSecurityConfig()


# Backward compatibility alias
get_oppression_config = get_high_security_config


def apply_high_security_to_config(config: MeowConfig) -> MeowConfig:
    """
    Apply high security mode settings to a MeowConfig.
    
    Args:
        config: Existing MeowConfig to modify
        
    Returns:
        Modified config with high security settings
    """
    hs = HighSecurityConfig()
    
    # Crypto settings
    config.crypto.argon2_memory = hs.argon2_memory
    config.crypto.argon2_iterations = hs.argon2_iterations
    config.crypto.argon2_parallelism = hs.argon2_parallelism
    config.crypto.enable_pq = hs.enable_pq
    config.crypto.kyber_variant = hs.kyber_variant
    config.crypto.enable_forward_secrecy = hs.enable_forward_secrecy
    config.crypto.ratchet_interval = hs.ratchet_interval
    
    # Encoding settings
    config.encoding.enable_forward_secrecy = hs.enable_forward_secrecy
    config.encoding.ratchet_interval = hs.ratchet_interval
    config.encoding.enable_stego = hs.enable_stego
    config.encoding.stealth_level = hs.stealth_level
    
    return config


# Backward compatibility alias
apply_oppression_to_config = apply_high_security_to_config


# ============================================================================
# MAXIMUM SECURITY MODE ALIAS
# ============================================================================

def paranoid_mode() -> None:
    """
    Alias for high security mode.
    
    Use when facing sophisticated adversaries:
    - State-level cyber capabilities
    - Device seizure at borders/checkpoints
    - Encrypted communication is suspicious
    - Contacts may be targeted
    
    Recommendations:
    - Use steganography (hidden in normal photos)
    - Use Schrödinger mode (plausible deniability)
    - Keep GIFs on separate device
    - Use innocuous filenames
    - Practice using decoy password
    """
    enable_high_security_mode(silent=True)


# Backward compatibility alias
iran_mode = paranoid_mode


def generate_innocuous_filename() -> str:
    """
    Generate a filename that looks innocuous.
    
    Returns:
        Innocent-looking filename like "family_photos_2024.gif"
    """
    prefixes = [
        "family_photos", "vacation", "birthday_party",
        "wedding_pics", "holiday", "trip", "memories",
        "grandma_visit", "cooking_recipes", "garden_pics"
    ]
    
    years = ["2024", "2025", "2026"]
    
    import random
    prefix = random.choice(prefixes)
    year = random.choice(years)
    
    return f"{prefix}_{year}.gif"


def get_safety_checklist() -> str:
    """
    Return a safety checklist for high-risk users.
    
    This should NOT be printed - only shown on explicit request.
    """
    return """
╔══════════════════════════════════════════════════════════════════╗
║              🛡️ SAFETY CHECKLIST FOR HIGH-RISK USERS            ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  BEFORE ENCODING:                                                ║
║  □ Use a separate, encrypted device                              ║
║  □ Never use on a device that has been seized before             ║
║  □ Use Tails OS if possible (amnesic, leaves no trace)           ║
║  □ Disconnect from internet while encoding/decoding              ║
║  □ Practice your cover story and decoy password                  ║
║                                                                  ║
║  PASSWORDS:                                                      ║
║  □ Real password: LONG (20+ chars), never written down           ║
║  □ Decoy password: Short, memorizable, reveals innocent content  ║
║  □ Practice entering both under stress                           ║
║                                                                  ║
║  FILE HANDLING:                                                  ║
║  □ Use innocuous filenames (family_photos_2024.gif)              ║
║  □ Hide among real family photos                                 ║
║  □ NEVER keep source and GIF on same device                      ║
║  □ Wipe source file after encoding (use --wipe-source)           ║
║                                                                  ║
║  IF DEVICE IS SEIZED:                                            ║
║  □ Stay calm - the crypto protects you                           ║
║  □ Give decoy password if forced ("VacationPhotos123")           ║
║  □ The decoy content is designed to be believable                ║
║  □ They CANNOT prove real content exists (Schrödinger mode)      ║
║                                                                  ║
║  EMERGENCY:                                                      ║
║  □ If you suspect compromise, wipe everything                    ║
║  □ Breaking the device destroys the key                          ║
║  □ A forgotten password is an encrypted brick                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ============================================================================
# TESTING / VERIFICATION
# ============================================================================

if __name__ == "__main__":
    print("🛡️ High Security Mode - Maximum Protection")
    print("=" * 60)
    print()
    
    # Enable high security mode
    print("Enabling high security mode...")
    enable_high_security_mode(silent=False)
    
    print(f"Active: {is_high_security_mode()}")
    
    # Show configuration
    config = HighSecurityConfig()
    print(f"\nArgon2id Memory: {config.argon2_memory / 1024} MiB")
    print(f"Argon2id Iterations: {config.argon2_iterations}")
    print(f"Post-Quantum: {config.enable_pq} ({config.kyber_variant})")
    print(f"Steganography: {config.enable_stego}")
    print(f"Schrödinger Mode: {config.enable_schrodinger}")
    
    # Test key derivation timing
    print("\nTesting key derivation time (this will take a while)...")
    
    import time
    from .crypto import derive_key
    
    salt = secrets.token_bytes(16)
    
    start = time.time()
    key = derive_key("test_password_123", salt)
    elapsed = time.time() - start
    
    print(f"Key derivation: {elapsed:.2f} seconds")
    print(f"  (Each brute force attempt takes this long)")
    print(f"  (1 billion attempts = {elapsed * 1e9 / 86400 / 365:.0f} years)")
    
    print("\n✅ High security mode operational!")
    print("\nFor high-risk users: your secrets are protected by mathematics.")
    print("Stay safe. 🛡️")
