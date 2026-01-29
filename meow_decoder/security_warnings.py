"""
🔐 Security Warnings Module

Centralized security warnings for experimental/unverified features.
These warnings are logged once per session to avoid noise.

Security Principle:
    "Users must be explicitly informed about feature maturity levels
     before relying on them for sensitive operations."
"""

import warnings
import os
from functools import lru_cache

# Environment variable to silence warnings (for CI or informed users)
SILENCE_PQ_WARNING = os.environ.get("MEOW_SILENCE_PQ_WARNING", "").lower() in ("1", "true", "yes")


class PostQuantumExperimentalWarning(UserWarning):
    """Warning for experimental post-quantum cryptography usage."""
    pass


class SecurityDeprecationWarning(UserWarning):
    """Warning for deprecated security features."""
    pass


@lru_cache(maxsize=1)
def _warn_pq_experimental() -> None:
    """Emit PQ experimental warning (once per session)."""
    if SILENCE_PQ_WARNING:
        return
    
    warnings.warn(
        "\n"
        "════════════════════════════════════════════════════════════════════════\n"
        "⚠️  EXPERIMENTAL: Post-Quantum Cryptography\n"
        "════════════════════════════════════════════════════════════════════════\n"
        "\n"
        "You are using post-quantum (ML-KEM / ML-DSA) cryptography which is:\n"
        "\n"
        "  • Based on NIST FIPS 203/204 standards (finalized August 2024)\n"
        "  • Implemented in unaudited release-candidate crates (v0.1.0-rc)\n"
        "  • NOT independently audited for side-channel resistance\n"
        "  • Running in HYBRID mode (X25519 + ML-KEM) for defense-in-depth\n"
        "\n"
        "RECOMMENDATION:\n"
        "  - Do NOT rely solely on PQ crypto for life-critical applications\n"
        "  - Hybrid mode is secure if EITHER X25519 OR ML-KEM is secure\n"
        "  - Track: https://github.com/RustCrypto/KEMs for audit status\n"
        "\n"
        "To silence this warning: MEOW_SILENCE_PQ_WARNING=1\n"
        "════════════════════════════════════════════════════════════════════════\n",
        PostQuantumExperimentalWarning,
        stacklevel=3
    )


def warn_pq_experimental() -> None:
    """
    Emit a one-time warning about experimental PQ crypto status.
    
    Call this when initializing PQ key material or performing PQ operations.
    The warning is only shown once per Python session.
    
    Set MEOW_SILENCE_PQ_WARNING=1 to suppress for informed users.
    """
    _warn_pq_experimental()


@lru_cache(maxsize=1)
def _warn_python_backend() -> None:
    """Emit Python backend warning (once per session)."""
    warnings.warn(
        "\n"
        "════════════════════════════════════════════════════════════════════════\n"
        "⚠️  SECURITY: Python Crypto Backend Active\n"
        "════════════════════════════════════════════════════════════════════════\n"
        "\n"
        "The Python crypto backend does NOT provide:\n"
        "\n"
        "  • Constant-time guarantees (timing side-channel risk)\n"
        "  • Memory zeroization guarantees (key residue risk)\n"
        "  • Hardware acceleration isolation\n"
        "\n"
        "RECOMMENDED: Use the Rust backend (meow_crypto_rs) for production.\n"
        "════════════════════════════════════════════════════════════════════════\n",
        SecurityDeprecationWarning,
        stacklevel=3
    )


def warn_python_backend() -> None:
    """
    Emit warning when Python backend is used instead of Rust.
    
    This should never happen in normal operation since Python backend
    is disabled, but serves as defense-in-depth if it's accidentally enabled.
    """
    _warn_python_backend()


# ============================================================================
# Frame MAC Security Rationale (for documentation and auditors)
# ============================================================================

FRAME_MAC_SECURITY_RATIONALE = """
╔════════════════════════════════════════════════════════════════════════════╗
║  FRAME MAC DESIGN RATIONALE (8-byte / 64-bit truncated HMAC-SHA256)        ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  PURPOSE:                                                                  ║
║    DoS resistance - reject invalid frames BEFORE expensive processing.    ║
║    NOT for long-term message authentication (manifest HMAC handles that). ║
║                                                                            ║
║  SECURITY ANALYSIS:                                                        ║
║    • Collision probability: 2^(-64) ≈ 5.4 × 10^(-20) per frame           ║
║    • Birthday attack: ~2^32 frames to find collision (impractical)       ║
║    • Frame count: Typical GIF has <1000 frames                           ║
║    • Attack budget: 1000 frames × 2^(-64) = negligible success chance    ║
║                                                                            ║
║  WHY NOT 16-BYTE (128-BIT)?                                               ║
║    • QR code capacity is limited (~2953 bytes at L error correction)     ║
║    • 8 extra bytes per frame × 1000 frames = 8KB overhead                ║
║    • DoS resistance only requires work-factor, not long-term security    ║
║                                                                            ║
║  THREAT MODEL:                                                             ║
║    Frame MACs protect against:                                            ║
║    ✓ Random corruption triggering expensive decryption attempts          ║
║    ✓ Naive frame injection by passive observers                          ║
║    ✓ DoS attacks flooding decoder with invalid data                      ║
║                                                                            ║
║    Frame MACs do NOT protect against:                                     ║
║    ✗ Adversary with manifest key (can forge MACs anyway)                 ║
║    ✗ Long-term authentication (use manifest HMAC for that)               ║
║                                                                            ║
║  VERIFICATION:                                                             ║
║    - Constant-time comparison via secrets.compare_digest()                ║
║    - Per-frame key derivation prevents cross-frame attacks               ║
║    - Salt binding prevents cross-session replay                           ║
║                                                                            ║
║  CONCLUSION:                                                               ║
║    64-bit truncation is APPROPRIATE for the DoS-resistance threat model. ║
║    Upgrading to 128-bit would marginally improve security at QR cost.    ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
"""


def get_frame_mac_rationale() -> str:
    """Return formal security rationale for 8-byte frame MAC design."""
    return FRAME_MAC_SECURITY_RATIONALE
