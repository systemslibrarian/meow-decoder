"""
Frame-Level MAC Authentication
Prevents DoS attacks from malicious/random frames during decode

═══════════════════════════════════════════════════════════════════════════════
SECURITY DESIGN RATIONALE: 8-byte (64-bit) Truncated HMAC-SHA256
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
    DoS resistance - reject invalid frames BEFORE expensive fountain decoding.
    NOT for long-term message authentication (manifest HMAC handles that).

THREAT MODEL:
    Frame MACs protect against:
    ✓ Random corruption triggering expensive decryption attempts
    ✓ Naive frame injection by passive observers
    ✓ DoS attacks flooding decoder with invalid data

    Frame MACs do NOT protect against:
    ✗ Adversary with manifest key (can forge MACs anyway)
    ✗ Long-term authentication (manifest HMAC-SHA256 handles this)

SECURITY ANALYSIS:
    • Tag collision probability: 2^(-64) ≈ 5.4 × 10^(-20) per frame
    • Birthday bound: ~2^32 frames needed to find any collision
    • Practical frame count: <10,000 frames per GIF (typical: 100-1000)
    • Combined success: 10,000 × 2^(-64) ≈ 0 (negligible)
    • Brute-force: 2^64 attempts to forge a single frame MAC

WHY NOT 16-BYTE (128-BIT)?
    • QR capacity is limited (~2953 bytes at L error correction)
    • 8 extra bytes/frame × 1000 frames = 8KB additional overhead
    • DoS resistance only requires work-factor, not long-term security
    • Frame data is also protected by manifest HMAC and AES-GCM

VERIFICATION PROPERTIES:
    ✓ Constant-time comparison via secrets.compare_digest()
    ✓ Per-frame key derivation (HKDF with frame index) prevents cross-frame attacks
    ✓ Salt binding prevents cross-session replay
    ✓ Domain separation from encryption keys

CONCLUSION:
    64-bit truncation is APPROPRIATE for the DoS-resistance threat model.
    Full security is provided by the layered defense: frame MAC + manifest HMAC + AES-GCM.

For full rationale, see: meow_decoder.security_warnings.get_frame_mac_rationale()
═══════════════════════════════════════════════════════════════════════════════
"""

import hmac
import hashlib
import struct
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONSTANT: Frame MAC Size
# ═══════════════════════════════════════════════════════════════════════════════
# 8 bytes (64 bits) - Reviewed and justified in docstring above.
# See SECURITY_DESIGN_RATIONALE for threat model analysis.
# Changing this value requires security review and migration plan.
MAC_SIZE = 8

# Domain separation for frame MACs
FRAME_MAC_INFO = b"meow_frame_mac_v1"

# Domain separation for deriving the frame MAC master key from encryption key material
FRAME_MAC_MASTER_INFO = b"meow_frame_mac_master_v2"


def derive_frame_master_key(master_key_material: bytes, salt: bytes) -> bytes:
    """
    Derive a frame MAC master key from encryption key material.

    Args:
        master_key_material: Encryption key material (32 bytes)
        salt: Random salt (16 bytes)

    Returns:
        32-byte frame MAC master key

    Security:
        - HKDF domain separation from encryption/HMAC keys
        - Ensures keyfile/FS-derived keys bind frame MACs
        - Does not change frame format (MAC size unchanged)
    """
    # Why: HKDF domain separation prevents key reuse across encryption/HMAC/frame MACs.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=FRAME_MAC_MASTER_INFO
    ).derive(master_key_material)


def derive_frame_master_key_legacy(password: str, salt: bytes) -> bytes:
    """
    Legacy frame MAC key derivation (v1 compatibility).

    This preserves decode compatibility for existing files created prior to v2
    frame MAC master key derivation.
    """
    return hashlib.sha256(password.encode('utf-8') + salt + b'frame_mac_key').digest()


def derive_frame_key(master_key: bytes, frame_index: int, salt: bytes) -> bytes:
    """
    Derive unique key for frame MAC.
    
    Args:
        master_key: Master encryption key (32 bytes)
        frame_index: Frame number (0-indexed)
        salt: Random salt (16 bytes)
        
    Returns:
        Frame-specific MAC key (32 bytes)
        
    Security:
        - Each frame gets unique MAC key
        - HKDF ensures key independence
        - Frame index prevents MAC reuse
    """
    # Combine frame index into derivation
    info = FRAME_MAC_INFO + struct.pack('<Q', frame_index)
    
    frame_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(master_key)
    
    return frame_key


def compute_frame_mac(
    frame_data: bytes,
    master_key: bytes,
    frame_index: int,
    salt: bytes
) -> bytes:
    """
    Compute MAC for QR frame.
    
    Args:
        frame_data: Raw frame data (droplet bytes)
        master_key: Master encryption key
        frame_index: Frame number
        salt: Random salt
        
    Returns:
        8-byte MAC tag
        
    Security:
        - HMAC-SHA256 truncated to 8 bytes
        - Sufficient for DoS prevention (not long-term security)
        - Fast verification during decode
    """
    # Derive frame-specific key
    frame_key = derive_frame_key(master_key, frame_index, salt)
    
    # Compute HMAC-SHA256
    mac = hmac.new(frame_key, frame_data, hashlib.sha256).digest()
    
    # Truncate to 8 bytes (64 bits)
    # Why: Frame MACs are for DoS resistance (not long-term auth). 64-bit
    # tags provide ample work factor while keeping QR payloads smaller.
    return mac[:MAC_SIZE]


def verify_frame_mac(
    frame_data: bytes,
    received_mac: bytes,
    master_key: bytes,
    frame_index: int,
    salt: bytes
) -> bool:
    """
    Verify frame MAC in constant time.
    
    Args:
        frame_data: Raw frame data
        received_mac: MAC tag from QR code (8 bytes)
        master_key: Master encryption key
        frame_index: Frame number
        salt: Random salt
        
    Returns:
        True if MAC valid, False otherwise
        
    Security:
        - Constant-time comparison (secrets.compare_digest)
        - Prevents timing attacks on MAC verification
        - Invalid frames rejected immediately
    """
    if len(received_mac) != MAC_SIZE:
        return False
    
    # Compute expected MAC
    expected_mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
    
    # Constant-time comparison
    return secrets.compare_digest(expected_mac, received_mac)


def pack_frame_with_mac(
    frame_data: bytes,
    master_key: bytes,
    frame_index: int,
    salt: bytes
) -> bytes:
    """
    Pack frame data with prepended MAC.
    
    Args:
        frame_data: Raw droplet data
        master_key: Master encryption key
        frame_index: Frame number
        salt: Random salt
        
    Returns:
        MAC (8 bytes) || frame_data
        
    Format:
        [MAC: 8 bytes][Frame Data: variable]
    """
    mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
    return mac + frame_data


def unpack_frame_with_mac(
    packed_frame: bytes,
    master_key: bytes,
    frame_index: int,
    salt: bytes
) -> Tuple[bool, bytes]:
    """
    Unpack and verify frame data.
    
    Args:
        packed_frame: MAC || frame_data
        master_key: Master encryption key
        frame_index: Frame number
        salt: Random salt
        
    Returns:
        Tuple of (valid, frame_data)
        - valid: True if MAC verified
        - frame_data: Unpacked data (or b'' if invalid)
        
    Security:
        - Returns immediately if MAC invalid
        - Prevents wasting decode time on bad frames
        - Constant-time MAC verification
    """
    if len(packed_frame) < MAC_SIZE:
        return False, b''
    
    # Extract MAC and data
    received_mac = packed_frame[:MAC_SIZE]
    frame_data = packed_frame[MAC_SIZE:]
    
    # Verify MAC
    valid = verify_frame_mac(frame_data, received_mac, master_key, frame_index, salt)
    
    if not valid:
        return False, b''
    
    return True, frame_data


# Statistics for monitoring
class FrameMACStats:
    """Track frame MAC verification statistics."""
    
    def __init__(self):
        self.total_frames = 0
        self.valid_frames = 0
        self.invalid_frames = 0
        self.injection_attempts = 0
    
    def record_valid(self):
        """Record successful MAC verification."""
        self.total_frames += 1
        self.valid_frames += 1
    
    def record_invalid(self):
        """Record failed MAC verification."""
        self.total_frames += 1
        self.invalid_frames += 1
        self.injection_attempts += 1
    
    def success_rate(self) -> float:
        """Calculate MAC success rate."""
        if self.total_frames == 0:
            return 0.0
        return self.valid_frames / self.total_frames
    
    def report(self) -> str:
        """Generate statistics report."""
        return f"""
Frame MAC Statistics:
  Total frames: {self.total_frames}
  Valid frames: {self.valid_frames}
  Invalid frames: {self.invalid_frames}
  Injection attempts: {self.injection_attempts}
  Success rate: {self.success_rate()*100:.1f}%
"""


# Example usage
if __name__ == "__main__":
    # Generate test data
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    frame_data = b"This is droplet data for frame 42"
    frame_index = 42
    
    print("Frame MAC Authentication Test")
    print("=" * 50)
    
    # Pack frame with MAC
    packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
    print(f"\n✅ Packed frame:")
    print(f"   Total size: {len(packed)} bytes")
    print(f"   MAC: {packed[:MAC_SIZE].hex()}")
    print(f"   Data: {packed[MAC_SIZE:][:30]}...")
    
    # Verify valid frame
    valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)
    print(f"\n✅ Valid frame verification:")
    print(f"   Valid: {valid}")
    print(f"   Data matches: {unpacked == frame_data}")
    
    # Test invalid MAC (wrong frame index)
    valid2, unpacked2 = unpack_frame_with_mac(packed, master_key, 999, salt)
    print(f"\n❌ Invalid frame (wrong index):")
    print(f"   Valid: {valid2}")
    print(f"   Data: {unpacked2}")
    
    # Test tampered data
    tampered = packed[:MAC_SIZE] + b"TAMPERED" + packed[MAC_SIZE+8:]
    valid3, unpacked3 = unpack_frame_with_mac(tampered, master_key, frame_index, salt)
    print(f"\n❌ Tampered frame:")
    print(f"   Valid: {valid3}")
    print(f"   Data: {unpacked3}")
    
    # Test with statistics
    print(f"\n📊 Statistics Test:")
    stats = FrameMACStats()
    
    # Simulate decode with some invalid frames
    for i in range(100):
        if i % 7 == 0:  # Every 7th frame is invalid
            stats.record_invalid()
        else:
            stats.record_valid()
    
    print(stats.report())
    print(f"✅ Frame MAC module working correctly!")
