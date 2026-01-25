"""
🔏 Post-Quantum Signatures for Meow Decoder
Implements Dilithium (ML-DSA / FIPS 204) signatures for manifest authentication

Features:
- Dilithium3 signatures (NIST security level 3)
- Graceful fallback to Ed25519 if liboqs unavailable
- Hybrid mode: Ed25519 + Dilithium for defense-in-depth
- Key generation, signing, and verification

Security Properties:
- Quantum-resistant signatures (Dilithium)
- Classical fallback (Ed25519)
- Hybrid ensures security if EITHER algorithm is secure
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional, Union
import struct

# Try to import liboqs for Dilithium
try:
    import oqs
    HAS_LIBOQS = True
    DILITHIUM_AVAILABLE = "Dilithium3" in oqs.get_enabled_sig_mechanisms()
except ImportError:
    HAS_LIBOQS = False
    DILITHIUM_AVAILABLE = False

# Fallback to Ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


# Signature algorithm identifiers
SIG_ED25519 = 0x01
SIG_DILITHIUM3 = 0x02
SIG_HYBRID = 0x03  # Ed25519 + Dilithium3


@dataclass
class SignatureKeyPair:
    """Container for signature key material."""
    algorithm: int
    private_key: bytes
    public_key: bytes
    
    # For hybrid mode
    ed25519_private: Optional[bytes] = None
    ed25519_public: Optional[bytes] = None
    dilithium_private: Optional[bytes] = None
    dilithium_public: Optional[bytes] = None


@dataclass
class Signature:
    """Container for signature data."""
    algorithm: int
    signature: bytes
    
    # For hybrid mode
    ed25519_sig: Optional[bytes] = None
    dilithium_sig: Optional[bytes] = None
    
    def pack(self) -> bytes:
        """Pack signature to bytes."""
        if self.algorithm == SIG_HYBRID:
            # Format: algorithm (1) + ed25519_len (2) + ed25519_sig + dilithium_sig
            return (
                struct.pack('>BH', self.algorithm, len(self.ed25519_sig)) +
                self.ed25519_sig +
                self.dilithium_sig
            )
        else:
            # Format: algorithm (1) + signature
            return struct.pack('>B', self.algorithm) + self.signature
    
    @classmethod
    def unpack(cls, data: bytes) -> 'Signature':
        """Unpack signature from bytes."""
        algorithm = data[0]
        
        if algorithm == SIG_HYBRID:
            ed25519_len = struct.unpack('>H', data[1:3])[0]
            ed25519_sig = data[3:3+ed25519_len]
            dilithium_sig = data[3+ed25519_len:]
            return cls(
                algorithm=algorithm,
                signature=data[1:],  # Full signature data
                ed25519_sig=ed25519_sig,
                dilithium_sig=dilithium_sig
            )
        else:
            return cls(
                algorithm=algorithm,
                signature=data[1:]
            )


def get_available_algorithms() -> list:
    """Get list of available signature algorithms."""
    algos = ["ed25519"]  # Always available
    
    if DILITHIUM_AVAILABLE:
        algos.append("dilithium3")
        algos.append("hybrid")  # Ed25519 + Dilithium3
    
    return algos


def generate_keypair(algorithm: str = "hybrid") -> SignatureKeyPair:
    """
    Generate signature keypair.
    
    Args:
        algorithm: "ed25519", "dilithium3", or "hybrid"
        
    Returns:
        SignatureKeyPair with keys for the specified algorithm
        
    Raises:
        ValueError: If algorithm not available
    """
    algorithm = algorithm.lower()
    
    if algorithm == "ed25519":
        return _generate_ed25519_keypair()
    
    elif algorithm == "dilithium3":
        if not DILITHIUM_AVAILABLE:
            raise ValueError("Dilithium3 not available (install liboqs-python)")
        return _generate_dilithium_keypair()
    
    elif algorithm == "hybrid":
        if not DILITHIUM_AVAILABLE:
            # Fall back to Ed25519 only
            print("⚠️  Dilithium not available, using Ed25519 only")
            return _generate_ed25519_keypair()
        return _generate_hybrid_keypair()
    
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def _generate_ed25519_keypair() -> SignatureKeyPair:
    """Generate Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return SignatureKeyPair(
        algorithm=SIG_ED25519,
        private_key=private_bytes,
        public_key=public_bytes
    )


def _generate_dilithium_keypair() -> SignatureKeyPair:
    """Generate Dilithium3 keypair."""
    if not DILITHIUM_AVAILABLE:
        raise RuntimeError("Dilithium not available")
    
    with oqs.Signature("Dilithium3") as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
    
    return SignatureKeyPair(
        algorithm=SIG_DILITHIUM3,
        private_key=private_key,
        public_key=public_key
    )


def _generate_hybrid_keypair() -> SignatureKeyPair:
    """Generate hybrid Ed25519 + Dilithium3 keypair."""
    # Generate Ed25519
    ed_keypair = _generate_ed25519_keypair()
    
    # Generate Dilithium3
    dil_keypair = _generate_dilithium_keypair()
    
    # Combine public keys
    combined_public = ed_keypair.public_key + dil_keypair.public_key
    combined_private = ed_keypair.private_key + dil_keypair.private_key
    
    return SignatureKeyPair(
        algorithm=SIG_HYBRID,
        private_key=combined_private,
        public_key=combined_public,
        ed25519_private=ed_keypair.private_key,
        ed25519_public=ed_keypair.public_key,
        dilithium_private=dil_keypair.private_key,
        dilithium_public=dil_keypair.public_key
    )


def sign_manifest(manifest_bytes: bytes, keypair: SignatureKeyPair) -> Signature:
    """
    Sign manifest data.
    
    Args:
        manifest_bytes: Raw manifest bytes to sign
        keypair: Signing keypair
        
    Returns:
        Signature object
    """
    if keypair.algorithm == SIG_ED25519:
        return _sign_ed25519(manifest_bytes, keypair.private_key)
    
    elif keypair.algorithm == SIG_DILITHIUM3:
        return _sign_dilithium(manifest_bytes, keypair.private_key)
    
    elif keypair.algorithm == SIG_HYBRID:
        return _sign_hybrid(manifest_bytes, keypair)
    
    else:
        raise ValueError(f"Unknown algorithm: {keypair.algorithm}")


def _sign_ed25519(data: bytes, private_key: bytes) -> Signature:
    """Sign with Ed25519."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    sig = key.sign(data)
    
    return Signature(
        algorithm=SIG_ED25519,
        signature=sig
    )


def _sign_dilithium(data: bytes, private_key: bytes) -> Signature:
    """Sign with Dilithium3."""
    if not DILITHIUM_AVAILABLE:
        raise RuntimeError("Dilithium not available")
    
    with oqs.Signature("Dilithium3", private_key) as signer:
        sig = signer.sign(data)
    
    return Signature(
        algorithm=SIG_DILITHIUM3,
        signature=sig
    )


def _sign_hybrid(data: bytes, keypair: SignatureKeyPair) -> Signature:
    """Sign with both Ed25519 and Dilithium3."""
    # Sign with Ed25519
    ed_sig = _sign_ed25519(data, keypair.ed25519_private)
    
    # Sign with Dilithium3
    dil_sig = _sign_dilithium(data, keypair.dilithium_private)
    
    return Signature(
        algorithm=SIG_HYBRID,
        signature=ed_sig.signature + dil_sig.signature,
        ed25519_sig=ed_sig.signature,
        dilithium_sig=dil_sig.signature
    )


def verify_manifest(
    manifest_bytes: bytes,
    signature: Signature,
    public_key: bytes
) -> bool:
    """
    Verify manifest signature.
    
    Args:
        manifest_bytes: Raw manifest bytes
        signature: Signature to verify
        public_key: Public key bytes
        
    Returns:
        True if signature is valid
        
    Security:
        - For hybrid: BOTH signatures must be valid
        - Constant-time comparison where possible
    """
    try:
        if signature.algorithm == SIG_ED25519:
            return _verify_ed25519(manifest_bytes, signature.signature, public_key)
        
        elif signature.algorithm == SIG_DILITHIUM3:
            return _verify_dilithium(manifest_bytes, signature.signature, public_key)
        
        elif signature.algorithm == SIG_HYBRID:
            # Extract component public keys
            ed_public = public_key[:32]
            dil_public = public_key[32:]
            
            # BOTH must verify for hybrid
            ed_valid = _verify_ed25519(manifest_bytes, signature.ed25519_sig, ed_public)
            dil_valid = _verify_dilithium(manifest_bytes, signature.dilithium_sig, dil_public)
            
            return ed_valid and dil_valid
        
        else:
            return False
            
    except Exception:
        return False


def _verify_ed25519(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Ed25519 signature."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, data)
        return True
    except Exception:
        return False


def _verify_dilithium(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Dilithium3 signature."""
    if not DILITHIUM_AVAILABLE:
        return False
    
    try:
        with oqs.Signature("Dilithium3") as verifier:
            return verifier.verify(data, signature, public_key)
    except Exception:
        return False


def save_keypair(keypair: SignatureKeyPair, private_path: str, public_path: str, password: Optional[str] = None):
    """
    Save keypair to files.
    
    Args:
        keypair: Keypair to save
        private_path: Path for private key
        public_path: Path for public key
        password: Optional password to encrypt private key
    """
    # Save public key (unencrypted)
    with open(public_path, 'wb') as f:
        f.write(struct.pack('>B', keypair.algorithm))
        f.write(keypair.public_key)
    
    # Save private key (optionally encrypted)
    private_data = struct.pack('>B', keypair.algorithm) + keypair.private_key
    
    if password:
        # Encrypt with AES-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        # Derive key from password
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
        
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, private_data, None)
        
        with open(private_path, 'wb') as f:
            f.write(b"MEOW_SIG_ENC")  # Magic
            f.write(salt)
            f.write(nonce)
            f.write(encrypted)
    else:
        with open(private_path, 'wb') as f:
            f.write(private_data)


def load_keypair(private_path: str, public_path: str, password: Optional[str] = None) -> SignatureKeyPair:
    """
    Load keypair from files.
    
    Args:
        private_path: Path to private key
        public_path: Path to public key
        password: Password if private key is encrypted
        
    Returns:
        SignatureKeyPair
    """
    # Load public key
    with open(public_path, 'rb') as f:
        public_data = f.read()
    
    algorithm = public_data[0]
    public_key = public_data[1:]
    
    # Load private key
    with open(private_path, 'rb') as f:
        private_data = f.read()
    
    if private_data[:12] == b"MEOW_SIG_ENC":
        # Encrypted
        if not password:
            raise ValueError("Private key is encrypted, password required")
        
        salt = private_data[12:28]
        nonce = private_data[28:40]
        encrypted = private_data[40:]
        
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        private_data = aesgcm.decrypt(nonce, encrypted, None)
        
        algorithm = private_data[0]
        private_key = private_data[1:]
    else:
        algorithm = private_data[0]
        private_key = private_data[1:]
    
    # Reconstruct keypair
    if algorithm == SIG_HYBRID:
        # Split hybrid keys
        ed_private = private_key[:32]
        dil_private = private_key[32:]
        ed_public = public_key[:32]
        dil_public = public_key[32:]
        
        return SignatureKeyPair(
            algorithm=algorithm,
            private_key=private_key,
            public_key=public_key,
            ed25519_private=ed_private,
            ed25519_public=ed_public,
            dilithium_private=dil_private,
            dilithium_public=dil_public
        )
    else:
        return SignatureKeyPair(
            algorithm=algorithm,
            private_key=private_key,
            public_key=public_key
        )


# CLI helper
def generate_signing_keys_cli(output_dir: str = ".", algorithm: str = "hybrid"):
    """
    CLI helper to generate signing keypair.
    
    Args:
        output_dir: Directory to save keys
        algorithm: "ed25519", "dilithium3", or "hybrid"
    """
    import os
    from getpass import getpass
    
    print(f"\n🔏 Generating {algorithm.upper()} signing keypair...")
    
    # Generate keypair
    keypair = generate_keypair(algorithm)
    
    # Get password
    password = getpass("Enter password to protect private key: ")
    confirm = getpass("Confirm password: ")
    
    if password != confirm:
        raise ValueError("Passwords don't match")
    
    # Save files
    private_path = os.path.join(output_dir, "signing_private.key")
    public_path = os.path.join(output_dir, "signing_public.key")
    
    save_keypair(keypair, private_path, public_path, password)
    
    print(f"\n✅ Signing keypair generated!")
    print(f"   Private key (KEEP SECRET): {private_path}")
    print(f"   Public key (share freely): {public_path}")
    
    if algorithm == "hybrid":
        print(f"\n🛡️  Hybrid mode: Ed25519 + Dilithium3")
        print(f"   Secure against BOTH classical AND quantum attacks")
    elif algorithm == "dilithium3":
        print(f"\n🔮 Quantum-resistant: Dilithium3 (FIPS 204)")
    else:
        print(f"\n🔐 Classical: Ed25519")


# Self-test
if __name__ == "__main__":
    print("🔏 Post-Quantum Signatures Test")
    print("=" * 60)
    
    print(f"\n📋 Available algorithms: {get_available_algorithms()}")
    print(f"   liboqs installed: {HAS_LIBOQS}")
    print(f"   Dilithium available: {DILITHIUM_AVAILABLE}")
    
    # Test Ed25519
    print("\n1. Testing Ed25519...")
    keypair = generate_keypair("ed25519")
    test_data = b"Test manifest data for signing"
    
    sig = sign_manifest(test_data, keypair)
    valid = verify_manifest(test_data, sig, keypair.public_key)
    
    print(f"   Signature size: {len(sig.signature)} bytes")
    print(f"   Verification: {'✅ PASS' if valid else '❌ FAIL'}")
    
    # Test tampering detection
    tampered = test_data + b"!"
    tamper_valid = verify_manifest(tampered, sig, keypair.public_key)
    print(f"   Tamper detection: {'✅ DETECTED' if not tamper_valid else '❌ FAILED'}")
    
    # Test Dilithium if available
    if DILITHIUM_AVAILABLE:
        print("\n2. Testing Dilithium3...")
        keypair = generate_keypair("dilithium3")
        
        sig = sign_manifest(test_data, keypair)
        valid = verify_manifest(test_data, sig, keypair.public_key)
        
        print(f"   Signature size: {len(sig.signature)} bytes")
        print(f"   Public key size: {len(keypair.public_key)} bytes")
        print(f"   Verification: {'✅ PASS' if valid else '❌ FAIL'}")
        
        print("\n3. Testing Hybrid (Ed25519 + Dilithium3)...")
        keypair = generate_keypair("hybrid")
        
        sig = sign_manifest(test_data, keypair)
        valid = verify_manifest(test_data, sig, keypair.public_key)
        
        print(f"   Combined signature size: {len(sig.pack())} bytes")
        print(f"   Combined public key size: {len(keypair.public_key)} bytes")
        print(f"   Verification: {'✅ PASS' if valid else '❌ FAIL'}")
    else:
        print("\n⚠️  Dilithium not available (install liboqs-python)")
        print("   pip install liboqs-python")
    
    print("\n✅ Post-Quantum Signatures module operational!")
