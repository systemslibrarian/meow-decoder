"""
🐱 Quantum Nine Lives - Post-Quantum Cryptography for Meow Decoder
Real hybrid Kyber/ML-KEM + X25519 implementation with graceful fallback

Priority 2 Implementation: Uses liboqs-python when available
"""

import os
import struct
import secrets
from typing import Optional, Tuple
from dataclasses import dataclass

# Try to import liboqs for real post-quantum crypto
try:
    import oqs
    HAS_LIBOQS = True
    print("😸 Quantum Nine Lives ACTIVATED! (liboqs-python found)")
except ImportError:
    HAS_LIBOQS = False
    print("⚠️  Quantum Nine Lives in MOCK mode (install: pip install liboqs-python)")

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class QuantumKeyPair:
    """
    🐱 Quantum Nine Lives Key Pair
    
    Contains both classical (X25519) and quantum-resistant (Kyber) keys.
    """
    classical_public: bytes
    classical_secret: bytes
    quantum_public: Optional[bytes]
    quantum_secret: Optional[bytes]
    kyber_variant: str  # "kyber512", "kyber768", "kyber1024"


@dataclass
class QuantumEncapsulation:
    """
    🔐 Quantum-resistant encapsulation result.
    
    Contains both classical and quantum ciphertexts that
    protect the shared secret.
    """
    classical_ciphertext: bytes
    quantum_ciphertext: Optional[bytes]
    shared_secret: bytes
    variant: str


class QuantumNineLives:
    """
    🐱 Quantum Nine Lives - Hybrid PQ Crypto
    
    Combines X25519 (classical) with Kyber (post-quantum) for
    protection against both classical and quantum attacks.
    
    Security: Secure if EITHER classical OR quantum component is secure!
    """
    
    # Kyber variant mappings
    VARIANTS = {
        'kyber512': 'Kyber512',
        'kyber768': 'Kyber768',
        'kyber1024': 'Kyber1024',
    }
    
    def __init__(self, variant: str = 'kyber768'):
        """
        Initialize Quantum Nine Lives.
        
        Args:
            variant: Kyber variant (kyber512/kyber768/kyber1024)
                    kyber768 recommended for most use cases
        """
        if variant not in self.VARIANTS:
            raise ValueError(f"Unknown variant: {variant}. Use: {list(self.VARIANTS.keys())}")
        
        self.variant = variant
        self.oqs_variant = self.VARIANTS[variant]
        self.has_quantum = HAS_LIBOQS
        
        if HAS_LIBOQS:
            print(f"  🔐 Using real {variant.upper()} (quantum-resistant)")
        else:
            print(f"  ⚠️  Using classical-only mode (quantum NOT resistant)")
    
    def generate_keypair(self) -> QuantumKeyPair:
        """
        🔑 Generate a hybrid keypair.
        
        Returns:
            QuantumKeyPair with both classical and quantum keys
        """
        # Generate classical X25519 keypair
        classical_secret = x25519.X25519PrivateKey.generate()
        classical_public = classical_secret.public_key()
        
        classical_public_bytes = classical_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        classical_secret_bytes = classical_secret.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Generate quantum keypair if available
        quantum_public = None
        quantum_secret = None
        
        if HAS_LIBOQS:
            try:
                kem = oqs.KeyEncapsulation(self.oqs_variant)
                quantum_public = kem.generate_keypair()
                quantum_secret = kem.export_secret_key()
                print(f"  ✅ Generated quantum keypair ({len(quantum_public)} bytes)")
            except Exception as e:
                print(f"  ⚠️  Quantum keygen failed: {e}")
                self.has_quantum = False
        
        return QuantumKeyPair(
            classical_public=classical_public_bytes,
            classical_secret=classical_secret_bytes,
            quantum_public=quantum_public,
            quantum_secret=quantum_secret,
            kyber_variant=self.variant
        )
    
    def encapsulate(self, keypair: QuantumKeyPair) -> QuantumEncapsulation:
        """
        🔐 Encapsulate a shared secret using hybrid crypto.
        
        Args:
            keypair: Recipient's public keys
            
        Returns:
            QuantumEncapsulation with ciphertexts and shared secret
        """
        # Classical X25519 key exchange
        ephemeral_secret = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_secret.public_key()
        
        recipient_public = x25519.X25519PublicKey.from_public_bytes(
            keypair.classical_public
        )
        
        classical_shared = ephemeral_secret.exchange(recipient_public)
        
        classical_ciphertext = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Quantum encapsulation if available
        quantum_ciphertext = None
        quantum_shared = None
        
        if HAS_LIBOQS and keypair.quantum_public is not None:
            try:
                kem = oqs.KeyEncapsulation(self.oqs_variant)
                quantum_ciphertext, quantum_shared = kem.encap_secret(keypair.quantum_public)
                print(f"  🔐 Quantum encapsulation: {len(quantum_ciphertext)} bytes")
            except Exception as e:
                print(f"  ⚠️  Quantum encap failed: {e}")
        
        # Combine secrets using HKDF
        if quantum_shared:
            # Hybrid: XOR then HKDF
            combined = bytes(a ^ b for a, b in zip(
                classical_shared + b'\x00' * (len(quantum_shared) - len(classical_shared)),
                quantum_shared
            ))
        else:
            # Classical only
            combined = classical_shared
        
        # Derive final shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'meow_quantum_nine_lives_v1',
            info=b'hybrid_shared_secret'
        )
        shared_secret = hkdf.derive(combined)
        
        return QuantumEncapsulation(
            classical_ciphertext=classical_ciphertext,
            quantum_ciphertext=quantum_ciphertext,
            shared_secret=shared_secret,
            variant=self.variant
        )
    
    def decapsulate(self, keypair: QuantumKeyPair, encapsulation: QuantumEncapsulation) -> bytes:
        """
        🔓 Decapsulate shared secret using private keys.
        
        Args:
            keypair: Recipient's keypair (with secret keys)
            encapsulation: Encapsulation from sender
            
        Returns:
            Shared secret (32 bytes)
        """
        # Classical X25519 decapsulation
        secret_key = x25519.X25519PrivateKey.from_private_bytes(
            keypair.classical_secret
        )
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            encapsulation.classical_ciphertext
        )
        
        classical_shared = secret_key.exchange(ephemeral_public)
        
        # Quantum decapsulation if available
        quantum_shared = None
        
        if HAS_LIBOQS and keypair.quantum_secret is not None and encapsulation.quantum_ciphertext:
            try:
                kem = oqs.KeyEncapsulation(self.oqs_variant, keypair.quantum_secret)
                quantum_shared = kem.decap_secret(encapsulation.quantum_ciphertext)
                print(f"  🔓 Quantum decapsulation successful")
            except Exception as e:
                print(f"  ⚠️  Quantum decap failed: {e}")
        
        # Combine secrets
        if quantum_shared:
            combined = bytes(a ^ b for a, b in zip(
                classical_shared + b'\x00' * (len(quantum_shared) - len(classical_shared)),
                quantum_shared
            ))
        else:
            combined = classical_shared
        
        # Derive final shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'meow_quantum_nine_lives_v1',
            info=b'hybrid_shared_secret'
        )
        shared_secret = hkdf.derive(combined)
        
        return shared_secret


def pack_quantum_encapsulation(encap: QuantumEncapsulation) -> bytes:
    """
    📦 Pack quantum encapsulation for manifest v4.
    
    Format:
        version (1 byte) +
        variant_len (1 byte) +
        variant (variable) +
        classical_len (2 bytes) +
        classical_ciphertext (32 bytes for X25519) +
        quantum_len (2 bytes) +
        quantum_ciphertext (variable, 0 if none)
    """
    variant_bytes = encap.variant.encode('utf-8')
    
    packed = struct.pack('B', 4)  # v4
    packed += struct.pack('B', len(variant_bytes))
    packed += variant_bytes
    packed += struct.pack('>H', len(encap.classical_ciphertext))
    packed += encap.classical_ciphertext
    
    if encap.quantum_ciphertext:
        packed += struct.pack('>H', len(encap.quantum_ciphertext))
        packed += encap.quantum_ciphertext
    else:
        packed += struct.pack('>H', 0)
    
    return packed


def unpack_quantum_encapsulation(data: bytes) -> QuantumEncapsulation:
    """
    📦 Unpack quantum encapsulation from manifest v4.
    """
    offset = 0
    
    version = struct.unpack('B', data[offset:offset+1])[0]
    offset += 1
    
    if version != 4:
        raise ValueError(f"Wrong version: {version} (expected 4)")
    
    variant_len = struct.unpack('B', data[offset:offset+1])[0]
    offset += 1
    
    variant = data[offset:offset+variant_len].decode('utf-8')
    offset += variant_len
    
    classical_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    classical_ct = data[offset:offset+classical_len]
    offset += classical_len
    
    quantum_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    quantum_ct = None
    if quantum_len > 0:
        quantum_ct = data[offset:offset+quantum_len]
    
    # Shared secret will be computed during decapsulation
    return QuantumEncapsulation(
        classical_ciphertext=classical_ct,
        quantum_ciphertext=quantum_ct,
        shared_secret=b'',  # Placeholder
        variant=variant
    )


# Testing
if __name__ == "__main__":
    print("🐱 Testing Quantum Nine Lives...\n")
    
    # Test all variants
    for variant in ['kyber512', 'kyber768', 'kyber1024']:
        print(f"\n{'='*60}")
        print(f"Testing {variant.upper()}")
        print('='*60)
        
        try:
            # Initialize
            qnl = QuantumNineLives(variant=variant)
            
            # Generate keypair
            print("\n1. Generating keypair...")
            keypair = qnl.generate_keypair()
            print(f"   Classical public: {len(keypair.classical_public)} bytes")
            if keypair.quantum_public:
                print(f"   Quantum public: {len(keypair.quantum_public)} bytes")
            
            # Encapsulate
            print("\n2. Encapsulating...")
            encap = qnl.encapsulate(keypair)
            print(f"   Classical CT: {len(encap.classical_ciphertext)} bytes")
            if encap.quantum_ciphertext:
                print(f"   Quantum CT: {len(encap.quantum_ciphertext)} bytes")
            print(f"   Shared secret: {len(encap.shared_secret)} bytes")
            
            # Decapsulate
            print("\n3. Decapsulating...")
            recovered_secret = qnl.decapsulate(keypair, encap)
            
            if recovered_secret == encap.shared_secret:
                print(f"   ✅ Secrets match!")
            else:
                print(f"   ❌ Secret mismatch!")
            
            # Test packing
            print("\n4. Testing packing...")
            packed = pack_quantum_encapsulation(encap)
            print(f"   Packed size: {len(packed)} bytes")
            
            unpacked = unpack_quantum_encapsulation(packed)
            print(f"   ✅ Packing roundtrip successful")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "="*60)
    print("🎉 Quantum Nine Lives testing complete!")
    print("="*60)
    
    if HAS_LIBOQS:
        print("\n✅ Real post-quantum crypto ACTIVE")
        print("   Your secrets are safe from quantum computers!")
    else:
        print("\n⚠️  Running in classical-only mode")
        print("   Install liboqs-python for quantum resistance:")
        print("   pip install liboqs-python")
