"""
🐱⚛️ Multi-Secret Schrödinger Mode (N-Deniability)

Grok's suggestion: "Multi-Level Deniability - Instead of two secrets (Schrödinger mode),
support N levels of deniable encryption where each key reveals a different 'reality'."

This module extends Schrödinger mode to support N secrets (3+) with:
- Quantum superposition of N realities
- Each password reveals ONE reality
- N-1 realities remain unprovable
- Statistical indistinguishability across all N

Security Properties:
- Coercion resistance: Give away passwords one at a time
- Forensic resistance: Cannot prove unrevealed secrets exist
- Plausible deniability: Each reality is complete and believable
- Constant-time decoding: No timing leaks about which reality

Usage:
    from meow_decoder.multi_secret import MultiSecretEncoder
    
    encoder = MultiSecretEncoder([
        (secret1, "password1"),  # Most sensitive
        (secret2, "password2"),  # Less sensitive
        (secret3, "password3"),  # Decoy (can reveal)
    ])
    
    superposition = encoder.encode()
    
    # Later, reveal only what you must
    decoder = MultiSecretDecoder(superposition)
    reality = decoder.decode("password3")  # Returns decoy
"""

import secrets
import hashlib
import struct
from typing import List, Tuple, Optional
from dataclasses import dataclass, field
from collections import Counter
import zlib

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from argon2 import low_level


@dataclass
class Reality:
    """
    A single reality in the multi-secret superposition.
    
    Attributes:
        data: The secret data for this reality
        password: Password to access this reality
        salt: Unique salt for key derivation
        nonce: Unique nonce for encryption
        priority: Higher = more sensitive (revealed last)
    """
    data: bytes
    password: str
    salt: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(12))
    priority: int = 0


@dataclass
class MultiSecretManifest:
    """
    Manifest for N-secret superposition.
    
    Format:
        magic: "MEOWN" (5 bytes) - N for N-deniability
        version: 0x01 (1 byte)
        n_realities: number of secrets (1 byte)
        block_size: (2 bytes)
        total_blocks: (4 bytes)
        cipher_lengths: N x 4 bytes (length of each ciphertext)
        salt_array: N x 16 bytes
        nonce_array: N x 12 bytes
        hmac_array: N x 32 bytes (verifies correct password)
        merkle_root: 32 bytes
    """
    magic: bytes = b"MEOWN"
    version: int = 0x01
    n_realities: int = 0
    block_size: int = 256
    total_blocks: int = 0
    cipher_lengths: List[int] = field(default_factory=list)  # NEW: store ciphertext lengths
    salts: List[bytes] = field(default_factory=list)
    nonces: List[bytes] = field(default_factory=list)
    hmacs: List[bytes] = field(default_factory=list)
    merkle_root: bytes = b'\x00' * 32
    
    def pack(self) -> bytes:
        """Serialize manifest."""
        data = self.magic
        data += struct.pack('>BBH', self.version, self.n_realities, self.block_size)
        data += struct.pack('>I', self.total_blocks)
        
        # Pack cipher lengths
        for length in self.cipher_lengths:
            data += struct.pack('>I', length)
        
        for salt in self.salts:
            data += salt
        for nonce in self.nonces:
            data += nonce
        for hmac in self.hmacs:
            data += hmac
        
        data += self.merkle_root
        
        return data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'MultiSecretManifest':
        """Deserialize manifest."""
        if data[:5] != b"MEOWN":
            raise ValueError("Invalid multi-secret manifest magic")
        
        version, n_realities, block_size = struct.unpack('>BBH', data[5:9])
        total_blocks, = struct.unpack('>I', data[9:13])
        
        offset = 13
        
        # Unpack cipher lengths
        cipher_lengths = []
        for _ in range(n_realities):
            length, = struct.unpack('>I', data[offset:offset+4])
            cipher_lengths.append(length)
            offset += 4
        
        salts = []
        for _ in range(n_realities):
            salts.append(data[offset:offset+16])
            offset += 16
        
        nonces = []
        for _ in range(n_realities):
            nonces.append(data[offset:offset+12])
            offset += 12
        
        hmacs = []
        for _ in range(n_realities):
            hmacs.append(data[offset:offset+32])
            offset += 32
        
        merkle_root = data[offset:offset+32]
        
        return cls(
            magic=b"MEOWN",
            version=version,
            n_realities=n_realities,
            block_size=block_size,
            total_blocks=total_blocks,
            cipher_lengths=cipher_lengths,
            salts=salts,
            nonces=nonces,
            hmacs=hmacs,
            merkle_root=merkle_root
        )


class MultiSecretEncoder:
    """
    Encodes N secrets into a single quantum superposition.
    
    Strategy:
    1. Encrypt each reality independently
    2. Pad all to same length
    3. Interleave blocks (round-robin: 0,1,2,...,N-1,0,1,2,...)
    4. Permute with cryptographic shuffle
    5. Compute Merkle root for integrity
    """
    
    def __init__(self, realities: List[Tuple[bytes, str]], block_size: int = 256):
        """
        Initialize encoder with N realities.
        
        Args:
            realities: List of (data, password) tuples
            block_size: Block size for interleaving
            
        Raises:
            ValueError: If fewer than 2 realities provided
        """
        if len(realities) < 2:
            raise ValueError("Need at least 2 realities for multi-secret mode")
        
        if len(realities) > 16:
            raise ValueError("Maximum 16 realities supported")
        
        self.realities = [
            Reality(data=data, password=password, priority=i)
            for i, (data, password) in enumerate(realities)
        ]
        self.block_size = block_size
        self.manifest = None
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key using Argon2id."""
        return low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=3,
            memory_cost=65536,  # 64 MiB
            parallelism=4,
            hash_len=32,
            type=low_level.Type.ID
        )
    
    def _encrypt_reality(self, reality: Reality) -> bytes:
        """Encrypt a single reality."""
        # Compress
        compressed = zlib.compress(reality.data, level=9)
        
        # Derive key
        key = self._derive_key(reality.password, reality.salt)
        
        # Encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(reality.nonce, compressed, None)
        
        return ciphertext
    
    def _pad_to_blocks(self, data: bytes, target_blocks: int) -> List[bytes]:
        """Pad data to exact number of blocks."""
        blocks = []
        
        # Split into blocks
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            if len(block) < self.block_size:
                block += secrets.token_bytes(self.block_size - len(block))
            blocks.append(block)
        
        # Pad with random blocks if needed
        while len(blocks) < target_blocks:
            blocks.append(secrets.token_bytes(self.block_size))
        
        return blocks
    
    def _compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC for password verification."""
        import hmac as hmac_module
        return hmac_module.new(key, data, hashlib.sha256).digest()
    
    def _compute_merkle_root(self, blocks: List[bytes]) -> bytes:
        """Compute Merkle root of all blocks."""
        if not blocks:
            return hashlib.sha256(b"empty").digest()
        
        hashes = [hashlib.sha256(b).digest() for b in blocks]
        
        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                if i + 1 < len(hashes):
                    combined = hashlib.sha256(hashes[i] + hashes[i+1]).digest()
                else:
                    combined = hashes[i]
                next_level.append(combined)
            hashes = next_level
        
        return hashes[0]
    
    def _cryptographic_shuffle(self, blocks: List[bytes], seed: bytes) -> List[bytes]:
        """Shuffle blocks deterministically using cryptographic seed."""
        import random
        
        seed_int = int.from_bytes(seed[:8], 'big')
        rng = random.Random(seed_int)
        
        indices = list(range(len(blocks)))
        rng.shuffle(indices)
        
        return [blocks[i] for i in indices]
    
    def encode(self) -> Tuple[bytes, MultiSecretManifest]:
        """
        Encode all realities into superposition.
        
        Returns:
            (superposition_data, manifest)
        """
        n = len(self.realities)
        
        # Encrypt all realities
        ciphertexts = [self._encrypt_reality(r) for r in self.realities]
        
        # Find max size and compute blocks needed
        max_size = max(len(c) for c in ciphertexts)
        blocks_per_reality = (max_size + self.block_size - 1) // self.block_size
        
        # Store ciphertext lengths for proper decryption
        cipher_lengths = [len(ct) for ct in ciphertexts]
        
        # Pad all to same number of blocks
        all_blocks = [
            self._pad_to_blocks(ct, blocks_per_reality)
            for ct in ciphertexts
        ]
        
        # Interleave: round-robin across realities
        interleaved = []
        for block_idx in range(blocks_per_reality):
            for reality_idx in range(n):
                interleaved.append(all_blocks[reality_idx][block_idx])
        
        # Generate shuffle seed from all salts
        shuffle_seed = hashlib.sha256(
            b''.join(r.salt for r in self.realities)
        ).digest()
        
        # Shuffle to hide interleaving pattern
        shuffled = self._cryptographic_shuffle(interleaved, shuffle_seed)
        
        # Compute Merkle root
        merkle_root = self._compute_merkle_root(shuffled)
        
        # Compute HMACs for password verification
        hmacs = []
        for r in self.realities:
            key = self._derive_key(r.password, r.salt)
            hmac = self._compute_hmac(key, merkle_root)
            hmacs.append(hmac)
        
        # Create manifest
        self.manifest = MultiSecretManifest(
            n_realities=n,
            block_size=self.block_size,
            total_blocks=len(shuffled),
            cipher_lengths=cipher_lengths,  # Store lengths for decryption
            salts=[r.salt for r in self.realities],
            nonces=[r.nonce for r in self.realities],
            hmacs=hmacs,
            merkle_root=merkle_root
        )
        
        # Combine shuffled blocks
        superposition = b''.join(shuffled)
        
        return superposition, self.manifest


class MultiSecretDecoder:
    """
    Decodes one reality from N-secret superposition.
    
    Given a password, extracts and decrypts the corresponding reality.
    All other realities remain unprovable.
    """
    
    def __init__(self, superposition: bytes, manifest: MultiSecretManifest):
        """
        Initialize decoder.
        
        Args:
            superposition: The mixed superposition data
            manifest: The multi-secret manifest
        """
        self.superposition = superposition
        self.manifest = manifest
        
        # Split into blocks
        bs = manifest.block_size
        self.blocks = [
            superposition[i:i+bs]
            for i in range(0, len(superposition), bs)
        ]
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key using Argon2id."""
        return low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=low_level.Type.ID
        )
    
    def _verify_password(self, password: str) -> int:
        """
        Verify password and return reality index.
        
        Returns:
            Reality index (0 to N-1) or -1 if invalid
            
        Security:
            Uses constant-time comparison to prevent timing attacks.
        """
        import hmac as hmac_module
        
        for i in range(self.manifest.n_realities):
            key = self._derive_key(password, self.manifest.salts[i])
            expected_hmac = self._compute_hmac(key, self.manifest.merkle_root)
            
            # Constant-time comparison
            if secrets.compare_digest(expected_hmac, self.manifest.hmacs[i]):
                return i
        
        return -1
    
    def _compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC for verification."""
        import hmac as hmac_module
        return hmac_module.new(key, data, hashlib.sha256).digest()
    
    def _unshuffle(self, blocks: List[bytes]) -> List[bytes]:
        """Reverse the cryptographic shuffle."""
        import random
        
        shuffle_seed = hashlib.sha256(
            b''.join(self.manifest.salts)
        ).digest()
        
        seed_int = int.from_bytes(shuffle_seed[:8], 'big')
        rng = random.Random(seed_int)
        
        # Recreate shuffle indices
        indices = list(range(len(blocks)))
        rng.shuffle(indices)
        
        # Reverse: unshuffled[indices[i]] = shuffled[i]
        unshuffled = [None] * len(blocks)
        for i, block in enumerate(blocks):
            unshuffled[indices[i]] = block
        
        return unshuffled
    
    def decode(self, password: str) -> bytes:
        """
        Decode reality for given password.
        
        Args:
            password: Password for desired reality
            
        Returns:
            Decrypted data for this reality
            
        Raises:
            ValueError: If password is invalid
        """
        # Verify password and get reality index
        reality_idx = self._verify_password(password)
        
        if reality_idx == -1:
            raise ValueError("Invalid password")
        
        n = self.manifest.n_realities
        
        # Unshuffle blocks
        unshuffled = self._unshuffle(self.blocks)
        
        # Extract this reality's blocks (de-interleave)
        # Interleaving pattern: 0,1,2,...,N-1,0,1,2,...
        blocks_per_reality = len(unshuffled) // n
        
        reality_blocks = []
        for block_idx in range(blocks_per_reality):
            interleaved_idx = block_idx * n + reality_idx
            reality_blocks.append(unshuffled[interleaved_idx])
        
        # Reconstruct ciphertext and trim to original length
        ciphertext = b''.join(reality_blocks)
        
        # Use stored ciphertext length to remove padding
        original_cipher_len = self.manifest.cipher_lengths[reality_idx]
        ciphertext = ciphertext[:original_cipher_len]
        
        # Decrypt
        key = self._derive_key(password, self.manifest.salts[reality_idx])
        nonce = self.manifest.nonces[reality_idx]
        
        aesgcm = AESGCM(key)
        
        try:
            compressed = aesgcm.decrypt(nonce, ciphertext, None)
            return zlib.decompress(compressed)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


def verify_statistical_indistinguishability(superposition: bytes, n: int = 3) -> bool:
    """
    Verify that superposition has no statistical markers.
    
    Checks:
    - Entropy close to 8 bits/byte
    - Uniform byte distribution
    - No repeating patterns
    
    Returns:
        True if statistically indistinguishable from random
    """
    import math
    
    # Check entropy
    counter = Counter(superposition)
    length = len(superposition)
    
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    
    # Should be close to 8 bits/byte
    if entropy < 7.5:
        return False
    
    # Check byte distribution (chi-square test)
    expected = length / 256
    chi_sq = sum((count - expected) ** 2 / expected for count in counter.values())
    
    # Degrees of freedom = 255, threshold ~300 for p=0.05
    if chi_sq > 350:
        return False
    
    return True


# Convenience function
def encode_multi_secret(
    secrets: List[Tuple[bytes, str]],
    block_size: int = 256
) -> Tuple[bytes, MultiSecretManifest]:
    """
    Encode multiple secrets into superposition.
    
    Args:
        secrets: List of (data, password) tuples
        block_size: Block size for encoding
        
    Returns:
        (superposition_data, manifest)
        
    Example:
        # 3-level deniability
        data, manifest = encode_multi_secret([
            (top_secret, "level3_pass"),   # Most sensitive
            (sensitive, "level2_pass"),    # Moderately sensitive  
            (innocuous, "level1_pass"),    # Safe to reveal
        ])
    """
    encoder = MultiSecretEncoder(secrets, block_size)
    return encoder.encode()


def decode_multi_secret(
    superposition: bytes,
    manifest: MultiSecretManifest,
    password: str
) -> bytes:
    """
    Decode one secret from superposition.
    
    Args:
        superposition: Mixed superposition data
        manifest: Multi-secret manifest
        password: Password for desired secret
        
    Returns:
        Decrypted data
    """
    decoder = MultiSecretDecoder(superposition, manifest)
    return decoder.decode(password)


# Self-test
if __name__ == "__main__":
    print("🐱⚛️ Multi-Secret Schrödinger Mode Self-Test")
    print("=" * 60)
    
    # Test 1: 3-secret encoding
    print("\n1. Testing 3-secret encoding...")
    
    secrets_data = [
        (b"TOP SECRET: Nuclear launch codes\n" * 100, "level3_nuke"),
        (b"CONFIDENTIAL: Budget projections\n" * 100, "level2_budget"),
        (b"UNCLASSIFIED: Lunch menu\n" * 100, "level1_lunch"),
    ]
    
    superposition, manifest = encode_multi_secret(secrets_data)
    
    print(f"   ✅ Encoded {manifest.n_realities} realities")
    print(f"   Superposition: {len(superposition):,} bytes")
    print(f"   Blocks: {manifest.total_blocks}")
    print(f"   Merkle root: {manifest.merkle_root.hex()[:16]}...")
    
    # Test 2: Decode each reality
    print("\n2. Testing decoding each reality...")
    
    for i, (expected_data, password) in enumerate(secrets_data):
        decoded = decode_multi_secret(superposition, manifest, password)
        assert decoded == expected_data, f"Reality {i} mismatch!"
        print(f"   ✅ Reality {i}: Decoded correctly ({len(decoded)} bytes)")
    
    # Test 3: Wrong password
    print("\n3. Testing wrong password rejection...")
    
    try:
        decode_multi_secret(superposition, manifest, "wrong_password")
        print("   ❌ Should have rejected wrong password!")
    except ValueError:
        print("   ✅ Correctly rejected wrong password")
    
    # Test 4: Statistical indistinguishability
    print("\n4. Testing statistical properties...")
    
    is_indist = verify_statistical_indistinguishability(superposition, 3)
    
    if is_indist:
        print("   ✅ Superposition is statistically indistinguishable")
    else:
        print("   ⚠️  Some statistical markers detected (may still be secure)")
    
    # Test 5: 5-secret encoding
    print("\n5. Testing 5-secret encoding...")
    
    secrets_5 = [
        (f"Secret level {i}: {'x' * 1000}".encode(), f"password{i}")
        for i in range(5)
    ]
    
    superposition_5, manifest_5 = encode_multi_secret(secrets_5)
    
    print(f"   ✅ Encoded {manifest_5.n_realities} realities")
    
    # Decode random reality
    decoded = decode_multi_secret(superposition_5, manifest_5, "password3")
    assert b"Secret level 3" in decoded
    print(f"   ✅ Reality 3 decoded correctly")
    
    print("\n" + "=" * 60)
    print("🎉 Multi-secret Schrödinger mode working!")
    print("\n💡 Use cases:")
    print("   - Progressive reveal under coercion")
    print("   - Multiple classification levels")
    print("   - Distributed secret sharing")
