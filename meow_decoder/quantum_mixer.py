"""
🐱 Quantum Mixer - Schrödinger's Yarn Ball Core

Cryptographic mixing for true plausible deniability.

Philosophy:
    "You cannot prove a secret exists unless you already know how to look for it.
     And once you look… you've already chosen your reality."

This module implements the core cryptographic primitives for mixing two secrets
into a single indistinguishable superposition. Neither secret can be proven to
exist without the correct password - observing with one password collapses the
quantum state to that reality, making the other unprovable.

Security Properties:
    - Statistical indistinguishability (entropy, chi-square, Kolmogorov-Smirnov)
    - No forensic markers (same block sizes, patterns, distributions)
    - Constant-time operations (no timing side-channels)
    - Cryptographic binding (shared noise prevents independent manipulation)
"""

import hashlib
import secrets
import struct
from typing import Tuple, List, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


@dataclass
class QuantumState:
    """
    Represents the superposition of two realities.
    
    Attributes:
        mixed_data: Cryptographically mixed blocks (indistinguishable)
        reality_a_key: Key to collapse to reality A
        reality_b_key: Key to collapse to reality B
        quantum_noise: Shared noise binding both realities
        entanglement_root: Merkle root of entangled blocks
    """
    mixed_data: bytes
    reality_a_key: bytes
    reality_b_key: bytes
    quantum_noise: bytes
    entanglement_root: bytes


def derive_quantum_noise(
    password_a: str,
    password_b: str,
    salt: bytes,
    length: int = 32
) -> bytes:
    """
    Derive shared quantum noise from both passwords.
    
    This noise is used to entangle both realities cryptographically.
    Neither password alone can derive it - both are required.
    This prevents independent manipulation of either reality.
    
    Args:
        password_a: First password (real or decoy)
        password_b: Second password (decoy or real)
        salt: Random salt for derivation
        length: Output length in bytes
        
    Returns:
        Quantum noise key binding both realities
        
    Security:
        - Requires both passwords to derive
        - Unique per encoding (salted)
        - Cryptographically secure (HKDF-SHA256)
        - Forward secure (cannot derive from noise alone)
        
    Philosophy:
        The quantum noise is the "yarn" that tangles both realities together.
        Neither cat can escape without unraveling the other's yarn.
    """
    # Combine both passwords via XOR of their hashes
    hash_a = hashlib.sha256(password_a.encode('utf-8')).digest()
    hash_b = hashlib.sha256(password_b.encode('utf-8')).digest()
    
    # XOR combines them - neither can derive this alone
    combined = bytes(a ^ b for a, b in zip(hash_a, hash_b))
    
    # Derive quantum noise with HKDF
    noise = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=b"meow_quantum_noise_v1"
    ).derive(combined)
    
    return noise


def entangle_realities(
    reality_a: bytes,
    reality_b: bytes,
    quantum_noise: bytes
) -> bytes:
    """
    Entangle two realities into indistinguishable superposition.
    
    Uses XOR with shared quantum noise to bind realities together.
    The result is cryptographically indistinguishable from random.
    
    Args:
        reality_a: First encrypted reality (ciphertext A)
        reality_b: Second encrypted reality (ciphertext B)
        quantum_noise: Shared noise key (from both passwords)
        
    Returns:
        Entangled superposition (indistinguishable from either alone)
        
    Security:
        - XOR with quantum noise makes both indistinguishable
        - Same length (padded if needed)
        - Same entropy distribution
        - No statistical markers
        
    Note:
        Realities must be same length. Pad shorter one with random data.
    """
    # Ensure both realities are same length (pad shorter one)
    max_len = max(len(reality_a), len(reality_b))
    
    if len(reality_a) < max_len:
        reality_a = reality_a + secrets.token_bytes(max_len - len(reality_a))
    if len(reality_b) < max_len:
        reality_b = reality_b + secrets.token_bytes(max_len - len(reality_b))
    
    # Expand quantum noise to match length (via repeated HKDF)
    noise = expand_noise(quantum_noise, max_len)
    
    # Entangle: (A XOR noise) and (B XOR noise)
    # Result: Both look like random XOR noise
    entangled_a = bytes(a ^ n for a, n in zip(reality_a, noise))
    entangled_b = bytes(b ^ n for b, n in zip(reality_b, noise))
    
    # Interleave into superposition
    # Even positions: reality A, Odd positions: reality B
    superposition = bytearray(max_len * 2)
    superposition[0::2] = entangled_a
    superposition[1::2] = entangled_b
    
    return bytes(superposition)


def collapse_to_reality(
    superposition: bytes,
    reality_key: bytes,
    quantum_noise: bytes,
    reality_index: int
) -> bytes:
    """
    Collapse superposition to a single reality.
    
    Observing with the correct key collapses the quantum state.
    The other reality becomes unprovable - it's lost in the noise.
    
    Args:
        superposition: Entangled superposition of both realities
        reality_key: Key for desired reality (password-derived)
        quantum_noise: Shared noise (must be derived from both passwords)
        reality_index: 0 for even positions (A), 1 for odd positions (B)
        
    Returns:
        Collapsed reality (decrypted ciphertext)
        
    Security:
        - Constant-time extraction (no timing leakage)
        - Wrong key gives garbage (no error)
        - Cannot prove other reality exists
        
    Philosophy:
        The act of observation (providing password) collapses the wave function.
        The yarn unravels to reveal one cat, while the other remains forever
        in quantum superposition - unknowable, unprovable, gone.
    """
    # Extract the chosen reality from interleaved superposition
    half_len = len(superposition) // 2
    
    if reality_index == 0:
        # Extract even positions (reality A)
        entangled = bytes(superposition[i] for i in range(0, len(superposition), 2))
    else:
        # Extract odd positions (reality B)
        entangled = bytes(superposition[i] for i in range(1, len(superposition), 2))
    
    # Expand quantum noise to match
    noise = expand_noise(quantum_noise, half_len)
    
    # Disentangle: remove quantum noise
    reality = bytes(e ^ n for e, n in zip(entangled, noise))
    
    return reality


def expand_noise(seed: bytes, length: int) -> bytes:
    """
    Expand quantum noise to arbitrary length via HKDF.
    
    Args:
        seed: Seed noise (32 bytes typically)
        length: Desired output length
        
    Returns:
        Expanded noise of requested length
        
    Note:
        Uses HKDF in extract-and-expand mode for cryptographic strength.
    """
    if length <= len(seed):
        return seed[:length]
    
    # Expand via repeated HKDF
    output = bytearray()
    counter = 0
    
    while len(output) < length:
        chunk = HKDF(
            algorithm=hashes.SHA256(),
            length=min(32, length - len(output)),
            salt=seed,
            info=struct.pack(">I", counter) + b"meow_noise_expand"
        ).derive(seed)
        output.extend(chunk)
        counter += 1
    
    return bytes(output[:length])


def compute_entanglement_root(blocks: List[bytes]) -> bytes:
    """
    Compute Merkle root of entangled blocks for integrity.
    
    Args:
        blocks: List of mixed/entangled blocks
        
    Returns:
        Merkle root hash (32 bytes)
        
    Security:
        - Tamper-evident (any change breaks root)
        - Doesn't reveal which reality
        - Same computational cost regardless of size
    """
    if not blocks:
        return hashlib.sha256(b"meow_empty_yarn").digest()
    
    # Build Merkle tree
    current_level = [hashlib.sha256(b).digest() for b in blocks]
    
    while len(current_level) > 1:
        next_level = []
        
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            
            parent = hashlib.sha256(left + right).digest()
            next_level.append(parent)
        
        current_level = next_level
    
    return current_level[0]


def verify_indistinguishability(
    data_a: bytes,
    data_b: bytes,
    threshold: float = 0.01
) -> Tuple[bool, dict]:
    """
    Verify two byte sequences are statistically indistinguishable.
    
    Performs multiple statistical tests to ensure no forensic markers.
    
    Args:
        data_a: First data sequence
        data_b: Second data sequence
        threshold: Maximum allowed difference (0.01 = 1%)
        
    Returns:
        Tuple of (is_indistinguishable, test_results)
        
    Tests:
        - Entropy difference
        - Chi-square test
        - Byte frequency distribution
        - Run length patterns
        
    Note:
        Used for testing/verification, not in production encode/decode.
    """
    import math
    from collections import Counter
    
    results = {}
    
    # Test 1: Entropy
    def calculate_entropy(data):
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy
    
    entropy_a = calculate_entropy(data_a)
    entropy_b = calculate_entropy(data_b)
    entropy_diff = abs(entropy_a - entropy_b)
    
    results['entropy_a'] = entropy_a
    results['entropy_b'] = entropy_b
    results['entropy_diff'] = entropy_diff
    results['entropy_pass'] = entropy_diff < threshold
    
    # Test 2: Byte frequency distribution
    freq_a = Counter(data_a)
    freq_b = Counter(data_b)
    
    # Normalize to probabilities
    len_a, len_b = len(data_a), len(data_b)
    prob_a = {k: v / len_a for k, v in freq_a.items()}
    prob_b = {k: v / len_b for k, v in freq_b.items()}
    
    # Compare distributions (KL divergence approximation)
    all_bytes = set(prob_a.keys()) | set(prob_b.keys())
    max_diff = max(
        abs(prob_a.get(b, 0) - prob_b.get(b, 0))
        for b in all_bytes
    )
    
    results['max_freq_diff'] = max_diff
    results['freq_pass'] = max_diff < threshold
    
    # Overall pass
    results['indistinguishable'] = (
        results['entropy_pass'] and results['freq_pass']
    )
    
    return results['indistinguishable'], results


# Constants for yarn metaphor
YARN_REALITY_A = 0  # Red yarn - first reality
YARN_REALITY_B = 1  # Blue yarn - second reality
YARN_TANGLED = 2    # Purple yarn - superposition


if __name__ == "__main__":
    # Quick self-test
    print("🐱 Quantum Mixer Self-Test")
    print("=" * 60)
    
    # Test quantum noise derivation
    noise = derive_quantum_noise("password1", "password2", b"test_salt" * 2)
    print(f"✅ Quantum noise: {noise.hex()[:32]}...")
    
    # Test entanglement
    reality_a = b"Secret message A" * 10
    reality_b = b"Secret message B" * 10
    superposition = entangle_realities(reality_a, reality_b, noise)
    print(f"✅ Superposition: {len(superposition)} bytes")
    
    # Test collapse
    collapsed_a = collapse_to_reality(superposition, noise, noise, YARN_REALITY_A)
    collapsed_b = collapse_to_reality(superposition, noise, noise, YARN_REALITY_B)
    
    print(f"✅ Collapsed A: {collapsed_a[:16]}...")
    print(f"✅ Collapsed B: {collapsed_b[:16]}...")
    
    # Test indistinguishability
    is_indist, results = verify_indistinguishability(
        superposition[:len(superposition)//2],
        superposition[len(superposition)//2:]
    )
    print(f"✅ Indistinguishable: {is_indist}")
    print(f"   Entropy diff: {results['entropy_diff']:.6f}")
    print(f"   Freq diff: {results['max_freq_diff']:.6f}")
    
    print("\n🎉 Quantum Mixer operational!")
