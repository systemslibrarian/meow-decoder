"""
Merkle Tree for Chunk Integrity Verification
Enables early detection of tampered chunks during decode

Security Model:
- Build Merkle tree over all chunks
- Root hash stored in authenticated manifest
- Verify each chunk as received
- Detect tampering before full decode
- Prevents wasting time on corrupted data
"""

import hashlib
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class MerkleProof:
    """
    Merkle proof for chunk verification.
    
    Attributes:
        chunk_index: Index of chunk being verified
        chunk_hash: Hash of the chunk
        proof_hashes: Sibling hashes for verification path
        root_hash: Merkle tree root hash
    """
    chunk_index: int
    chunk_hash: bytes
    proof_hashes: List[bytes]
    root_hash: bytes


class MerkleTree:
    """
    Merkle tree for chunk integrity.
    
    Security:
        - SHA-256 for all hashes
        - Binary tree structure
        - Log(N) proof size
        - Constant-time verification
    """
    
    def __init__(self, chunks: List[bytes]):
        """
        Build Merkle tree from chunks.
        
        Args:
            chunks: List of chunk data
            
        Note:
            Hashes are computed immediately.
            Store only hashes, not chunk data.
        """
        if not chunks:
            raise ValueError("Cannot build tree from empty chunks")
        
        self.num_chunks = len(chunks)
        
        # Compute leaf hashes
        self.leaf_hashes = [self._hash(chunk) for chunk in chunks]
        
        # Build tree
        self.tree = self._build_tree(self.leaf_hashes)
        
        # Root is last element
        self.root_hash = self.tree[-1][0] if self.tree else self.leaf_hashes[0]
    
    @staticmethod
    def _hash(data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def _hash_pair(left: bytes, right: bytes) -> bytes:
        """Hash a pair of nodes."""
        return hashlib.sha256(left + right).digest()
    
    def _build_tree(self, leaf_hashes: List[bytes]) -> List[List[bytes]]:
        """
        Build Merkle tree from leaf hashes.
        
        Returns:
            List of tree levels (leaves to root)
        """
        if len(leaf_hashes) == 1:
            return [leaf_hashes]
        
        tree = [leaf_hashes]
        current_level = leaf_hashes
        
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                
                if i + 1 < len(current_level):
                    # Pair exists
                    right = current_level[i + 1]
                else:
                    # Odd number, duplicate last
                    right = left
                
                parent = self._hash_pair(left, right)
                next_level.append(parent)
            
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_root(self) -> bytes:
        """Get Merkle root hash."""
        return self.root_hash
    
    def get_proof(self, chunk_index: int) -> MerkleProof:
        """
        Generate Merkle proof for chunk.
        
        Args:
            chunk_index: Index of chunk to prove
            
        Returns:
            MerkleProof with verification path
            
        Raises:
            ValueError: If chunk_index out of range
        """
        if chunk_index < 0 or chunk_index >= self.num_chunks:
            raise ValueError(f"Invalid chunk index: {chunk_index}")
        
        chunk_hash = self.leaf_hashes[chunk_index]
        proof_hashes = []
        
        # Walk up tree collecting sibling hashes
        index = chunk_index
        
        for level in self.tree[:-1]:  # Exclude root level
            # Is this a left or right child?
            is_left = (index % 2 == 0)
            sibling_index = index + 1 if is_left else index - 1
            
            # Get sibling hash if it exists
            if sibling_index < len(level):
                proof_hashes.append(level[sibling_index])
            else:
                # Odd number of nodes, sibling is same as current
                proof_hashes.append(level[index])
            
            # Move to parent level
            index = index // 2
        
        return MerkleProof(
            chunk_index=chunk_index,
            chunk_hash=chunk_hash,
            proof_hashes=proof_hashes,
            root_hash=self.root_hash
        )
    
    @staticmethod
    def verify_proof(chunk_data: bytes, proof: MerkleProof) -> bool:
        """
        Verify Merkle proof.
        
        Args:
            chunk_data: Actual chunk data
            proof: Merkle proof from get_proof()
            
        Returns:
            True if proof valid, False otherwise
            
        Security:
            - Recomputes chunk hash
            - Walks up tree with proof hashes
            - Compares final hash to root
            - Constant-time comparison
        """
        # Compute chunk hash
        computed_hash = hashlib.sha256(chunk_data).digest()
        
        # Check chunk hash matches proof
        if computed_hash != proof.chunk_hash:
            return False
        
        # Walk up tree with proof hashes
        current_hash = computed_hash
        index = proof.chunk_index
        
        for sibling_hash in proof.proof_hashes:
            is_left = (index % 2 == 0)
            
            if is_left:
                # Current is left child
                current_hash = MerkleTree._hash_pair(current_hash, sibling_hash)
            else:
                # Current is right child
                current_hash = MerkleTree._hash_pair(sibling_hash, current_hash)
            
            index = index // 2
        
        # Compare to root (constant-time)
        import secrets
        return secrets.compare_digest(current_hash, proof.root_hash)


def build_merkle_tree_from_chunks(chunks: List[bytes]) -> Tuple[bytes, MerkleTree]:
    """
    Convenience function to build tree and get root.
    
    Args:
        chunks: List of chunk data
        
    Returns:
        Tuple of (root_hash, tree)
    """
    tree = MerkleTree(chunks)
    return tree.get_root(), tree


def verify_chunk_with_proof(
    chunk_data: bytes,
    chunk_index: int,
    root_hash: bytes,
    proof_hashes: List[bytes]
) -> bool:
    """
    Verify chunk without full tree.
    
    Args:
        chunk_data: Chunk to verify
        chunk_index: Chunk index
        root_hash: Expected Merkle root
        proof_hashes: Sibling hashes for proof path
        
    Returns:
        True if valid, False otherwise
        
    Note:
        Use this during decode when you don't have full tree.
    """
    chunk_hash = hashlib.sha256(chunk_data).digest()
    
    proof = MerkleProof(
        chunk_index=chunk_index,
        chunk_hash=chunk_hash,
        proof_hashes=proof_hashes,
        root_hash=root_hash
    )
    
    return MerkleTree.verify_proof(chunk_data, proof)


# Example usage
if __name__ == "__main__":
    print("Merkle Tree Test")
    print("=" * 50)
    
    # Create test chunks
    chunks = [
        b"Chunk 0: The quick brown fox",
        b"Chunk 1: jumps over the lazy dog",
        b"Chunk 2: Pack my box with five dozen",
        b"Chunk 3: liquor jugs",
        b"Chunk 4: The five boxing wizards",
        b"Chunk 5: jump quickly",
        b"Chunk 6: Sphinx of black quartz",
        b"Chunk 7: judge my vow"
    ]
    
    print(f"\nBuilding Merkle tree from {len(chunks)} chunks...")
    
    # Build tree
    root_hash, tree = build_merkle_tree_from_chunks(chunks)
    
    print(f"✅ Tree built successfully")
    print(f"   Root hash: {root_hash.hex()[:32]}...")
    print(f"   Tree height: {len(tree.tree)}")
    
    # Test proof generation and verification
    print(f"\nTesting proof for chunk 3:")
    
    proof = tree.get_proof(3)
    print(f"   Chunk index: {proof.chunk_index}")
    print(f"   Chunk hash: {proof.chunk_hash.hex()[:32]}...")
    print(f"   Proof size: {len(proof.proof_hashes)} hashes")
    
    # Verify valid chunk
    valid = MerkleTree.verify_proof(chunks[3], proof)
    print(f"✅ Valid chunk verified: {valid}")
    
    # Test tampered chunk
    tampered = b"Chunk 3: TAMPERED DATA"
    invalid = MerkleTree.verify_proof(tampered, proof)
    print(f"❌ Tampered chunk rejected: {not invalid}")
    
    # Test all chunks
    print(f"\nVerifying all chunks:")
    all_valid = True
    
    for i, chunk in enumerate(chunks):
        proof = tree.get_proof(i)
        valid = MerkleTree.verify_proof(chunk, proof)
        
        if not valid:
            print(f"   ❌ Chunk {i} failed!")
            all_valid = False
    
    if all_valid:
        print(f"   ✅ All {len(chunks)} chunks verified successfully")
    
    # Test proof size scaling
    print(f"\nProof size analysis:")
    for n in [10, 100, 1000, 10000]:
        test_chunks = [f"Chunk {i}".encode() for i in range(n)]
        test_tree = MerkleTree(test_chunks)
        test_proof = test_tree.get_proof(0)
        
        proof_size = len(test_proof.proof_hashes) * 32  # 32 bytes per hash
        print(f"   {n:5d} chunks → {len(test_proof.proof_hashes):2d} hashes ({proof_size:3d} bytes)")
    
    print(f"\n✅ Merkle tree module working!")
    print(f"   Proof size: O(log N)")
    print(f"   Verification: O(log N)")
    print(f"   Early tamper detection: ✅")
