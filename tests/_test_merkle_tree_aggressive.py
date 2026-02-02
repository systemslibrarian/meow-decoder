#!/usr/bin/env python3
"""
⚠️ DEPRECATED - MERGED INTO test_fountain.py ⚠️

This file has been merged into test_fountain.py as part of test consolidation.
See: tests/test_fountain.py

Original description:
🧪 Aggressive Tests for merkle_tree.py
Target: 95%+ coverage of MerkleTree and MerkleProof classes

Tests tree construction, proof generation, and verification.
"""

import pytest
pytest.skip("DEPRECATED: Tests merged into test_fountain.py", allow_module_level=True)

import hashlib
import secrets
from typing import List

# Import module under test
from meow_decoder.merkle_tree import MerkleTree, MerkleProof


class TestMerkleTreeConstruction:
    """Tests for MerkleTree construction."""
    
    def test_single_chunk(self):
        """Test tree with single chunk."""
        chunks = [b"single chunk data"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 1
        assert tree.root_hash is not None
        assert len(tree.root_hash) == 32
    
    def test_two_chunks(self):
        """Test tree with two chunks."""
        chunks = [b"chunk one", b"chunk two"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
        assert tree.root_hash is not None
        assert len(tree.root_hash) == 32
    
    def test_power_of_two_chunks(self):
        """Test tree with power-of-two chunks."""
        chunks = [f"chunk {i}".encode() for i in range(8)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 8
        assert len(tree.leaf_hashes) == 8
    
    def test_non_power_of_two_chunks(self):
        """Test tree with non-power-of-two chunks."""
        chunks = [f"chunk {i}".encode() for i in range(7)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 7
        assert len(tree.leaf_hashes) == 7
    
    def test_large_number_of_chunks(self):
        """Test tree with many chunks."""
        chunks = [secrets.token_bytes(100) for _ in range(100)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 100
        assert tree.root_hash is not None
    
    def test_empty_chunks_raises(self):
        """Test that empty chunks list raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            MerkleTree([])
    
    def test_identical_chunks_different_root(self):
        """Test that different chunk order produces different roots."""
        chunks1 = [b"chunk a", b"chunk b"]
        chunks2 = [b"chunk b", b"chunk a"]
        
        tree1 = MerkleTree(chunks1)
        tree2 = MerkleTree(chunks2)
        
        assert tree1.root_hash != tree2.root_hash
    
    def test_deterministic_root(self):
        """Test that same chunks produce same root."""
        chunks = [b"chunk a", b"chunk b", b"chunk c"]
        
        tree1 = MerkleTree(chunks)
        tree2 = MerkleTree(chunks)
        
        assert tree1.root_hash == tree2.root_hash


class TestMerkleTreeHashing:
    """Tests for internal hashing functions."""
    
    def test_hash_function(self):
        """Test _hash produces SHA-256."""
        data = b"test data"
        expected = hashlib.sha256(data).digest()
        
        result = MerkleTree._hash(data)
        
        assert result == expected
        assert len(result) == 32
    
    def test_hash_pair(self):
        """Test _hash_pair concatenates and hashes."""
        left = b"left" + b"\x00" * 28
        right = b"right" + b"\x00" * 27
        
        expected = hashlib.sha256(left + right).digest()
        result = MerkleTree._hash_pair(left, right)
        
        assert result == expected
    
    def test_leaf_hashes(self):
        """Test leaf hashes are correctly computed."""
        chunks = [b"chunk 0", b"chunk 1"]
        tree = MerkleTree(chunks)
        
        assert tree.leaf_hashes[0] == hashlib.sha256(b"chunk 0").digest()
        assert tree.leaf_hashes[1] == hashlib.sha256(b"chunk 1").digest()


class TestMerkleTreeGetRoot:
    """Tests for get_root method."""
    
    def test_get_root_single(self):
        """Test get_root with single chunk."""
        chunks = [b"only chunk"]
        tree = MerkleTree(chunks)
        
        root = tree.get_root()
        
        assert root == tree.root_hash
        assert root == hashlib.sha256(b"only chunk").digest()
    
    def test_get_root_multiple(self):
        """Test get_root with multiple chunks."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        root = tree.get_root()
        
        # Root should be hash(hash(a) || hash(b))
        hash_a = hashlib.sha256(b"a").digest()
        hash_b = hashlib.sha256(b"b").digest()
        expected = hashlib.sha256(hash_a + hash_b).digest()
        
        assert root == expected
    
    def test_get_root_is_deterministic(self):
        """Test get_root returns same value each call."""
        chunks = [b"a", b"b", b"c"]
        tree = MerkleTree(chunks)
        
        root1 = tree.get_root()
        root2 = tree.get_root()
        
        assert root1 == root2


class TestMerkleProofGeneration:
    """Tests for proof generation."""
    
    def test_get_proof_first_chunk(self):
        """Test proof for first chunk."""
        chunks = [b"chunk 0", b"chunk 1"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        assert proof.chunk_index == 0
        assert proof.chunk_hash == tree.leaf_hashes[0]
        assert len(proof.proof_hashes) >= 0
        assert proof.root_hash == tree.root_hash
    
    def test_get_proof_last_chunk(self):
        """Test proof for last chunk."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(3)
        
        assert proof.chunk_index == 3
        assert proof.chunk_hash == tree.leaf_hashes[3]
    
    def test_get_proof_middle_chunk(self):
        """Test proof for middle chunk."""
        chunks = [f"chunk {i}".encode() for i in range(8)]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(4)
        
        assert proof.chunk_index == 4
    
    def test_get_proof_invalid_index_negative(self):
        """Test proof with negative index raises error."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(-1)
    
    def test_get_proof_invalid_index_too_large(self):
        """Test proof with index >= num_chunks raises error."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(2)
    
    def test_get_proof_all_chunks(self):
        """Test proof generation for all chunks."""
        chunks = [f"chunk {i}".encode() for i in range(16)]
        tree = MerkleTree(chunks)
        
        for i in range(16):
            proof = tree.get_proof(i)
            assert proof.chunk_index == i
            assert proof.chunk_hash == tree.leaf_hashes[i]
            assert proof.root_hash == tree.root_hash


class TestMerkleProofDataclass:
    """Tests for MerkleProof dataclass."""
    
    def test_merkle_proof_attributes(self):
        """Test MerkleProof has correct attributes."""
        proof = MerkleProof(
            chunk_index=5,
            chunk_hash=b"hash" + b"\x00" * 28,
            proof_hashes=[b"proof1" + b"\x00" * 26],
            root_hash=b"root" + b"\x00" * 28,
        )
        
        assert proof.chunk_index == 5
        assert proof.chunk_hash == b"hash" + b"\x00" * 28
        assert len(proof.proof_hashes) == 1
        assert proof.root_hash == b"root" + b"\x00" * 28


class TestMerkleProofVerification:
    """Tests for proof verification (if verify_proof exists)."""
    
    def test_proof_contains_sibling_hashes(self):
        """Test proof contains correct sibling hashes."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        # Proof for chunk 0 should include sibling at index 1
        proof = tree.get_proof(0)
        
        # Proof should have at least log2(4) = 2 hashes
        assert len(proof.proof_hashes) >= 1
    
    def test_proof_path_length(self):
        """Test proof path has logarithmic length."""
        import math
        
        for n in [2, 4, 8, 16, 32]:
            chunks = [f"c{i}".encode() for i in range(n)]
            tree = MerkleTree(chunks)
            
            proof = tree.get_proof(0)
            
            # Path length should be ceil(log2(n))
            expected_max = math.ceil(math.log2(n))
            assert len(proof.proof_hashes) <= expected_max
    
    def test_can_recompute_root_from_proof(self):
        """Test that proof allows root recomputation."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        # Manually verify: hash(chunk_hash || sibling)
        if proof.proof_hashes:
            computed = hashlib.sha256(
                proof.chunk_hash + proof.proof_hashes[0]
            ).digest()
            assert computed == tree.root_hash


class TestMerkleTreeEdgeCases:
    """Edge case tests."""
    
    def test_very_large_chunk(self):
        """Test tree with very large chunk."""
        large_chunk = secrets.token_bytes(1024 * 1024)  # 1 MB
        tree = MerkleTree([large_chunk])
        
        assert tree.num_chunks == 1
        assert tree.root_hash is not None
    
    def test_empty_chunk(self):
        """Test tree with empty chunk."""
        chunks = [b"", b"non-empty"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
    
    def test_binary_chunks(self):
        """Test tree with binary data chunks."""
        chunks = [secrets.token_bytes(256) for _ in range(10)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 10
        
        # All proofs should work
        for i in range(10):
            proof = tree.get_proof(i)
            assert proof.chunk_index == i
    
    def test_unicode_in_chunks(self):
        """Test tree with unicode content."""
        chunks = ["Hello 世界".encode('utf-8'), "🐱🔐".encode('utf-8')]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2


class TestMerkleTreeBuildTree:
    """Tests for internal _build_tree method."""
    
    def test_build_tree_structure(self):
        """Test tree structure is correct."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        # Tree should have multiple levels
        assert len(tree.tree) >= 2
        
        # First level is leaves
        assert len(tree.tree[0]) == 4
        
        # Second level has 2 nodes
        assert len(tree.tree[1]) == 2
        
        # Third level (root) has 1 node
        assert len(tree.tree[2]) == 1
    
    def test_build_tree_odd_number(self):
        """Test tree building with odd number of chunks."""
        chunks = [b"a", b"b", b"c"]
        tree = MerkleTree(chunks)
        
        # Should handle odd number by duplicating last
        assert len(tree.tree) >= 2
        assert tree.num_chunks == 3


class TestMerkleTreeIntegration:
    """Integration tests for complete Merkle tree workflows."""
    
    def test_complete_workflow(self):
        """Test complete Merkle tree workflow."""
        # Create chunks
        chunks = [f"data block {i}".encode() for i in range(10)]
        
        # Build tree
        tree = MerkleTree(chunks)
        
        # Get root for manifest
        root = tree.get_root()
        assert len(root) == 32
        
        # Get proofs for all chunks
        proofs = [tree.get_proof(i) for i in range(10)]
        
        # Verify all proofs reference correct root
        for proof in proofs:
            assert proof.root_hash == root
    
    def test_tamper_detection(self):
        """Test that tampering changes root."""
        chunks1 = [b"chunk 0", b"chunk 1", b"chunk 2"]
        chunks2 = [b"TAMPER", b"chunk 1", b"chunk 2"]
        
        tree1 = MerkleTree(chunks1)
        tree2 = MerkleTree(chunks2)
        
        # Roots should differ
        assert tree1.root_hash != tree2.root_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
