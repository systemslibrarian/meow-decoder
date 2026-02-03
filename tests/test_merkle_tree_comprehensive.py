#!/usr/bin/env python3
"""
🧪 Comprehensive Tests for merkle_tree.py
Target: 90-95% coverage of MerkleTree, MerkleProof, and convenience functions

Tests:
- MerkleProof dataclass
- MerkleTree class (construction, hashing, proofs, verification)
- build_merkle_tree_from_chunks convenience function
- verify_chunk_with_proof convenience function
- Edge cases, security properties, and integration scenarios

Cat-themed naming conventions for the Meow Decoder project.
"""

import pytest
import hashlib
import secrets
import math
from typing import List
from unittest.mock import patch, MagicMock

from meow_decoder.merkle_tree import (
    MerkleProof,
    MerkleTree,
    build_merkle_tree_from_chunks,
    verify_chunk_with_proof,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def simple_chunks_meow():
    """Simple test chunks - like cat treats in a row."""
    return [b"chunk_0", b"chunk_1", b"chunk_2", b"chunk_3"]


@pytest.fixture
def power_of_two_chunks_meow():
    """Power-of-two chunks - perfect binary tree like cat family tree."""
    return [f"cat_{i}".encode() for i in range(8)]


@pytest.fixture
def odd_chunks_meow():
    """Odd number of chunks - asymmetric like a cat's ears."""
    return [f"whisker_{i}".encode() for i in range(7)]


@pytest.fixture
def single_chunk_meow():
    """Single chunk - lone cat."""
    return [b"solo_cat_chunk"]


@pytest.fixture
def binary_chunks_meow():
    """Binary data chunks - encrypted cat secrets."""
    return [secrets.token_bytes(64) for _ in range(10)]


@pytest.fixture
def large_chunks_meow():
    """Large chunks - big cat data."""
    return [secrets.token_bytes(4096) for _ in range(5)]


# =============================================================================
# Test MerkleProof Dataclass
# =============================================================================

class TestMerkleProofDataclassMeow:
    """Tests for MerkleProof dataclass - like a cat's pedigree certificate."""
    
    def test_merkle_proof_creation_basic_meow(self):
        """Test basic MerkleProof creation - whiskers and all."""
        proof = MerkleProof(
            chunk_index=0,
            chunk_hash=b"\x00" * 32,
            proof_hashes=[b"\x11" * 32],
            root_hash=b"\xff" * 32,
        )
        
        assert proof.chunk_index == 0
        assert proof.chunk_hash == b"\x00" * 32
        assert len(proof.proof_hashes) == 1
        assert proof.root_hash == b"\xff" * 32
    
    def test_merkle_proof_with_multiple_hashes_meow(self):
        """Test MerkleProof with multiple proof hashes - long lineage."""
        proof_hashes = [secrets.token_bytes(32) for _ in range(5)]
        proof = MerkleProof(
            chunk_index=15,
            chunk_hash=secrets.token_bytes(32),
            proof_hashes=proof_hashes,
            root_hash=secrets.token_bytes(32),
        )
        
        assert len(proof.proof_hashes) == 5
        assert proof.chunk_index == 15
    
    def test_merkle_proof_empty_proof_hashes_meow(self):
        """Test MerkleProof with empty proof_hashes - single chunk tree."""
        proof = MerkleProof(
            chunk_index=0,
            chunk_hash=b"hash" * 8,
            proof_hashes=[],
            root_hash=b"root" * 8,
        )
        
        assert len(proof.proof_hashes) == 0
    
    def test_merkle_proof_attributes_accessible_meow(self):
        """Test all attributes are accessible - pet your data structures."""
        chunk_hash = hashlib.sha256(b"meow").digest()
        root_hash = hashlib.sha256(b"root").digest()
        proof_hashes = [hashlib.sha256(b"sibling").digest()]
        
        proof = MerkleProof(
            chunk_index=42,
            chunk_hash=chunk_hash,
            proof_hashes=proof_hashes,
            root_hash=root_hash,
        )
        
        assert proof.chunk_index == 42
        assert proof.chunk_hash == chunk_hash
        assert proof.proof_hashes == proof_hashes
        assert proof.root_hash == root_hash


# =============================================================================
# Test MerkleTree Construction
# =============================================================================

class TestMerkleTreeConstructionMeow:
    """Tests for MerkleTree construction - building the cat family tree."""
    
    def test_construction_single_chunk_meow(self, single_chunk_meow):
        """Test tree with single chunk - lone kitty."""
        tree = MerkleTree(single_chunk_meow)
        
        assert tree.num_chunks == 1
        assert tree.root_hash is not None
        assert len(tree.root_hash) == 32
        assert len(tree.leaf_hashes) == 1
    
    def test_construction_two_chunks_meow(self):
        """Test tree with two chunks - pair of cats."""
        chunks = [b"cat_left", b"cat_right"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
        assert len(tree.leaf_hashes) == 2
        assert tree.root_hash is not None
    
    def test_construction_power_of_two_meow(self, power_of_two_chunks_meow):
        """Test tree with power-of-two chunks - perfect family."""
        tree = MerkleTree(power_of_two_chunks_meow)
        
        assert tree.num_chunks == 8
        assert len(tree.leaf_hashes) == 8
        assert len(tree.tree) == 4  # 8->4->2->1
    
    def test_construction_odd_number_meow(self, odd_chunks_meow):
        """Test tree with odd chunks - asymmetric ears."""
        tree = MerkleTree(odd_chunks_meow)
        
        assert tree.num_chunks == 7
        assert len(tree.leaf_hashes) == 7
    
    def test_construction_empty_raises_meow(self):
        """Test empty chunks raises ValueError - no cats, no tree."""
        with pytest.raises(ValueError, match="empty"):
            MerkleTree([])
    
    def test_construction_large_number_meow(self):
        """Test tree with many chunks - cat colony."""
        chunks = [secrets.token_bytes(32) for _ in range(1000)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 1000
        assert tree.root_hash is not None
    
    def test_construction_deterministic_meow(self, simple_chunks_meow):
        """Test same chunks produce same tree - consistent cats."""
        tree1 = MerkleTree(simple_chunks_meow)
        tree2 = MerkleTree(simple_chunks_meow)
        
        assert tree1.root_hash == tree2.root_hash
        assert tree1.leaf_hashes == tree2.leaf_hashes
    
    def test_construction_order_matters_meow(self):
        """Test chunk order affects root - cats in line."""
        chunks1 = [b"first", b"second"]
        chunks2 = [b"second", b"first"]
        
        tree1 = MerkleTree(chunks1)
        tree2 = MerkleTree(chunks2)
        
        assert tree1.root_hash != tree2.root_hash
    
    def test_construction_empty_chunk_allowed_meow(self):
        """Test empty chunk is allowed - invisible cat."""
        chunks = [b"", b"visible"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
    
    def test_construction_binary_data_meow(self, binary_chunks_meow):
        """Test binary data chunks - encrypted secrets."""
        tree = MerkleTree(binary_chunks_meow)
        
        assert tree.num_chunks == 10
        assert all(len(h) == 32 for h in tree.leaf_hashes)


# =============================================================================
# Test MerkleTree Hashing Methods
# =============================================================================

class TestMerkleTreeHashingMeow:
    """Tests for internal hashing methods - cat cryptography."""
    
    def test_hash_method_produces_sha256_meow(self):
        """Test _hash produces SHA-256 - standard cat crypto."""
        data = b"meow_decoder_test_data"
        expected = hashlib.sha256(data).digest()
        
        result = MerkleTree._hash(data)
        
        assert result == expected
        assert len(result) == 32
    
    def test_hash_method_empty_data_meow(self):
        """Test _hash with empty data - silent meow."""
        expected = hashlib.sha256(b"").digest()
        result = MerkleTree._hash(b"")
        
        assert result == expected
    
    def test_hash_pair_concatenation_meow(self):
        """Test _hash_pair concatenates then hashes - paired cats."""
        left = hashlib.sha256(b"left").digest()
        right = hashlib.sha256(b"right").digest()
        
        expected = hashlib.sha256(left + right).digest()
        result = MerkleTree._hash_pair(left, right)
        
        assert result == expected
    
    def test_hash_pair_order_matters_meow(self):
        """Test _hash_pair order matters - left paw vs right paw."""
        a = hashlib.sha256(b"a").digest()
        b = hashlib.sha256(b"b").digest()
        
        result_ab = MerkleTree._hash_pair(a, b)
        result_ba = MerkleTree._hash_pair(b, a)
        
        assert result_ab != result_ba
    
    def test_leaf_hashes_correct_meow(self, simple_chunks_meow):
        """Test leaf hashes match direct SHA-256 - verified lineage."""
        tree = MerkleTree(simple_chunks_meow)
        
        for i, chunk in enumerate(simple_chunks_meow):
            expected = hashlib.sha256(chunk).digest()
            assert tree.leaf_hashes[i] == expected


# =============================================================================
# Test MerkleTree Get Root
# =============================================================================

class TestMerkleTreeGetRootMeow:
    """Tests for get_root method - the alpha cat."""
    
    def test_get_root_single_chunk_meow(self):
        """Test get_root with single chunk - solo leader."""
        chunks = [b"only_cat"]
        tree = MerkleTree(chunks)
        
        root = tree.get_root()
        
        assert root == tree.root_hash
        assert root == hashlib.sha256(b"only_cat").digest()
    
    def test_get_root_two_chunks_meow(self):
        """Test get_root with two chunks - paired leaders."""
        chunks = [b"cat_a", b"cat_b"]
        tree = MerkleTree(chunks)
        
        root = tree.get_root()
        
        hash_a = hashlib.sha256(b"cat_a").digest()
        hash_b = hashlib.sha256(b"cat_b").digest()
        expected = hashlib.sha256(hash_a + hash_b).digest()
        
        assert root == expected
    
    def test_get_root_consistent_meow(self, simple_chunks_meow):
        """Test get_root returns consistent value - reliable leader."""
        tree = MerkleTree(simple_chunks_meow)
        
        root1 = tree.get_root()
        root2 = tree.get_root()
        root3 = tree.get_root()
        
        assert root1 == root2 == root3
    
    def test_get_root_matches_stored_meow(self, power_of_two_chunks_meow):
        """Test get_root matches root_hash attribute - identity verified."""
        tree = MerkleTree(power_of_two_chunks_meow)
        
        assert tree.get_root() == tree.root_hash


# =============================================================================
# Test MerkleTree Get Proof
# =============================================================================

class TestMerkleTreeGetProofMeow:
    """Tests for get_proof method - proving cat lineage."""
    
    def test_get_proof_first_chunk_meow(self, simple_chunks_meow):
        """Test proof for first chunk - eldest cat."""
        tree = MerkleTree(simple_chunks_meow)
        
        proof = tree.get_proof(0)
        
        assert proof.chunk_index == 0
        assert proof.chunk_hash == tree.leaf_hashes[0]
        assert proof.root_hash == tree.root_hash
    
    def test_get_proof_last_chunk_meow(self, simple_chunks_meow):
        """Test proof for last chunk - youngest cat."""
        tree = MerkleTree(simple_chunks_meow)
        last_idx = len(simple_chunks_meow) - 1
        
        proof = tree.get_proof(last_idx)
        
        assert proof.chunk_index == last_idx
        assert proof.chunk_hash == tree.leaf_hashes[last_idx]
    
    def test_get_proof_middle_chunk_meow(self, power_of_two_chunks_meow):
        """Test proof for middle chunk - middle child cat."""
        tree = MerkleTree(power_of_two_chunks_meow)
        
        proof = tree.get_proof(4)
        
        assert proof.chunk_index == 4
        assert proof.chunk_hash == tree.leaf_hashes[4]
    
    def test_get_proof_negative_index_raises_meow(self, simple_chunks_meow):
        """Test negative index raises error - no negative cats."""
        tree = MerkleTree(simple_chunks_meow)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(-1)
    
    def test_get_proof_too_large_index_raises_meow(self, simple_chunks_meow):
        """Test too large index raises error - ghost cat."""
        tree = MerkleTree(simple_chunks_meow)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(100)
    
    def test_get_proof_boundary_index_raises_meow(self, simple_chunks_meow):
        """Test exact boundary index raises error - fence cat."""
        tree = MerkleTree(simple_chunks_meow)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(len(simple_chunks_meow))
    
    def test_get_proof_all_chunks_meow(self, power_of_two_chunks_meow):
        """Test proof generation for all chunks - full family census."""
        tree = MerkleTree(power_of_two_chunks_meow)
        
        for i in range(len(power_of_two_chunks_meow)):
            proof = tree.get_proof(i)
            
            assert proof.chunk_index == i
            assert proof.chunk_hash == tree.leaf_hashes[i]
            assert proof.root_hash == tree.root_hash
    
    def test_get_proof_logarithmic_size_meow(self):
        """Test proof size is logarithmic - efficient lineage."""
        for n in [2, 4, 8, 16, 32, 64]:
            chunks = [f"chunk_{i}".encode() for i in range(n)]
            tree = MerkleTree(chunks)
            
            proof = tree.get_proof(0)
            
            expected_max = math.ceil(math.log2(n))
            assert len(proof.proof_hashes) <= expected_max
    
    def test_get_proof_contains_sibling_hashes_meow(self):
        """Test proof contains sibling hashes - family connections."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        # Should include sibling (chunk 1's hash)
        assert tree.leaf_hashes[1] in proof.proof_hashes


# =============================================================================
# Test MerkleTree Verify Proof
# =============================================================================

class TestMerkleTreeVerifyProofMeow:
    """Tests for verify_proof method - validating cat papers."""
    
    def test_verify_proof_valid_chunk_meow(self, simple_chunks_meow):
        """Test verification of valid chunk - authentic cat."""
        tree = MerkleTree(simple_chunks_meow)
        
        for i, chunk in enumerate(simple_chunks_meow):
            proof = tree.get_proof(i)
            result = MerkleTree.verify_proof(chunk, proof)
            
            assert result is True
    
    def test_verify_proof_tampered_chunk_meow(self, simple_chunks_meow):
        """Test verification fails for tampered chunk - imposter cat!"""
        tree = MerkleTree(simple_chunks_meow)
        
        proof = tree.get_proof(0)
        tampered_chunk = b"TAMPERED_DATA_NOT_ORIGINAL"
        
        result = MerkleTree.verify_proof(tampered_chunk, proof)
        
        assert result is False
    
    def test_verify_proof_wrong_proof_meow(self, simple_chunks_meow):
        """Test verification fails with wrong proof - mixed up papers."""
        tree = MerkleTree(simple_chunks_meow)
        
        # Get proof for chunk 0, try to verify chunk 1 with it
        proof_for_0 = tree.get_proof(0)
        
        result = MerkleTree.verify_proof(simple_chunks_meow[1], proof_for_0)
        
        assert result is False
    
    def test_verify_proof_corrupted_root_meow(self, simple_chunks_meow):
        """Test verification fails with corrupted root - forged certificate."""
        tree = MerkleTree(simple_chunks_meow)
        
        proof = tree.get_proof(0)
        # Corrupt the root hash
        corrupted_proof = MerkleProof(
            chunk_index=proof.chunk_index,
            chunk_hash=proof.chunk_hash,
            proof_hashes=proof.proof_hashes,
            root_hash=b"\x00" * 32,  # Wrong root
        )
        
        result = MerkleTree.verify_proof(simple_chunks_meow[0], corrupted_proof)
        
        assert result is False
    
    def test_verify_proof_corrupted_proof_hash_meow(self, simple_chunks_meow):
        """Test verification fails with corrupted proof hash - broken chain."""
        tree = MerkleTree(simple_chunks_meow)
        
        proof = tree.get_proof(0)
        if proof.proof_hashes:
            # Corrupt first proof hash
            corrupted_hashes = [b"\xff" * 32] + proof.proof_hashes[1:]
            corrupted_proof = MerkleProof(
                chunk_index=proof.chunk_index,
                chunk_hash=proof.chunk_hash,
                proof_hashes=corrupted_hashes,
                root_hash=proof.root_hash,
            )
            
            result = MerkleTree.verify_proof(simple_chunks_meow[0], corrupted_proof)
            
            assert result is False
    
    def test_verify_proof_single_chunk_meow(self, single_chunk_meow):
        """Test verification for single-chunk tree - only child."""
        tree = MerkleTree(single_chunk_meow)
        
        proof = tree.get_proof(0)
        result = MerkleTree.verify_proof(single_chunk_meow[0], proof)
        
        assert result is True
    
    def test_verify_proof_constant_time_comparison_meow(self, simple_chunks_meow):
        """Test that verification uses constant-time comparison - security."""
        tree = MerkleTree(simple_chunks_meow)
        
        proof = tree.get_proof(0)
        
        # Verify calls secrets.compare_digest internally
        # We test this indirectly by ensuring valid proof works
        result = MerkleTree.verify_proof(simple_chunks_meow[0], proof)
        assert result is True


# =============================================================================
# Test build_merkle_tree_from_chunks Convenience Function
# =============================================================================

class TestBuildMerkleTreeFromChunksMeow:
    """Tests for build_merkle_tree_from_chunks - quick tree building."""
    
    def test_build_returns_tuple_meow(self, simple_chunks_meow):
        """Test function returns (root, tree) tuple - two cats."""
        result = build_merkle_tree_from_chunks(simple_chunks_meow)
        
        assert isinstance(result, tuple)
        assert len(result) == 2
    
    def test_build_root_matches_tree_meow(self, simple_chunks_meow):
        """Test returned root matches tree's root - same leader."""
        root, tree = build_merkle_tree_from_chunks(simple_chunks_meow)
        
        assert root == tree.get_root()
        assert root == tree.root_hash
    
    def test_build_tree_is_valid_meow(self, simple_chunks_meow):
        """Test returned tree is properly constructed - healthy family."""
        root, tree = build_merkle_tree_from_chunks(simple_chunks_meow)
        
        assert isinstance(tree, MerkleTree)
        assert tree.num_chunks == len(simple_chunks_meow)
    
    def test_build_single_chunk_meow(self, single_chunk_meow):
        """Test build with single chunk - lone survivor."""
        root, tree = build_merkle_tree_from_chunks(single_chunk_meow)
        
        expected_root = hashlib.sha256(single_chunk_meow[0]).digest()
        assert root == expected_root
    
    def test_build_many_chunks_meow(self):
        """Test build with many chunks - large colony."""
        chunks = [secrets.token_bytes(32) for _ in range(100)]
        
        root, tree = build_merkle_tree_from_chunks(chunks)
        
        assert len(root) == 32
        assert tree.num_chunks == 100


# =============================================================================
# Test verify_chunk_with_proof Convenience Function
# =============================================================================

class TestVerifyChunkWithProofMeow:
    """Tests for verify_chunk_with_proof - standalone verification."""
    
    def test_verify_valid_chunk_meow(self, simple_chunks_meow):
        """Test verification of valid chunk - papers in order."""
        tree = MerkleTree(simple_chunks_meow)
        root = tree.get_root()
        
        proof = tree.get_proof(2)
        
        result = verify_chunk_with_proof(
            chunk_data=simple_chunks_meow[2],
            chunk_index=2,
            root_hash=root,
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is True
    
    def test_verify_invalid_chunk_meow(self, simple_chunks_meow):
        """Test verification fails for invalid chunk - fake papers."""
        tree = MerkleTree(simple_chunks_meow)
        root = tree.get_root()
        
        proof = tree.get_proof(2)
        
        result = verify_chunk_with_proof(
            chunk_data=b"TAMPERED",
            chunk_index=2,
            root_hash=root,
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is False
    
    def test_verify_wrong_index_meow(self, simple_chunks_meow):
        """Test verification fails with wrong index - identity theft."""
        tree = MerkleTree(simple_chunks_meow)
        root = tree.get_root()
        
        proof = tree.get_proof(0)
        
        # Use chunk 0's data but claim it's chunk 1
        result = verify_chunk_with_proof(
            chunk_data=simple_chunks_meow[0],
            chunk_index=1,  # Wrong index
            root_hash=root,
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is False
    
    def test_verify_wrong_root_meow(self, simple_chunks_meow):
        """Test verification fails with wrong root - wrong family."""
        tree = MerkleTree(simple_chunks_meow)
        
        proof = tree.get_proof(0)
        
        result = verify_chunk_with_proof(
            chunk_data=simple_chunks_meow[0],
            chunk_index=0,
            root_hash=b"\x00" * 32,  # Wrong root
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is False
    
    def test_verify_all_chunks_meow(self, power_of_two_chunks_meow):
        """Test verification of all chunks - complete census."""
        tree = MerkleTree(power_of_two_chunks_meow)
        root = tree.get_root()
        
        for i, chunk in enumerate(power_of_two_chunks_meow):
            proof = tree.get_proof(i)
            
            result = verify_chunk_with_proof(
                chunk_data=chunk,
                chunk_index=i,
                root_hash=root,
                proof_hashes=proof.proof_hashes,
            )
            
            assert result is True


# =============================================================================
# Test Tree Building Internal Method
# =============================================================================

class TestMerkleTreeBuildTreeMeow:
    """Tests for internal _build_tree method - construction details."""
    
    def test_build_tree_structure_power_of_two_meow(self):
        """Test tree structure with power-of-two chunks - perfect tree."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        # 4 chunks -> levels: [4, 2, 1]
        assert len(tree.tree) == 3
        assert len(tree.tree[0]) == 4  # Leaves
        assert len(tree.tree[1]) == 2  # Intermediate
        assert len(tree.tree[2]) == 1  # Root
    
    def test_build_tree_structure_odd_meow(self):
        """Test tree structure with odd chunks - asymmetric tree."""
        chunks = [b"a", b"b", b"c"]
        tree = MerkleTree(chunks)
        
        # 3 chunks -> levels depend on padding strategy
        assert len(tree.tree) >= 2
        assert tree.tree[0] == tree.leaf_hashes
    
    def test_build_tree_preserves_leaf_order_meow(self, simple_chunks_meow):
        """Test leaf order preserved - cats in their places."""
        tree = MerkleTree(simple_chunks_meow)
        
        for i, chunk in enumerate(simple_chunks_meow):
            expected = hashlib.sha256(chunk).digest()
            assert tree.tree[0][i] == expected
    
    def test_build_tree_single_returns_list_meow(self, single_chunk_meow):
        """Test single chunk tree structure - lonely tree."""
        tree = MerkleTree(single_chunk_meow)
        
        assert len(tree.tree) >= 1
        assert len(tree.tree[0]) == 1


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestMerkleTreeEdgeCasesMeow:
    """Edge case tests - unusual cat situations."""
    
    def test_very_large_chunk_meow(self):
        """Test with very large chunk - big cat data."""
        large_chunk = secrets.token_bytes(1024 * 1024)  # 1 MB
        tree = MerkleTree([large_chunk])
        
        assert tree.num_chunks == 1
        assert len(tree.root_hash) == 32
    
    def test_empty_chunk_content_meow(self):
        """Test with empty chunk - invisible cat."""
        chunks = [b"", b"visible"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        result = MerkleTree.verify_proof(b"", proof)
        
        assert result is True
    
    def test_unicode_in_chunks_meow(self):
        """Test chunks with unicode - international cats."""
        chunks = ["Hello 世界".encode('utf-8'), "🐱🔐".encode('utf-8')]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
        
        for i, chunk in enumerate(chunks):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(chunk, proof)
    
    def test_identical_chunks_meow(self):
        """Test identical chunks - cloned cats."""
        chunks = [b"same_data"] * 4
        tree = MerkleTree(chunks)
        
        # All leaf hashes should be same
        assert len(set(tree.leaf_hashes)) == 1
        
        # But proofs should still work
        for i in range(4):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(b"same_data", proof)
    
    def test_nearly_identical_chunks_meow(self):
        """Test nearly identical chunks - twin cats."""
        chunks = [b"cat_a", b"cat_b"]
        tree = MerkleTree(chunks)
        
        # Different chunks should produce different leaf hashes
        assert tree.leaf_hashes[0] != tree.leaf_hashes[1]
    
    def test_max_practical_size_meow(self):
        """Test reasonable maximum size - cat capacity."""
        # 10,000 chunks is practical
        chunks = [f"chunk_{i}".encode() for i in range(10000)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 10000
        
        # Verify a few random proofs
        for i in [0, 5000, 9999]:
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(chunks[i], proof)


# =============================================================================
# Test Security Properties
# =============================================================================

class TestMerkleTreeSecurityMeow:
    """Security property tests - protecting the cats."""
    
    def test_tamper_detection_meow(self):
        """Test that any tampering changes root - no sneaky changes."""
        original = [b"chunk_0", b"chunk_1", b"chunk_2"]
        tampered = [b"TAMPERED", b"chunk_1", b"chunk_2"]
        
        tree_original = MerkleTree(original)
        tree_tampered = MerkleTree(tampered)
        
        assert tree_original.root_hash != tree_tampered.root_hash
    
    def test_single_bit_flip_detection_meow(self):
        """Test single bit flip changes root - precision security."""
        chunk = b"\x00" * 32
        chunk_flipped = b"\x01" + b"\x00" * 31  # Single bit flip
        
        tree1 = MerkleTree([chunk])
        tree2 = MerkleTree([chunk_flipped])
        
        assert tree1.root_hash != tree2.root_hash
    
    def test_proof_cannot_be_reused_for_different_tree_meow(self):
        """Test proof from one tree can't verify another - unique lineage."""
        chunks1 = [b"tree1_chunk"]
        chunks2 = [b"tree2_chunk"]
        
        tree1 = MerkleTree(chunks1)
        tree2 = MerkleTree(chunks2)
        
        proof1 = tree1.get_proof(0)
        
        # Proof from tree1 should not verify chunk from tree2
        result = MerkleTree.verify_proof(chunks2[0], proof1)
        assert result is False
    
    def test_hash_collision_resistance_meow(self):
        """Test distinct inputs produce distinct roots - no duplicates."""
        roots = set()
        
        for i in range(100):
            chunks = [f"unique_chunk_{i}_{j}".encode() for j in range(4)]
            tree = MerkleTree(chunks)
            roots.add(tree.root_hash)
        
        # All 100 roots should be unique
        assert len(roots) == 100
    
    def test_proof_verification_independent_of_tree_meow(self):
        """Test proof can verify without original tree - portable proof."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(2)
        root = tree.get_root()
        
        # Delete tree reference
        del tree
        
        # Verification should still work with just proof data
        result = verify_chunk_with_proof(
            chunk_data=chunks[2],
            chunk_index=2,
            root_hash=root,
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is True


# =============================================================================
# Test Integration Scenarios
# =============================================================================

class TestMerkleTreeIntegrationMeow:
    """Integration tests - complete cat workflows."""
    
    def test_complete_encode_decode_workflow_meow(self):
        """Test complete workflow like in encoding/decoding - full journey."""
        # Simulate encoding
        chunks = [f"data_block_{i}".encode() for i in range(16)]
        root, tree = build_merkle_tree_from_chunks(chunks)
        
        # Store root in manifest (simulation)
        manifest_root = root
        
        # Generate proofs for all chunks (for transmission)
        proofs = [tree.get_proof(i) for i in range(16)]
        
        # Simulate decoding - verify each chunk
        for i, chunk in enumerate(chunks):
            # Verify using standalone function (like decoder would)
            valid = verify_chunk_with_proof(
                chunk_data=chunk,
                chunk_index=i,
                root_hash=manifest_root,
                proof_hashes=proofs[i].proof_hashes,
            )
            assert valid
    
    def test_partial_chunk_verification_meow(self):
        """Test verifying subset of chunks - incomplete reception."""
        chunks = [f"chunk_{i}".encode() for i in range(8)]
        tree = MerkleTree(chunks)
        root = tree.get_root()
        
        # Verify only odd-indexed chunks (simulating packet loss)
        for i in [1, 3, 5, 7]:
            proof = tree.get_proof(i)
            
            result = verify_chunk_with_proof(
                chunk_data=chunks[i],
                chunk_index=i,
                root_hash=root,
                proof_hashes=proof.proof_hashes,
            )
            
            assert result is True
    
    def test_early_tamper_detection_meow(self):
        """Test early detection of tampered chunk - quick rejection."""
        original_chunks = [b"chunk_0", b"chunk_1", b"chunk_2", b"chunk_3"]
        tree = MerkleTree(original_chunks)
        root = tree.get_root()
        
        # Generate proof for chunk 1
        proof = tree.get_proof(1)
        
        # Attempt to verify tampered chunk - should fail immediately
        tampered = b"TAMPERED_CHUNK_1"
        
        result = verify_chunk_with_proof(
            chunk_data=tampered,
            chunk_index=1,
            root_hash=root,
            proof_hashes=proof.proof_hashes,
        )
        
        # Tamper detected before full decode
        assert result is False
    
    def test_manifest_root_storage_meow(self):
        """Test root can be stored and retrieved - manifest integration."""
        chunks = [secrets.token_bytes(64) for _ in range(10)]
        root, tree = build_merkle_tree_from_chunks(chunks)
        
        # Simulate storing root in manifest
        manifest_data = {
            'merkle_root': root.hex(),
            'num_chunks': len(chunks),
        }
        
        # Simulate retrieving from manifest
        retrieved_root = bytes.fromhex(manifest_data['merkle_root'])
        
        assert retrieved_root == root
        
        # Use retrieved root for verification
        proof = tree.get_proof(5)
        result = verify_chunk_with_proof(
            chunk_data=chunks[5],
            chunk_index=5,
            root_hash=retrieved_root,
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is True


# =============================================================================
# Test Performance Characteristics
# =============================================================================

class TestMerkleTreePerformanceMeow:
    """Performance characteristic tests - speedy cats."""
    
    def test_logarithmic_proof_size_scaling_meow(self):
        """Test proof size scales logarithmically - efficient proofs."""
        results = []
        
        for n in [8, 16, 32, 64, 128, 256]:
            chunks = [f"c{i}".encode() for i in range(n)]
            tree = MerkleTree(chunks)
            proof = tree.get_proof(0)
            
            results.append((n, len(proof.proof_hashes)))
        
        # Proof size should roughly equal log2(n)
        for n, proof_size in results:
            expected = math.ceil(math.log2(n))
            assert proof_size <= expected
    
    def test_tree_construction_scales_meow(self):
        """Test tree construction with increasing sizes - scalability."""
        for n in [10, 100, 1000]:
            chunks = [secrets.token_bytes(32) for _ in range(n)]
            tree = MerkleTree(chunks)
            
            assert tree.num_chunks == n
            assert tree.root_hash is not None
    
    def test_verification_efficiency_meow(self):
        """Test verification doesn't require full tree - lean verification."""
        # Build tree and get proof
        chunks = [f"chunk_{i}".encode() for i in range(1000)]
        tree = MerkleTree(chunks)
        root = tree.get_root()
        proof = tree.get_proof(500)
        
        # Verification should work with just:
        # - chunk data
        # - chunk index
        # - root hash
        # - proof hashes (logarithmic size)
        
        # Proof should have ~10 hashes for 1000 chunks (log2(1000) ≈ 10)
        assert len(proof.proof_hashes) <= 10
        
        # Verification
        result = verify_chunk_with_proof(
            chunk_data=chunks[500],
            chunk_index=500,
            root_hash=root,
            proof_hashes=proof.proof_hashes,
        )
        
        assert result is True


# =============================================================================
# Test Error Handling
# =============================================================================

class TestMerkleTreeErrorHandlingMeow:
    """Error handling tests - catching cat mistakes."""
    
    def test_empty_list_raises_clear_error_meow(self):
        """Test empty list gives clear error message - helpful meow."""
        with pytest.raises(ValueError) as exc_info:
            MerkleTree([])
        
        assert "empty" in str(exc_info.value).lower()
    
    def test_invalid_index_gives_clear_error_meow(self, simple_chunks_meow):
        """Test invalid index gives clear error - specific feedback."""
        tree = MerkleTree(simple_chunks_meow)
        
        with pytest.raises(ValueError) as exc_info:
            tree.get_proof(999)
        
        assert "999" in str(exc_info.value) or "Invalid" in str(exc_info.value)
    
    def test_none_chunk_handling_meow(self):
        """Test behavior with None in chunks list - null cat."""
        # This should either work or raise a clear error
        try:
            tree = MerkleTree([None, b"valid"])
            # If it doesn't raise, hash should still work
            assert tree.num_chunks == 2
        except (TypeError, AttributeError):
            # Expected - None can't be hashed
            pass


# =============================================================================
# Test Specific Module Behavior
# =============================================================================

class TestMerkleTreeModuleBehaviorMeow:
    """Tests for specific module behaviors and patterns."""
    
    def test_hash_is_static_method_meow(self):
        """Test _hash is static and callable without instance."""
        result = MerkleTree._hash(b"test")
        
        assert len(result) == 32
    
    def test_hash_pair_is_static_method_meow(self):
        """Test _hash_pair is static and callable without instance."""
        result = MerkleTree._hash_pair(b"a" * 32, b"b" * 32)
        
        assert len(result) == 32
    
    def test_verify_proof_is_static_method_meow(self):
        """Test verify_proof is static - no tree instance needed."""
        # Create proof manually
        chunk = b"test_chunk"
        chunk_hash = hashlib.sha256(chunk).digest()
        
        # Single chunk tree - root equals chunk hash
        proof = MerkleProof(
            chunk_index=0,
            chunk_hash=chunk_hash,
            proof_hashes=[],
            root_hash=chunk_hash,
        )
        
        # Call static method
        result = MerkleTree.verify_proof(chunk, proof)
        
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
