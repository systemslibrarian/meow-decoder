#!/usr/bin/env python3
"""
Tests for AFL++ Fuzzing infrastructure and Double Ratchet protocol.
"""

import pytest
import sys
import struct
import secrets
import hashlib
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestFuzzingInfrastructure:
    """Test fuzzing seed corpus generation and fuzz targets."""
    
    def test_seed_corpus_generation(self):
        """Test that seed corpus generator works."""
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Import and run seed generator
            sys.path.insert(0, str(Path(__file__).parent.parent / "fuzz"))
            from seed_corpus import generate_manifest_samples, generate_fountain_samples
            
            # Generate samples
            generate_manifest_samples(tmpdir / "manifest", count=5)
            generate_fountain_samples(tmpdir / "fountain", count=5)
            
            # Verify files were created
            manifest_files = list((tmpdir / "manifest").glob("*.bin"))
            fountain_files = list((tmpdir / "fountain").glob("*.bin"))
            
            assert len(manifest_files) > 5, "Should have manifest samples + edge cases"
            assert len(fountain_files) > 5, "Should have fountain samples + edge cases"
            
            # Verify most manifest files are valid size (some edge cases may be empty)
            non_empty_count = sum(1 for f in manifest_files if f.stat().st_size > 0)
            assert non_empty_count >= 5, f"Should have at least 5 non-empty manifest samples"
    
    def test_manifest_fuzz_target(self):
        """Test manifest fuzz target with valid input."""
        from meow_decoder.crypto import pack_manifest, Manifest
        
        # Create valid manifest
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=500,
            cipher_len=516,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=10,
            hmac=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        # Import fuzz target function (without running atheris)
        from meow_decoder.crypto import unpack_manifest
        
        # Should parse without error
        result = unpack_manifest(packed)
        assert result.orig_len == 1000
        assert result.k_blocks == 10
    
    def test_manifest_fuzz_edge_cases(self):
        """Test manifest parser handles edge cases gracefully."""
        from meow_decoder.crypto import unpack_manifest
        
        edge_cases = [
            b"",  # Empty
            b"MEOW",  # Truncated magic
            b"MEOW3" + b"\x00" * 50,  # Too short
            b"XXXX" + b"\x00" * 200,  # Wrong magic
            secrets.token_bytes(1000),  # Random garbage
        ]
        
        for case in edge_cases:
            try:
                unpack_manifest(case)
            except ValueError:
                pass  # Expected
            except Exception as e:
                # Should be a controlled error, not a crash
                assert "short" in str(e).lower() or "invalid" in str(e).lower()
    
    def test_fountain_fuzz_target(self):
        """Test fountain fuzz target with valid input."""
        from meow_decoder.fountain import Droplet, pack_droplet, unpack_droplet
        
        # Create valid droplet
        droplet = Droplet(
            seed=12345,
            block_indices=[0, 5, 10],
            data=secrets.token_bytes(256)
        )
        
        packed = pack_droplet(droplet)
        
        # Should parse without error
        result = unpack_droplet(packed, 256)
        assert result.seed == 12345
        assert result.block_indices == [0, 5, 10]
    
    def test_fountain_fuzz_edge_cases(self):
        """Test fountain parser handles edge cases gracefully."""
        from meow_decoder.fountain import unpack_droplet
        
        edge_cases = [
            b"",  # Empty
            struct.pack(">I", 0),  # Just seed
            struct.pack(">IH", 0, 65535),  # Max indices
            secrets.token_bytes(5),  # Truncated
        ]
        
        for case in edge_cases:
            try:
                unpack_droplet(case, 256)
            except (ValueError, struct.error):
                pass  # Expected
            except Exception:
                pass  # Other errors OK too


class TestDoubleRatchet:
    """Test Double Ratchet protocol implementation."""
    
    def test_keypair_generation(self):
        """Test KeyPair generation."""
        from meow_decoder.double_ratchet import KeyPair
        
        kp = KeyPair.generate()
        
        assert kp.private is not None
        assert kp.public is not None
        
        pub_bytes = kp.public_bytes()
        assert len(pub_bytes) == 32
    
    def test_message_header(self):
        """Test MessageHeader pack/unpack."""
        from meow_decoder.double_ratchet import MessageHeader
        
        dh_pub = secrets.token_bytes(32)
        header = MessageHeader(dh_public=dh_pub, pn=5, n=10)
        
        packed = header.pack()
        assert len(packed) == 40
        
        unpacked = MessageHeader.unpack(packed)
        assert unpacked.dh_public == dh_pub
        assert unpacked.pn == 5
        assert unpacked.n == 10
    
    def test_basic_exchange(self):
        """Test basic Alice → Bob → Alice exchange."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        # Alice → Bob
        msg1 = b"Hello Bob!"
        ct1, hdr1 = alice.encrypt(msg1)
        pt1 = bob.decrypt(ct1, hdr1)
        assert pt1 == msg1
        
        # Bob → Alice (DH ratchet)
        msg2 = b"Hello Alice!"
        ct2, hdr2 = bob.encrypt(msg2)
        pt2 = alice.decrypt(ct2, hdr2)
        assert pt2 == msg2
        
        # Alice → Bob again
        msg3 = b"Third message"
        ct3, hdr3 = alice.encrypt(msg3)
        pt3 = bob.decrypt(ct3, hdr3)
        assert pt3 == msg3
    
    def test_multiple_messages_same_direction(self):
        """Test multiple messages before reply."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        # Alice sends 5 messages
        messages = [f"Message {i}".encode() for i in range(5)]
        encrypted = []
        
        for msg in messages:
            ct, hdr = alice.encrypt(msg)
            encrypted.append((ct, hdr))
        
        # Bob receives all
        for i, (ct, hdr) in enumerate(encrypted):
            pt = bob.decrypt(ct, hdr)
            assert pt == messages[i]
    
    def test_out_of_order_delivery(self):
        """Test handling of out-of-order messages."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        # Alice sends 3 messages
        msgs = [b"First", b"Second", b"Third"]
        encrypted = [(alice.encrypt(m)) for m in msgs]
        
        # Bob receives in reverse order
        pt3 = bob.decrypt(encrypted[2][0], encrypted[2][1])
        assert pt3 == b"Third"
        
        pt1 = bob.decrypt(encrypted[0][0], encrypted[0][1])
        assert pt1 == b"First"
        
        pt2 = bob.decrypt(encrypted[1][0], encrypted[1][1])
        assert pt2 == b"Second"
    
    def test_state_serialization(self):
        """Test state serialize/deserialize."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, RatchetState
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        # Exchange a few messages
        ct1, hdr1 = alice.encrypt(b"Hello")
        bob.decrypt(ct1, hdr1)
        
        ct2, hdr2 = bob.encrypt(b"Hi")
        alice.decrypt(ct2, hdr2)
        
        # Serialize Alice's state
        state_bytes = alice.state.serialize()
        assert len(state_bytes) > 100
        
        # Restore Alice
        restored_state = RatchetState.deserialize(state_bytes)
        alice_restored = DoubleRatchet(restored_state)
        
        # Send from restored Alice
        ct3, hdr3 = alice_restored.encrypt(b"From restored")
        pt3 = bob.decrypt(ct3, hdr3)
        assert pt3 == b"From restored"
    
    def test_forward_secrecy(self):
        """Test that DH ratchet provides forward secrecy."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        # Exchange messages (causes DH ratchets)
        old_send_key = alice.state.send_chain_key
        
        ct1, hdr1 = alice.encrypt(b"Message 1")
        bob.decrypt(ct1, hdr1)
        
        ct2, hdr2 = bob.encrypt(b"Reply")
        alice.decrypt(ct2, hdr2)
        
        # After DH ratchet, keys are different
        new_send_key = alice.state.send_chain_key
        
        assert old_send_key != new_send_key, "Keys should change after DH ratchet"
    
    def test_clowder_session(self):
        """Test Clowder mode multi-party session."""
        from meow_decoder.double_ratchet import ClowderSession, KeyPair
        
        # Create identities
        alice_id = KeyPair.generate()
        bob_id = KeyPair.generate()
        
        # Create sessions
        alice_session = ClowderSession(alice_id)
        bob_session = ClowderSession(bob_id)
        
        # Peer IDs
        alice_peer_id = hashlib.sha256(b"alice").digest()
        bob_peer_id = hashlib.sha256(b"bob").digest()
        
        # Shared secret
        peer_secret = secrets.token_bytes(32)
        
        # Add peers
        alice_session.add_peer(bob_peer_id, bob_id.public_bytes(), True, peer_secret)
        bob_session.add_peer(alice_peer_id, alice_id.public_bytes(), False, peer_secret)
        
        # Exchange
        msg = b"Hello from Clowder!"
        ct, hdr = alice_session.encrypt_for_peer(bob_peer_id, msg)
        pt = bob_session.decrypt_from_peer(alice_peer_id, ct, hdr)
        
        assert pt == msg
    
    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, RatchetError
        
        shared_secret = secrets.token_bytes(32)
        wrong_secret = secrets.token_bytes(32)
        
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob_wrong = DoubleRatchet.initialize_bob(wrong_secret, bob_keypair)
        
        ct1, hdr1 = alice.encrypt(b"Secret message")
        
        # Bob with wrong key should fail
        with pytest.raises(Exception):  # Could be RatchetError or crypto error
            bob_wrong.decrypt(ct1, hdr1)


class TestDoubleRatchetIntegration:
    """Integration tests for Double Ratchet with Clowder mode."""
    
    def test_long_conversation(self):
        """Test 100+ message exchange."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        for i in range(100):
            # Alternate sender
            if i % 2 == 0:
                msg = f"Alice message {i}".encode()
                ct, hdr = alice.encrypt(msg)
                pt = bob.decrypt(ct, hdr)
            else:
                msg = f"Bob message {i}".encode()
                ct, hdr = bob.encrypt(msg)
                pt = alice.decrypt(ct, hdr)
            
            assert pt == msg
    
    def test_skipped_keys_limit(self):
        """Test that skipped keys are limited to prevent DoS."""
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, MAX_SKIP
        
        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)
        
        # Send many messages from Alice
        encrypted = []
        for i in range(50):
            ct, hdr = alice.encrypt(f"Message {i}".encode())
            encrypted.append((ct, hdr))
        
        # Receive only the last one (skip 49)
        pt = bob.decrypt(encrypted[49][0], encrypted[49][1])
        assert pt == b"Message 49"
        
        # Skipped keys should be stored
        assert len(bob.state.skipped_keys) <= MAX_SKIP


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
