#!/usr/bin/env python3
"""Tests for meow_decoder.double_ratchet.
Target: 95%+ branch coverage
"""

import hashlib
import secrets

import pytest


class TestDoubleRatchet:
    def test_keypair_generation(self):
        from meow_decoder.double_ratchet import KeyPair

        kp = KeyPair.generate()
        assert kp._private_handle is not None
        assert isinstance(kp._private_handle, int)
        assert kp._public_bytes is not None
        assert len(kp.public_bytes()) == 32

    def test_message_header_pack_unpack(self):
        from meow_decoder.double_ratchet import MessageHeader

        dh_pub = secrets.token_bytes(32)
        header = MessageHeader(dh_public=dh_pub, pn=5, n=10)
        packed = header.pack()
        assert len(packed) == 40
        unpacked = MessageHeader.unpack(packed)
        assert unpacked.dh_public == dh_pub
        assert unpacked.pn == 5
        assert unpacked.n == 10

    def test_message_header_pack_invalid_pubkey(self):
        from meow_decoder.double_ratchet import MessageHeader

        with pytest.raises(ValueError, match="DH public key must be 32 bytes"):
            MessageHeader(dh_public=b"short", pn=0, n=0).pack()

    def test_keypair_public_from_bytes_invalid_length(self):
        from meow_decoder.double_ratchet import KeyPair

        with pytest.raises(ValueError, match="Public key must be 32 bytes"):
            KeyPair.public_from_bytes(b"short")

    def test_basic_exchange(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        msg1 = b"Hello Bob!"
        ct1, hdr1 = alice.encrypt(msg1)
        pt1 = bob.decrypt(ct1, hdr1)
        assert pt1 == msg1

        msg2 = b"Hello Alice!"
        ct2, hdr2 = bob.encrypt(msg2)
        pt2 = alice.decrypt(ct2, hdr2)
        assert pt2 == msg2

        msg3 = b"Third message"
        ct3, hdr3 = alice.encrypt(msg3)
        pt3 = bob.decrypt(ct3, hdr3)
        assert pt3 == msg3

    def test_multiple_messages_same_direction(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        messages = [f"Message {i}".encode() for i in range(5)]
        encrypted = []

        for msg in messages:
            ct, hdr = alice.encrypt(msg)
            encrypted.append((ct, hdr))

        for i, (ct, hdr) in enumerate(encrypted):
            pt = bob.decrypt(ct, hdr)
            assert pt == messages[i]

    def test_out_of_order_delivery(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        msgs = [b"First", b"Second", b"Third"]
        encrypted = [(alice.encrypt(m)) for m in msgs]

        pt3 = bob.decrypt(encrypted[2][0], encrypted[2][1])
        assert pt3 == b"Third"

        pt1 = bob.decrypt(encrypted[0][0], encrypted[0][1])
        assert pt1 == b"First"

        pt2 = bob.decrypt(encrypted[1][0], encrypted[1][1])
        assert pt2 == b"Second"

    def test_state_serialization(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, RatchetState

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        ct1, hdr1 = alice.encrypt(b"Hello")
        bob.decrypt(ct1, hdr1)

        ct2, hdr2 = bob.encrypt(b"Hi")
        alice.decrypt(ct2, hdr2)

        state_bytes = alice.state.serialize()
        assert len(state_bytes) > 100

        restored_state = RatchetState.deserialize(state_bytes)
        alice_restored = DoubleRatchet(restored_state)

        ct3, hdr3 = alice_restored.encrypt(b"From restored")
        pt3 = bob.decrypt(ct3, hdr3)
        assert pt3 == b"From restored"

    def test_state_serialize_without_keypair_or_remote(self):
        from meow_decoder.double_ratchet import RatchetState

        state = RatchetState()
        data = state.serialize()
        restored = RatchetState.deserialize(data)

        assert restored.dh_keypair is None
        assert restored.dh_remote_public is None

    def test_skip_messages_without_recv_chain_key_noop(self):
        from meow_decoder.double_ratchet import DoubleRatchet, RatchetState

        dr = DoubleRatchet(RatchetState())
        # Should be a no-op without raising
        dr._skip_messages(10)

    def test_state_serializes_skipped_keys(self):
        from meow_decoder.double_ratchet import RatchetState
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        state = RatchetState(
            root_key=hb.import_key(b"\x01" * 32),
            send_chain_key=hb.import_key(b"\x02" * 32),
            recv_chain_key=hb.import_key(b"\x03" * 32),
            dh_remote_public=b"\x04" * 32,
        )
        state.skipped_keys[(b"\x04" * 32, 7)] = hb.import_key(b"\x05" * 32)

        data = state.serialize()
        restored = RatchetState.deserialize(data)

        assert (b"\x04" * 32, 7) in restored.skipped_keys
        # After roundtrip, skipped_keys values are handles; export to compare
        restored_bytes = hb.export_key(restored.skipped_keys[(b"\x04" * 32, 7)])
        assert restored_bytes == b"\x05" * 32

    def test_forward_secrecy_key_changes(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        old_send_key = alice.state.send_chain_key
        ct1, hdr1 = alice.encrypt(b"Message 1")
        bob.decrypt(ct1, hdr1)
        ct2, hdr2 = bob.encrypt(b"Reply")
        alice.decrypt(ct2, hdr2)

        new_send_key = alice.state.send_chain_key
        assert old_send_key != new_send_key

    def test_clowder_session(self):
        from meow_decoder.double_ratchet import ClowderSession, KeyPair

        alice_id = KeyPair.generate()
        bob_id = KeyPair.generate()

        alice_session = ClowderSession(alice_id)
        bob_session = ClowderSession(bob_id)

        alice_peer_id = hashlib.sha256(b"alice").digest()
        bob_peer_id = hashlib.sha256(b"bob").digest()
        peer_secret = secrets.token_bytes(32)

        alice_session.add_peer(bob_peer_id, bob_id.public_bytes(), True, peer_secret)
        bob_session.add_peer(alice_peer_id, alice_id.public_bytes(), False, peer_secret)

        msg = b"Hello from Clowder!"
        ct, hdr = alice_session.encrypt_for_peer(bob_peer_id, msg)
        pt = bob_session.decrypt_from_peer(alice_peer_id, ct, hdr)

        assert pt == msg

    def test_wrong_key_fails(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        wrong_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob_wrong = DoubleRatchet.initialize_bob(wrong_secret, bob_keypair)

        ct1, hdr1 = alice.encrypt(b"Secret message")

        with pytest.raises(Exception):
            bob_wrong.decrypt(ct1, hdr1)

    def test_encrypt_without_send_chain_raises(self):
        from meow_decoder.double_ratchet import DoubleRatchet, RatchetError

        dr = DoubleRatchet()  # empty state
        with pytest.raises(RatchetError, match="no sending chain"):
            dr.encrypt(b"hi")

    def test_aead_decrypt_wrong_key_raises(self):
        from meow_decoder.double_ratchet import DoubleRatchet
        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        key_good = hb.import_key(secrets.token_bytes(32))
        key_bad = hb.import_key(secrets.token_bytes(32))
        aad = b"header"

        ct = DoubleRatchet._aead_encrypt(key_good, b"payload", aad)

        with pytest.raises(Exception):
            DoubleRatchet._aead_decrypt(key_bad, ct, aad)

    def test_decrypt_with_skipped_key_path(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        ct1, hdr1 = alice.encrypt(b"msg1")
        ct2, hdr2 = alice.encrypt(b"msg2")

        # Deliver msg2 first to create a skipped key for msg1
        pt2 = bob.decrypt(ct2, hdr2)
        assert pt2 == b"msg2"

        # Now msg1 should be decrypted via skipped key lookup path
        pt1 = bob.decrypt(ct1, hdr1)
        assert pt1 == b"msg1"

    def test_skip_messages_too_many_raises(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, RatchetError, MAX_SKIP

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        # Create one message to initialize receive chain for Bob
        ct1, hdr1 = alice.encrypt(b"msg1")
        bob.decrypt(ct1, hdr1)

        # Force skip beyond MAX_SKIP
        with pytest.raises(RatchetError, match="Too many skipped messages"):
            bob._skip_messages(bob.state.recv_n + MAX_SKIP + 1)

    def test_skip_messages_evicts_oldest_when_prepopulated(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, MAX_SKIP

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        # Initialize recv chain by receiving one message
        ct1, hdr1 = alice.encrypt(b"msg1")
        bob.decrypt(ct1, hdr1)

        # Prepopulate skipped keys to MAX_SKIP
        bob.state.skipped_keys = {(b"\x01" * 32, i): b"\x02" * 32 for i in range(MAX_SKIP)}
        # Trigger one more skipped key insertion to evict oldest
        bob._skip_messages(bob.state.recv_n + 1)

        assert len(bob.state.skipped_keys) <= MAX_SKIP


class TestDoubleRatchetIntegration:
    def test_long_conversation(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        for i in range(100):
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
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair, MAX_SKIP

        shared_secret = secrets.token_bytes(32)
        bob_keypair = KeyPair.generate()

        alice = DoubleRatchet.initialize_alice(shared_secret, bob_keypair.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_keypair)

        encrypted = []
        for i in range(50):
            ct, hdr = alice.encrypt(f"Message {i}".encode())
            encrypted.append((ct, hdr))

        pt = bob.decrypt(encrypted[49][0], encrypted[49][1])
        assert pt == b"Message 49"
        assert len(bob.state.skipped_keys) <= MAX_SKIP

    def test_clowder_restore_session_roundtrip(self):
        from meow_decoder.double_ratchet import ClowderSession, KeyPair

        alice_id = KeyPair.generate()
        bob_id = KeyPair.generate()

        alice_session = ClowderSession(alice_id)
        bob_session = ClowderSession(bob_id)

        alice_peer_id = hashlib.sha256(b"alice").digest()
        bob_peer_id = hashlib.sha256(b"bob").digest()
        peer_secret = secrets.token_bytes(32)

        alice_session.add_peer(bob_peer_id, bob_id.public_bytes(), True, peer_secret)
        bob_session.add_peer(alice_peer_id, alice_id.public_bytes(), False, peer_secret)

        # Save and restore Alice session
        state_bytes = alice_session.get_session_state(bob_peer_id)
        alice_restored = ClowderSession(alice_id)
        alice_restored.restore_session(bob_peer_id, state_bytes)

        msg = b"Restored session message"
        ct, hdr = alice_restored.encrypt_for_peer(bob_peer_id, msg)
        pt = bob_session.decrypt_from_peer(alice_peer_id, ct, hdr)

        assert pt == msg


class TestDoubleRatchetEdgeCases:
    def test_header_unpack_too_short(self):
        from meow_decoder.double_ratchet import MessageHeader

        with pytest.raises(ValueError, match="Header too short"):
            MessageHeader.unpack(b"short")

    def test_initialize_alice_invalid_lengths(self):
        from meow_decoder.double_ratchet import DoubleRatchet

        with pytest.raises(ValueError, match="Shared secret must be 32 bytes"):
            DoubleRatchet.initialize_alice(b"short", secrets.token_bytes(32))

        with pytest.raises(ValueError, match="Public key must be 32 bytes"):
            DoubleRatchet.initialize_alice(secrets.token_bytes(32), b"short")

    def test_initialize_bob_invalid_secret(self):
        from meow_decoder.double_ratchet import DoubleRatchet, KeyPair

        with pytest.raises(ValueError, match="Shared secret must be 32 bytes"):
            DoubleRatchet.initialize_bob(b"short", KeyPair.generate())

    def test_aead_decrypt_short_ciphertext(self):
        from meow_decoder.double_ratchet import DoubleRatchet, RatchetError

        with pytest.raises(RatchetError, match="Ciphertext too short"):
            DoubleRatchet._aead_decrypt(b"\x00" * 32, b"short", b"")


class TestClowderSessionErrors:
    def test_unknown_peer_encrypt_decrypt_get_state(self):
        from meow_decoder.double_ratchet import ClowderSession, KeyPair, RatchetError

        session = ClowderSession(KeyPair.generate())
        peer_id = secrets.token_bytes(32)

        with pytest.raises(RatchetError, match="Unknown peer"):
            session.encrypt_for_peer(peer_id, b"hi")

        with pytest.raises(RatchetError, match="Unknown peer"):
            session.decrypt_from_peer(peer_id, b"ct", b"header")

        with pytest.raises(RatchetError, match="Unknown peer"):
            session.get_session_state(peer_id)
