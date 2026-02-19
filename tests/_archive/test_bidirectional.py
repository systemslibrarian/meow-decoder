import hashlib

import meow_decoder.bidirectional as bidirectional


def test_session_info_pack_unpack_roundtrip():
    info = bidirectional.SessionInfo(
        session_id=b"12345678",
        total_frames=10,
        k_blocks=5,
        block_size=512,
        file_hash=b"a" * 32,
        session_salt=b"b" * 16,
    )
    packed = info.pack()
    unpacked = bidirectional.SessionInfo.unpack(packed)
    assert unpacked.session_id == info.session_id
    assert unpacked.total_frames == info.total_frames
    assert unpacked.k_blocks == info.k_blocks
    assert unpacked.block_size == info.block_size
    assert unpacked.file_hash == info.file_hash
    assert unpacked.session_salt == info.session_salt


def test_sender_receiver_session_start_and_status_flow():
    password = "shared-secret"
    file_hash = hashlib.sha256(b"data").digest()

    sender = bidirectional.BiDirectionalSender(
        file_hash=file_hash,
        k_blocks=4,
        block_size=512,
        total_frames=6,
        password=password,
    )
    session_msg = sender.get_session_start_message()

    receiver = bidirectional.BiDirectionalReceiver()
    assert receiver.process_session_start(session_msg, password=password)

    receiver.blocks_decoded = 2
    status_msg = receiver.get_status_message()
    status = sender.process_ack(status_msg)
    assert status is not None
    assert status.blocks_decoded == 2

    # Replay should be rejected
    replay = sender.process_ack(status_msg)
    assert replay is None


def test_completion_message_sets_sender_complete():
    password = "shared-secret"
    file_hash = hashlib.sha256(b"data").digest()

    sender = bidirectional.BiDirectionalSender(
        file_hash=file_hash,
        k_blocks=4,
        block_size=512,
        total_frames=6,
        password=password,
    )
    session_msg = sender.get_session_start_message()

    receiver = bidirectional.BiDirectionalReceiver()
    assert receiver.process_session_start(session_msg, password=password)

    completion = receiver.get_completion_message()
    sender.process_ack(completion)
    assert sender.is_complete is True


def test_create_and_verify_session_hmac():
    key = b"k" * 32
    message = b"hello"
    tag = bidirectional.create_session_hmac(key, message)
    assert bidirectional.verify_session_hmac(key, message, tag)
    assert not bidirectional.verify_session_hmac(key, message + b"!", tag)


def test_bidirectional_protocol_sender_check_status():
    password = "shared-secret"
    file_hash = hashlib.sha256(b"data").digest()
    protocol = bidirectional.BiDirectionalProtocol(password, is_sender=True)
    protocol.start_session(file_hash, k_blocks=4, block_size=512, total_frames=6)
    status = protocol.check_status()
    assert "session_id" in status
    assert "is_complete" in status


def test_anti_spoofing_receiver_sequence():
    receiver = bidirectional.BidirectionalReceiver()
    assert receiver.check_sequence_number(0) is True
    assert receiver.check_sequence_number(0) is False
    assert receiver.check_sequence_number(1) is True
