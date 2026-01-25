
import unittest
import secrets
import hmac
import hashlib
import struct
import warnings
from meow_decoder.bidirectional import (
    BiDirectionalSender, BiDirectionalReceiver, MessageType, StatusUpdate
)

class TestControlChannel(unittest.TestCase):
    def test_payload_parsing_bug(self):
        """Test that status updates are parsed correctly (fix the offset bug)."""
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        # Create a StatusUpdate payload manually with counter prefix
        session_id = b'S'*8
        counter = struct.pack('>I', 1)  # Replay protection counter
        payload = counter + struct.pack('>8sIIIIII', session_id, 1, 1, 1, 9, 0, 0)
        
        # Create the full ACK message
        msg_type = bytes([MessageType.STATUS_UPDATE])
        
        # Calculate HMAC
        mac = hmac.new(sender.auth_key, msg_type + payload, hashlib.sha256).digest()
        
        # Construct message: Type(1) + MAC(32) + Counter(4) + Payload(N)
        full_msg = msg_type + mac + payload
        
        # Process it
        status = sender.process_ack(full_msg)
        
        self.assertIsNotNone(status, "Status should be accepted")
        self.assertEqual(status.session_id, session_id, "Session ID should match")
        self.assertEqual(status.frames_received, 1)


class TestReplayProtection(unittest.TestCase):
    """Test replay protection for control channel messages."""
    
    def test_replay_attack_rejected(self):
        """Test that replayed control messages are rejected."""
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        # Create a COMPLETION message with counter=1
        msg_type = bytes([MessageType.COMPLETION])
        counter = struct.pack('>I', 1)
        payload = counter + b'\x00' * 8  # session_id
        
        mac = hmac.new(sender.auth_key, msg_type + payload, hashlib.sha256).digest()
        full_msg = msg_type + mac + payload
        
        # First receipt - should be accepted
        sender.process_ack(full_msg)
        self.assertTrue(sender.is_complete, "First COMPLETION should be accepted")
        
        # Reset for replay test
        sender.is_complete = False
        
        # Replay the SAME message (same counter)
        sender.process_ack(full_msg)
        
        # Should be rejected (is_complete should remain False)
        self.assertFalse(sender.is_complete, "Replayed COMPLETION should be rejected")
    
    def test_status_update_replay_rejected(self):
        """Test that replayed STATUS_UPDATE messages are rejected."""
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        # Create a STATUS_UPDATE message with counter=1
        msg_type = bytes([MessageType.STATUS_UPDATE])
        counter = struct.pack('>I', 1)
        session_id = b'S' * 8
        status_payload = struct.pack('>IIIIII', 5, 5, 3, 10, 7, 0)  # frames, decoded, blocks, etc.
        payload = counter + session_id + status_payload
        
        mac = hmac.new(sender.auth_key, msg_type + payload, hashlib.sha256).digest()
        full_msg = msg_type + mac + payload
        
        # First receipt - should be accepted
        status1 = sender.process_ack(full_msg)
        self.assertIsNotNone(status1, "First STATUS_UPDATE should be accepted")
        initial_count = len(sender.status_updates)
        
        # Replay the SAME message (same counter)
        status2 = sender.process_ack(full_msg)
        
        # Should be rejected (status2 should be None and no new status added)
        self.assertIsNone(status2, "Replayed STATUS_UPDATE should be rejected")
        self.assertEqual(len(sender.status_updates), initial_count, "No new status should be added")
    
    def test_counter_must_increase(self):
        """Test that counter must strictly increase."""
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        def make_completion_msg(counter_val):
            msg_type = bytes([MessageType.COMPLETION])
            counter = struct.pack('>I', counter_val)
            payload = counter + b'\x00' * 8
            mac = hmac.new(sender.auth_key, msg_type + payload, hashlib.sha256).digest()
            return msg_type + mac + payload
        
        # Send counter=5 first
        sender.process_ack(make_completion_msg(5))
        sender.is_complete = False  # Reset
        
        # Counter=3 should be rejected (less than 5)
        sender.process_ack(make_completion_msg(3))
        self.assertFalse(sender.is_complete, "Counter=3 after counter=5 should be rejected")
        
        # Counter=5 should be rejected (equal to last)
        sender.process_ack(make_completion_msg(5))
        self.assertFalse(sender.is_complete, "Counter=5 replay should be rejected")
        
        # Counter=6 should be accepted
        sender.process_ack(make_completion_msg(6))
        self.assertTrue(sender.is_complete, "Counter=6 should be accepted")


class TestHMACAuthentication(unittest.TestCase):
    """Test HMAC authentication for control channel messages."""
    
    def test_invalid_hmac_rejected(self):
        """Test that messages with invalid HMAC are rejected."""
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        # Create a valid message structure but with wrong HMAC
        msg_type = bytes([MessageType.COMPLETION])
        counter = struct.pack('>I', 1)
        payload = counter + b'\x00' * 8
        
        # Use wrong key for HMAC
        wrong_key = b'wrong_key_12345678901234567890AB'  # 32 bytes
        mac = hmac.new(wrong_key, msg_type + payload, hashlib.sha256).digest()
        full_msg = msg_type + mac + payload
        
        # Should be rejected
        sender.process_ack(full_msg)
        self.assertFalse(sender.is_complete, "Message with invalid HMAC should be rejected")
    
    def test_tampered_payload_rejected(self):
        """Test that tampered payloads are rejected."""
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        # Create a valid message
        msg_type = bytes([MessageType.COMPLETION])
        counter = struct.pack('>I', 1)
        payload = counter + b'\x00' * 8
        mac = hmac.new(sender.auth_key, msg_type + payload, hashlib.sha256).digest()
        
        # Tamper with payload after HMAC computation
        tampered_payload = counter + b'\xFF' * 8
        full_msg = msg_type + mac + tampered_payload
        
        # Should be rejected
        sender.process_ack(full_msg)
        self.assertFalse(sender.is_complete, "Tampered message should be rejected")
    
    def test_empty_password_warning(self):
        """Test that empty password triggers security warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            sender = BiDirectionalSender(
                file_hash=b'A'*32,
                k_blocks=10,
                block_size=100,
                total_frames=15,
                password=""  # Empty password
            )
            # Check that a UserWarning was issued (security advisory)
            self.assertTrue(
                any(issubclass(warning.category, UserWarning) for warning in w),
                "Empty password should trigger UserWarning"
            )


class TestReceiverCounters(unittest.TestCase):
    """Test that receiver includes counters in outgoing messages."""
    
    def test_status_update_includes_counter(self):
        """Test that get_status_message includes replay protection counter."""
        receiver = BiDirectionalReceiver()
        
        # Setup a valid session
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        session_msg = sender.get_session_start_message()
        receiver.process_session_start(session_msg, "secure_password")
        
        # Get first status message
        msg1 = receiver.get_status_message()
        # Get second status message
        msg2 = receiver.get_status_message()
        
        # Extract counters (Type(1) + MAC(32) + Counter(4) + ...)
        counter1 = struct.unpack('>I', msg1[33:37])[0]
        counter2 = struct.unpack('>I', msg2[33:37])[0]
        
        self.assertEqual(counter1, 1, "First counter should be 1")
        self.assertEqual(counter2, 2, "Second counter should be 2")
        self.assertGreater(counter2, counter1, "Counter must increase")
    
    def test_completion_includes_counter(self):
        """Test that get_completion_message includes replay protection counter."""
        receiver = BiDirectionalReceiver()
        
        # Setup a valid session
        sender = BiDirectionalSender(
            file_hash=b'A'*32,
            k_blocks=10,
            block_size=100,
            total_frames=15,
            password="secure_password"
        )
        
        session_msg = sender.get_session_start_message()
        receiver.process_session_start(session_msg, "secure_password")
        
        # Get completion message
        msg = receiver.get_completion_message()
        
        # Extract counter (Type(1) + MAC(32) + Counter(4) + ...)
        counter = struct.unpack('>I', msg[33:37])[0]
        
        self.assertEqual(counter, 1, "Completion counter should be 1")


if __name__ == '__main__':
    unittest.main()
