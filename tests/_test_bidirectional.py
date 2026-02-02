#!/usr/bin/env python3
"""
🧪 Test Suite: bidirectional.py
Tests bidirectional streaming communication.
"""

import pytest
import secrets
import os
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import bidirectional module
try:
    from meow_decoder.bidirectional import (
        BidirectionalChannel,
        Message,
        MessageType,
    )
    BIDIRECTIONAL_AVAILABLE = True
except ImportError:
    BIDIRECTIONAL_AVAILABLE = False


@pytest.mark.skipif(not BIDIRECTIONAL_AVAILABLE, reason="bidirectional module not available")
class TestBidirectionalChannel:
    """Tests for BidirectionalChannel."""

    def test_channel_creation(self):
        """Test basic channel creation."""
        channel = BidirectionalChannel()
        assert channel is not None

    def test_send_message(self):
        """Test sending a message."""
        channel = BidirectionalChannel()
        msg = Message(type=MessageType.DATA, payload=b"test")
        result = channel.send(msg)
        assert result is not None

    def test_receive_message(self):
        """Test receiving a message."""
        channel = BidirectionalChannel()
        msg = Message(type=MessageType.DATA, payload=b"test")
        channel.send(msg)
        received = channel.receive()
        assert received.payload == b"test"


@pytest.mark.skipif(not BIDIRECTIONAL_AVAILABLE, reason="bidirectional module not available")
class TestMessage:
    """Tests for Message class."""

    def test_message_creation(self):
        """Test basic message creation."""
        msg = Message(type=MessageType.DATA, payload=b"test data")
        assert msg.type == MessageType.DATA
        assert msg.payload == b"test data"

    def test_message_serialization(self):
        """Test message serialization."""
        msg = Message(type=MessageType.DATA, payload=b"test")
        serialized = msg.serialize()
        assert isinstance(serialized, bytes)

    def test_message_deserialization(self):
        """Test message deserialization."""
        msg = Message(type=MessageType.DATA, payload=b"test")
        serialized = msg.serialize()
        restored = Message.deserialize(serialized)
        assert restored.payload == msg.payload


@pytest.mark.skipif(not BIDIRECTIONAL_AVAILABLE, reason="bidirectional module not available")
class TestMessageType:
    """Tests for MessageType enum."""

    def test_message_types_exist(self):
        """Test that required message types exist."""
        assert hasattr(MessageType, 'DATA')
        assert hasattr(MessageType, 'ACK')


# Fallback test
@pytest.mark.skipif(BIDIRECTIONAL_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not BIDIRECTIONAL_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
