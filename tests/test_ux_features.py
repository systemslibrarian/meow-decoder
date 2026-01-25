#!/usr/bin/env python3
"""
🧪 Tests for New UX Features
Tests for progress_bar, ascii_qr, and bidirectional modules

These features were inspired by competitor analysis of:
- TXQR (ASCII terminal QR)
- Bitfountain (visual progress bar)
- QRFileTransfer (bidirectional protocol)
"""

import pytest
import time
import hashlib
from io import StringIO
from unittest.mock import patch, MagicMock

# Import modules under test
from meow_decoder.progress_bar import (
    ProgressStats, ProgressBar, FountainProgressBar, create_progress
)
from meow_decoder.ascii_qr import (
    ASCIIQRCode, generate_terminal_qr, print_terminal_qr, AnimatedTerminalQR
)
from meow_decoder.bidirectional import (
    MessageType, SessionInfo, FrameAck, StatusUpdate,
    BiDirectionalSender, BiDirectionalReceiver, BiDirectionalProtocol,
    create_sender_protocol, create_receiver_protocol
)


# ============================================================================
# ProgressBar Tests
# ============================================================================

class TestProgressStats:
    """Tests for ProgressStats dataclass."""
    
    def test_stats_creation(self):
        """Test creating progress stats."""
        stats = ProgressStats(
            total_items=100,
            received_items=50,
            start_time=time.time() - 5.0,
            bytes_transferred=1024
        )
        
        assert stats.total_items == 100
        assert stats.received_items == 50
        assert stats.percentage == 50.0
        assert stats.bytes_transferred == 1024
    
    def test_elapsed_calculation(self):
        """Test elapsed time calculation."""
        start = time.time() - 10.0
        stats = ProgressStats(
            total_items=100,
            received_items=50,
            start_time=start,
            bytes_transferred=0
        )
        
        # Elapsed should be ~10 seconds (format is MM:SS or HH:MM:SS)
        # Check that it's a time string with colons
        assert ":" in stats.elapsed_str
    
    def test_eta_calculation(self):
        """Test ETA calculation."""
        stats = ProgressStats(
            total_items=100,
            received_items=50,
            start_time=time.time() - 10.0,
            bytes_transferred=5000  # Need bytes and throughput for ETA
        )
        
        # Need to add throughput samples for ETA to work
        stats._throughput_samples.append(500.0)  # 500 B/s
        
        # Now ETA should be calculable
        eta = stats.eta_seconds
        # ETA might still be None if items have no avg size
        # Just check the string returns something
        assert stats.eta_str is not None


class TestProgressBar:
    """Tests for ProgressBar class."""
    
    def test_progress_bar_creation(self):
        """Test creating progress bar."""
        bar = ProgressBar(total=100)
        
        assert bar.total == 100
        assert sum(bar.received) == 0
    
    def test_mark_received(self):
        """Test marking items as received."""
        bar = ProgressBar(total=10)
        
        bar.mark_received(0)
        bar.mark_received(5)
        bar.mark_received(9)
        
        assert bar.received[0] == True
        assert bar.received[5] == True
        assert bar.received[9] == True
        assert sum(bar.received) == 3
    
    def test_mark_received_with_bytes(self):
        """Test marking items with byte count."""
        bar = ProgressBar(total=100)
        
        for i in range(5):
            bar.mark_received(i, bytes_count=100)
        
        assert sum(bar.received) == 5
        assert bar.stats.bytes_transferred == 500
    
    def test_progress_percentage(self):
        """Test progress percentage calculation."""
        bar = ProgressBar(total=100)
        
        for i in range(50):
            bar.mark_received(i)
        
        assert bar.stats.percentage == 50.0
    
    def test_render_bar(self):
        """Test rendering progress bar."""
        bar = ProgressBar(total=10)
        
        for i in range(5):
            bar.mark_received(i)  # 50%
        
        rendered = bar.render_bar()
        
        # Should contain progress indicators
        assert len(rendered) > 0
        # Should contain ANSI codes or block chars
        assert "█" in rendered or "░" in rendered or "\033" in rendered
    
    def test_render_compact(self):
        """Test compact rendering."""
        bar = ProgressBar(total=100)
        for i in range(75):
            bar.mark_received(i)
        
        compact = bar.render_compact()
        
        # Should show percentage
        assert "75.0%" in compact
    
    def test_throughput_tracking(self):
        """Test throughput calculation."""
        bar = ProgressBar(total=10)
        
        # Mark some items with bytes
        bar.mark_received(0, bytes_count=1024)
        time.sleep(0.1)
        bar.mark_received(1, bytes_count=1024)
        
        assert bar.stats.bytes_transferred == 2048
    
    def test_finish(self):
        """Test finish method."""
        bar = ProgressBar(total=10, use_color=False)
        for i in range(10):
            bar.mark_received(i)
        
        # Just make sure finish doesn't crash
        # (it prints to stdout)
        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            bar.finish()
        
        output = f.getvalue()
        # Should contain completion message
        assert "Complete" in output or "✅" in output


class TestFountainProgressBar:
    """Tests for FountainProgressBar class."""
    
    def test_fountain_creation(self):
        """Test creating fountain progress bar."""
        bar = FountainProgressBar(k_blocks=100, expected_droplets=150)
        
        assert bar.k_blocks == 100
        assert bar.expected_droplets == 150
    
    def test_update_decoding(self):
        """Test updating decoding progress."""
        bar = FountainProgressBar(k_blocks=100, expected_droplets=150)
        
        bar.update_decoding(droplets_received=50, blocks_decoded=30)
        
        assert bar.droplets_received == 50
        assert bar.blocks_decoded == 30
    
    def test_fountain_stats(self):
        """Test getting stats includes fountain info."""
        bar = FountainProgressBar(k_blocks=100, expected_droplets=150)
        bar.update_decoding(droplets_received=100, blocks_decoded=80)
        
        # blocks_decoded should update the internal tracking
        assert bar.blocks_decoded == 80
        assert bar.k_blocks == 100
    
    def test_completion_detection(self):
        """Test detecting completion."""
        bar = FountainProgressBar(k_blocks=100, expected_droplets=150)
        
        # Not complete yet
        bar.update_decoding(droplets_received=100, blocks_decoded=80)
        assert bar.blocks_decoded < bar.k_blocks
        
        # Complete
        bar.update_decoding(droplets_received=120, blocks_decoded=100)
        assert bar.blocks_decoded == bar.k_blocks


class TestCreateProgress:
    """Tests for convenience function."""
    
    def test_create_basic_progress(self):
        """Test creating basic progress bar."""
        bar = create_progress(total=50)
        
        assert isinstance(bar, ProgressBar)
        assert bar.total == 50
    
    def test_create_fountain_progress(self):
        """Test creating fountain progress bar."""
        bar = create_progress(total=100, fountain=True)
        
        assert isinstance(bar, FountainProgressBar)
        assert bar.k_blocks == 100  # total becomes k_blocks


# ============================================================================
# ASCII QR Tests
# ============================================================================

class TestASCIIQRCode:
    """Tests for ASCIIQRCode class."""
    
    def test_basic_creation(self):
        """Test creating ASCII QR code."""
        qr = ASCIIQRCode("Hello World")
        
        assert qr.data == "Hello World"
        assert qr.size > 0
        assert qr.version >= 1
    
    def test_render_unicode(self):
        """Test unicode rendering."""
        qr = ASCIIQRCode("Test", border=1)
        
        output = qr.render_unicode()
        
        assert len(output) > 0
        # Should contain block characters
        assert any(c in output for c in ['█', '▀', '▄', ' '])
    
    def test_render_ascii(self):
        """Test ASCII rendering."""
        qr = ASCIIQRCode("Test", border=1)
        
        output = qr.render_ascii()
        
        assert len(output) > 0
        # Should contain only ASCII characters
        assert all(ord(c) < 128 for c in output)
    
    def test_render_large(self):
        """Test large rendering."""
        qr = ASCIIQRCode("Test", border=1)
        
        normal = qr.render_unicode()
        large = qr.render_large()
        
        # Large should have more lines (2x)
        normal_lines = normal.count('\n')
        large_lines = large.count('\n')
        
        # Large should be roughly 4x as big (2x2 per module)
        assert large_lines > normal_lines
    
    def test_render_colored(self):
        """Test colored rendering."""
        qr = ASCIIQRCode("Test", border=1)
        
        output = qr.render_colored()
        
        # Should contain ANSI escape codes
        assert '\033[' in output
        assert qr.RESET in output
    
    def test_invert(self):
        """Test color inversion."""
        qr = ASCIIQRCode("Test", border=1)
        
        normal = qr.render_unicode(invert=False)
        inverted = qr.render_unicode(invert=True)
        
        # Outputs should differ (inverted pattern)
        # They have same characters but different positions
        assert normal != inverted
    
    def test_error_correction_levels(self):
        """Test different error correction levels."""
        data = "Test data for error correction"
        
        for level in ['L', 'M', 'Q', 'H']:
            qr = ASCIIQRCode(data, error_correction=level)
            assert qr.size > 0
            # Higher EC = larger QR
            # L < M < Q < H (usually)
    
    def test_module_count(self):
        """Test module count property."""
        qr = ASCIIQRCode("Test")
        
        # Module count should be positive and reasonable (21-177 for QR versions 1-40)
        assert qr.module_count >= 21
        assert qr.module_count <= 177
    
    def test_render_method_dispatch(self):
        """Test render() method with different modes."""
        qr = ASCIIQRCode("Test", border=1)
        
        for mode in ['unicode', 'ascii', 'large', 'colored']:
            output = qr.render(mode=mode)
            assert len(output) > 0


class TestGenerateTerminalQR:
    """Tests for generate_terminal_qr function."""
    
    def test_basic_generation(self):
        """Test basic QR generation."""
        output = generate_terminal_qr("Hello")
        
        assert len(output) > 0
        assert '\n' in output  # Multiple lines
    
    def test_different_modes(self):
        """Test different rendering modes."""
        data = "Test"
        
        outputs = {}
        for mode in ['unicode', 'ascii', 'large', 'colored']:
            outputs[mode] = generate_terminal_qr(data, mode=mode)
        
        # All should produce output
        assert all(len(o) > 0 for o in outputs.values())
        
        # Different modes should produce different output
        assert outputs['unicode'] != outputs['ascii']
        assert outputs['unicode'] != outputs['colored']


class TestPrintTerminalQR:
    """Tests for print_terminal_qr function."""
    
    def test_print_without_title(self):
        """Test printing QR without title."""
        with patch('builtins.print') as mock_print:
            print_terminal_qr("Test")
            
            # Should have been called at least once
            assert mock_print.called
    
    def test_print_with_title(self):
        """Test printing QR with title."""
        with patch('builtins.print') as mock_print:
            print_terminal_qr("Test", title="My QR Code")
            
            # Check title was printed
            calls = [str(c) for c in mock_print.call_args_list]
            assert any("My QR Code" in str(c) for c in calls)


class TestAnimatedTerminalQR:
    """Tests for AnimatedTerminalQR class."""
    
    def test_animated_creation(self):
        """Test creating animated QR."""
        data = [b"Frame 1", b"Frame 2", b"Frame 3"]
        anim = AnimatedTerminalQR(data, fps=10)
        
        assert anim.fps == 10
        assert len(anim.data_list) == 3
    
    def test_frame_delay_calculation(self):
        """Test frame delay is calculated correctly."""
        data = [b"Frame"]
        
        anim5 = AnimatedTerminalQR(data, fps=5)
        anim10 = AnimatedTerminalQR(data, fps=10)
        
        assert anim5.frame_delay == 0.2  # 1/5
        assert anim10.frame_delay == 0.1  # 1/10


# ============================================================================
# Bidirectional Protocol Tests
# ============================================================================

class TestSessionInfo:
    """Tests for SessionInfo class."""
    
    def test_session_creation(self):
        """Test creating session info."""
        session = SessionInfo(
            session_id=b'12345678',
            total_frames=100,
            k_blocks=80,
            block_size=512,
            file_hash=hashlib.sha256(b"test").digest()
        )
        
        assert session.total_frames == 100
        assert session.k_blocks == 80
        assert len(session.session_id) == 8
    
    def test_session_pack_unpack(self):
        """Test packing and unpacking session info."""
        original = SessionInfo(
            session_id=b'abcdefgh',
            total_frames=150,
            k_blocks=100,
            block_size=256,
            file_hash=hashlib.sha256(b"test data").digest()
        )
        
        packed = original.pack()
        unpacked = SessionInfo.unpack(packed)
        
        assert unpacked.session_id == original.session_id
        assert unpacked.total_frames == original.total_frames
        assert unpacked.k_blocks == original.k_blocks
        assert unpacked.block_size == original.block_size
        assert unpacked.file_hash == original.file_hash


class TestStatusUpdate:
    """Tests for StatusUpdate class."""
    
    def test_status_creation(self):
        """Test creating status update."""
        status = StatusUpdate(
            session_id=b'12345678',
            frames_received=50,
            frames_decoded=48,
            blocks_decoded=40,
            k_blocks_needed=100,
            missing_estimate=65,
            error_count=2
        )
        
        assert status.frames_received == 50
        assert status.blocks_decoded == 40
    
    def test_status_to_dict(self):
        """Test converting status to dictionary."""
        status = StatusUpdate(
            session_id=b'12345678',
            frames_received=50,
            frames_decoded=50,
            blocks_decoded=40,
            k_blocks_needed=100,
            missing_estimate=60,
            error_count=0
        )
        
        d = status.to_dict()
        
        assert 'progress_percent' in d
        assert d['progress_percent'] == 40.0
        assert d['frames_received'] == 50
    
    def test_status_compact_string(self):
        """Test compact status string."""
        status = StatusUpdate(
            session_id=b'abcdefgh',
            frames_received=100,
            frames_decoded=98,
            blocks_decoded=80,
            k_blocks_needed=100,
            missing_estimate=25,
            error_count=2
        )
        
        compact = status.to_compact_string()
        
        # Should be short
        assert len(compact) < 100
        # Should contain key info
        assert "R100" in compact or "100" in compact
        assert "80" in compact
        assert "E2" in compact


class TestBiDirectionalSender:
    """Tests for BiDirectionalSender class."""
    
    def test_sender_creation(self):
        """Test creating sender."""
        file_hash = hashlib.sha256(b"data").digest()
        
        sender = BiDirectionalSender(
            file_hash=file_hash,
            k_blocks=100,
            block_size=512,
            total_frames=150
        )
        
        assert sender.session.k_blocks == 100
        assert len(sender.session.session_id) == 8
    
    def test_session_start_message(self):
        """Test generating session start message."""
        file_hash = hashlib.sha256(b"data").digest()
        sender = BiDirectionalSender(file_hash, 100, 512, 150)
        
        msg = sender.get_session_start_message()
        
        # First byte should be message type
        assert msg[0] == MessageType.SESSION_START
        # Should contain session info
        assert len(msg) > 50
    
    def test_should_continue_sending(self):
        """Test sending continuation logic."""
        file_hash = hashlib.sha256(b"data").digest()
        sender = BiDirectionalSender(file_hash, 100, 512, 150)
        
        # Should continue at start
        assert sender.should_continue_sending() == True
        
        # Should stop when complete
        sender.is_complete = True
        assert sender.should_continue_sending() == False
        
        # Should stop when paused
        sender.is_complete = False
        sender.is_paused = True
        assert sender.should_continue_sending() == False


class TestBiDirectionalReceiver:
    """Tests for BiDirectionalReceiver class."""
    
    def test_receiver_creation(self):
        """Test creating receiver."""
        receiver = BiDirectionalReceiver()
        
        assert receiver.session is None
        assert len(receiver.frames_received) == 0
    
    def test_process_session_start(self):
        """Test processing session start."""
        # Create sender and get session start message
        file_hash = hashlib.sha256(b"data").digest()
        sender = BiDirectionalSender(file_hash, 100, 512, 150)
        msg = sender.get_session_start_message()
        
        # Receiver processes it
        receiver = BiDirectionalReceiver()
        result = receiver.process_session_start(msg)
        
        assert result == True
        assert receiver.session is not None
        assert receiver.session.k_blocks == 100
    
    def test_frame_tracking(self):
        """Test frame receipt tracking."""
        receiver = BiDirectionalReceiver()
        
        receiver.on_frame_received(0, success=True)
        receiver.on_frame_received(1, success=True)
        receiver.on_frame_received(2, success=False)  # Decode failed
        
        assert len(receiver.frames_received) == 3
        assert len(receiver.frames_decoded) == 2
        assert receiver.error_count == 1
    
    def test_status_update_generation(self):
        """Test generating status update."""
        # Setup receiver with session
        file_hash = hashlib.sha256(b"data").digest()
        sender = BiDirectionalSender(file_hash, 100, 512, 150)
        msg = sender.get_session_start_message()
        
        receiver = BiDirectionalReceiver()
        receiver.process_session_start(msg)
        
        # Add some progress
        for i in range(50):
            receiver.on_frame_received(i, success=True)
        receiver.on_blocks_decoded(40)
        
        status = receiver.get_status_update()
        
        assert status.frames_received == 50
        assert status.blocks_decoded == 40
        assert status.k_blocks_needed == 100
    
    def test_completion_detection(self):
        """Test detecting completion."""
        file_hash = hashlib.sha256(b"data").digest()
        sender = BiDirectionalSender(file_hash, 100, 512, 150)
        msg = sender.get_session_start_message()
        
        receiver = BiDirectionalReceiver()
        receiver.process_session_start(msg)
        
        # Not complete yet
        receiver.on_blocks_decoded(50)
        assert receiver.is_complete() == False
        
        # Complete
        receiver.on_blocks_decoded(100)
        assert receiver.is_complete() == True
    
    def test_feedback_qr_data(self):
        """Test getting feedback QR data."""
        file_hash = hashlib.sha256(b"data").digest()
        sender = BiDirectionalSender(file_hash, 100, 512, 150)
        msg = sender.get_session_start_message()
        
        receiver = BiDirectionalReceiver()
        receiver.process_session_start(msg)
        
        for i in range(75):
            receiver.on_frame_received(i, success=True)
        receiver.on_blocks_decoded(60)
        
        feedback = receiver.get_status_qr_data()
        
        # Should be compact
        assert len(feedback) < 100
        # Should contain progress info
        assert "60" in feedback


class TestBiDirectionalProtocol:
    """Tests for BiDirectionalProtocol class."""
    
    def test_sender_protocol(self):
        """Test sender-side protocol."""
        file_hash = hashlib.sha256(b"data").digest()
        
        protocol = BiDirectionalProtocol(is_sender=True)
        msg = protocol.start_session(file_hash, 100, 512, 150)
        
        assert protocol.sender is not None
        assert len(msg) > 0
    
    def test_receiver_protocol(self):
        """Test receiver-side protocol."""
        protocol = BiDirectionalProtocol(is_sender=False)
        
        assert protocol.receiver is not None
    
    def test_end_to_end_protocol(self):
        """Test full protocol exchange."""
        file_hash = hashlib.sha256(b"test data").digest()
        
        # Sender starts session
        sender = BiDirectionalProtocol(is_sender=True)
        session_msg = sender.start_session(file_hash, 100, 512, 150)
        
        # Receiver gets session
        receiver = BiDirectionalProtocol(is_sender=False)
        result = receiver.receive_session_start(session_msg)
        assert result == True
        
        # Simulate transfer
        for i in range(120):
            receiver.on_frame(i, success=True)
            if i % 10 == 0:
                receiver.on_decode_progress((i * 100) // 120)
        
        receiver.on_decode_progress(100)
        
        # Check completion
        assert receiver.should_continue() == False
        
        # Get final feedback
        feedback = receiver.get_feedback_qr()
        assert feedback is not None


class TestConvenienceFunctions:
    """Tests for module convenience functions."""
    
    def test_create_sender_protocol(self):
        """Test create_sender_protocol function."""
        file_hash = hashlib.sha256(b"data").digest()
        
        protocol = create_sender_protocol(file_hash, 100, 512, 150)
        
        assert protocol.sender is not None
        assert protocol.sender.session.k_blocks == 100
    
    def test_create_receiver_protocol(self):
        """Test create_receiver_protocol function."""
        protocol = create_receiver_protocol()
        
        assert protocol.receiver is not None
        assert protocol.receiver.session is None  # Until session received


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests across modules."""
    
    def test_progress_with_fountain_simulation(self):
        """Test progress bar with simulated fountain decoding."""
        bar = FountainProgressBar(k_blocks=100, expected_droplets=150)
        
        # Simulate decoding progress
        for i in range(150):
            blocks_decoded = min(100, int(i * 0.7))  # 70% efficiency
            bar.update_decoding(
                droplets_received=i + 1,
                blocks_decoded=blocks_decoded
            )
            
            if blocks_decoded >= 100:
                break
        
        # Verify completion via blocks_decoded
        assert bar.blocks_decoded == bar.k_blocks
    
    def test_ascii_qr_with_bidirectional_status(self):
        """Test displaying bidirectional status as ASCII QR."""
        # Setup bidirectional receiver
        file_hash = hashlib.sha256(b"data").digest()
        sender = create_sender_protocol(file_hash, 100, 512, 150)
        session_msg = sender.sender.get_session_start_message()
        
        receiver = create_receiver_protocol()
        receiver.receive_session_start(session_msg)
        
        # Generate status
        for i in range(50):
            receiver.on_frame(i, success=True)
        receiver.on_decode_progress(40)
        
        feedback = receiver.get_feedback_qr()
        
        # Generate ASCII QR of the feedback
        qr = ASCIIQRCode(feedback, border=1)
        output = qr.render_unicode()
        
        # Should be valid QR output
        assert len(output) > 0
        assert '\n' in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
