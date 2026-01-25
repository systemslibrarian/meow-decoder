"""
🐱 Bidirectional Communication Module
Optional reverse channel for enhanced transfer reliability

DESIGN DECISION:
- This is a CONTROL CHANNEL ONLY
- We do NOT replace fountain code redundancy with ACK-heavy retransmission
- Fountain codes remain the primary error correction mechanism
- Bidirectional mode AUGMENTS, not REPLACES, the fountain approach

Features:
- Session framing (unique session IDs)
- Optional acknowledgments (which frames decoded)
- Early termination (stop when receiver has enough)
- Status updates (progress feedback to sender)

Use Cases:
- Interactive transfer (both devices in same room)
- Faster completion (stop sending when receiver is done)
- Debugging (see which frames are missing)
"""

import secrets
import struct
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Optional, List, Set, Dict, Any
from enum import IntEnum
import base64
import json


class MessageType(IntEnum):
    """Bidirectional protocol message types."""
    # Sender → Receiver
    SESSION_START = 0x01
    SESSION_END = 0x02
    FRAME_DATA = 0x03
    HEARTBEAT = 0x04
    
    # Receiver → Sender
    SESSION_ACK = 0x11
    FRAME_ACK = 0x12
    STATUS_UPDATE = 0x13
    COMPLETION = 0x14
    ERROR = 0x15
    
    # Control
    RESEND_REQUEST = 0x21
    PAUSE = 0x22
    RESUME = 0x23


@dataclass
class SessionInfo:
    """
    Bidirectional session information.
    
    The session ID provides:
    - Uniqueness (prevents mixing transfers)
    - Ordering (sequence numbers)
    - Binding (receiver knows which session they're in)
    - Authentication (HMAC key shared via session start)
    """
    session_id: bytes  # 8 bytes, random
    total_frames: int
    k_blocks: int
    block_size: int
    file_hash: bytes  # SHA-256 of original file
    auth_key: bytes   # 32 bytes, HMAC key
    created_at: float = field(default_factory=time.time)
    
    def pack(self) -> bytes:
        """Pack session info to bytes."""
        # Format: session_id(8) + total_frames(4) + k(4) + block_size(2) + file_hash(32) + auth_key(32)
        # Total: 82 bytes
        return struct.pack(
            '>8sIIH32s32s',
            self.session_id,
            self.total_frames,
            self.k_blocks,
            self.block_size,
            self.file_hash,
            self.auth_key
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'SessionInfo':
        """Unpack session info from bytes."""
        if len(data) < 82:
            raise ValueError(f"Session info too short: {len(data)} (need 82)")
            
        session_id, total_frames, k_blocks, block_size, file_hash, auth_key = struct.unpack(
            '>8sIIH32s32s', data[:82]
        )
        return cls(
            session_id=session_id,
            total_frames=total_frames,
            k_blocks=k_blocks,
            block_size=block_size,
            file_hash=file_hash,
            auth_key=auth_key
        )


@dataclass
class FrameAck:
    """Acknowledgment of received frames."""
    session_id: bytes
    received_frames: Set[int]  # Frame indices that were received
    blocks_decoded: int        # How many source blocks decoded
    timestamp: float = field(default_factory=time.time)
    
    def is_complete(self, k_blocks: int) -> bool:
        """Check if receiver has decoded all blocks."""
        return self.blocks_decoded >= k_blocks


@dataclass
class StatusUpdate:
    """Status update from receiver to sender."""
    session_id: bytes
    frames_received: int
    frames_decoded: int        # Frames successfully decoded (valid QR)
    blocks_decoded: int        # Source blocks recovered
    k_blocks_needed: int       # Total source blocks needed
    missing_estimate: int      # Estimated frames still needed
    error_count: int           # QR decode errors
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'session_id': self.session_id.hex(),
            'frames_received': self.frames_received,
            'frames_decoded': self.frames_decoded,
            'blocks_decoded': self.blocks_decoded,
            'k_blocks_needed': self.k_blocks_needed,
            'missing_estimate': self.missing_estimate,
            'error_count': self.error_count,
            'timestamp': self.timestamp,
            'progress_percent': 100.0 * self.blocks_decoded / self.k_blocks_needed if self.k_blocks_needed > 0 else 0.0
        }
    
    def to_compact_string(self) -> str:
        """Generate compact status string for QR display."""
        # Format: SESSION:RECV:DEC:BLOCKS:NEEDED:ERR
        return f"S:{self.session_id.hex()[:8]}:R{self.frames_received}:D{self.blocks_decoded}/{self.k_blocks_needed}:E{self.error_count}"


class BiDirectionalSender:
    """
    Sender with bidirectional communication support.
    
    IMPORTANT: This does NOT replace fountain code redundancy!
    The bidirectional channel is for:
    - Early termination when receiver is done
    - Status visibility
    - Debugging
    
    We still send fountain-coded frames as the primary mechanism.
    """
    
    def __init__(self, file_hash: bytes, k_blocks: int, block_size: int,
                 total_frames: int):
        """
        Initialize bidirectional sender.
        
        Args:
            file_hash: SHA-256 of original file
            k_blocks: Number of source blocks
            block_size: Size of each block
            total_frames: Total fountain frames to send
        """
        self.session = SessionInfo(
            session_id=secrets.token_bytes(8),
            total_frames=total_frames,
            k_blocks=k_blocks,
            block_size=block_si,
            auth_key=secrets.token_bytes(32)  # Generate random auth keyze,
            file_hash=file_hash
        )
        
        self.frames_sent = 0
        self.acks_received: List[FrameAck] = []
        self.status_updates: List[StatusUpdate] = []
        self.is_complete = False
        self.is_paused = False
    
    def get_session_start_message(self) -> bytes:
        """Generate session start message (encode to QR for receiver)."""
        msg_type = struct.pack('B', MessageType.SESSION_START)
        return msg_type + self.session.pack()
    
    def process_ack(self, ack_data: bytes) -> Optional[StatusUpdate]:
        """
        Process acknowledgment from receiver.
        
        Args:
            ack_data: Raw acknowledgment data
            
        Returns:
            StatusUpdate if33:
            # Need Type (1) + HMAC (32)
            return None
        
        msg_type = ack_data[0]
        mac = ack_data[1:33]
        payload = ack_data[33:]
        
        # Verify HMAC
        expected_mac = hmac.new(
            self.session.auth_key,
            bytes([msg_type]) + payload,
            hashlib.sha256
        ).digest()
        
        if not secrets.compare_digest(mac, expected_mac):
            print("⚠️  Invalid HMAC on ack packet")
            return None
        msg_type = ack_data[0]
        payload = ack_data[1:]
        
        if msg_type == MessageType.COMPLETION:
            self.is_complete = True
            print("🎉 Receiver signaled completion!")
            
        elif msg_type == MessageType.STATUS_UPDATE:
            try:
                status = self._parse_status_update(payload)
                self.status_updates.append(status)
                
                # Check for completion
                if status.blocks_decoded >= self.session.k_blocks:
                    self.is_complete = True
                
                return status
            except Exception:
                pass
        
        elif msg_type == MessageType.PAUSE:
            self.is_paused = True
            
        elif msg_type == MessageType.RESUME:
            self.is_paused = False
        
        return None
    
    def _parse_status_update(self, data: bytes) -> StatusUpdate:
        """Parse status update from receiver."""
        # Format: session_id(8) + frames_received(4) + frames_decoded(4) + 
        #         blocks_decoded(4) + k_blocks_needed(4) + missing(4) + errors(4)
        if len(data) < 32:
            raise ValueError("Status update too short")
        
        session_id = data[:8]
        (frames_received, frames_decoded, blocks_decoded, 
         k_blocks_needed, missing, errors) = struct.unpack('>IIIIII', data[8:32])
        
        return StatusUpdate(
            session_id=session_id,
            frames_received=frames_received,
            frames_decoded=frames_decoded,
            blocks_decoded=blocks_decoded,
            k_blocks_needed=k_blocks_needed,
            missing_estimate=missing,
            error_count=errors
        )
    
    def should_continue_sending(self) -> bool:
        """Check if we should continue sending frames."""
        if self.is_complete:
            return False
        if self.is_paused:
            return False
        return True
    
    def on_frame_sent(self, frame_idx: int) -> None:
        """Called when a frame is sent."""
        self.frames_sent = max(self.frames_sent, frame_idx + 1)


class BiDirectionalReceiver:
    """
    Receiver with bidirectional communication support.
    
    Tracks decoding progress and generates status messages
    that can be displayed (as QR or text) for the sender to see.
    """
    
    def __init__(self):
        """Initialize bidirectional receiver."""
        self.session: Optional[SessionInfo] = None
        self.frames_received: Set[int] = set()
        self.frames_decoded: Set[int] = set()  # Successfully QR-decoded
        self.blocks_decoded = 0
        self.error_count = 0
        self.started_at: Optional[float] = None
    
    def process_session_start(self, data: bytes) -> bool:
        """
        Process session start message from sender.
        
        Args:
            data: Session start message (with type byte)
            
        Returns:
            True if valid session, False otherwise
        """
        if len(data) < 1:
            return False
        
        if data[0] != MessageType.SESSION_START:
            return False
        
        try:
            self.session = SessionInfo.unpack(data[1:])
            self.started_at = time.time()
            return True
        except Exception:
            return False
    
    def on_frame_received(self, frame_idx: int, success: bool) -> None:
        """
        Record that a frame was received.
        
        _sign_packet(self, msg_type: int, payload: bytes) -> bytes:
        """Sign and pack a message."""
        if not self.session:
            return b''
            
        # Format: Type(1) + HMAC(32) + Payload
        header = bytes([msg_type])
        mac = hmac.new(
            self.session.auth_key, 
            header + payload, 
            hashlib.sha256
        ).digest()
        
        return header + mac + payload

    def Args:
            frame_idx: Frame index
            success: Whether QR decoding succeeded
        """
        self.frames_received.add(frame_idx)
        if success:
            self.frames_decoded.add(frame_idx)
        else:bytes:
        """
        Generate binary status packet for QR display back to sender.
        Returns binary data (Type + HMAC + Payload).
        """
        if not self.session:
            return b''
            
        # Pack status payload
        # Format: session_id(8) + frames_received(4) + frames_decoded(4) + 
        #         blocks_decoded(4) + k_blocks_needed(4) + missing(4) + errors(4)
        payload = self.session.session_id
        
        status = self.get_status_update()
        
        payload += struct.pack(
            '>IIIIII',
            status.frames_received,
            status.frames_decoded,
            status.blocks_decoded,
            status.k_blocks_needed,
            status.missing_estimate,
            status.error_count
        )
        
        return self._sign_packet(MessageType.STATUS_UPDATE, payload)
    
    def get_completion_message(self) -> bytes:
        """Generate completion message to send to sender."""
        payload = self.session.session_id if self.session else b'\x00' * 8
        return self._sign_packet(MessageType.COMPLETION, payload)= len(self.frames_decoded) / self.blocks_decoded
            missing = int((k_blocks - self.blocks_decoded) * ratio) + 5
        else:
            missing = k_blocks
        
        return StatusUpdate(
            session_id=self.session.session_id if self.session else b'\x00' * 8,
            frames_received=len(self.frames_received),
            frames_decoded=len(self.frames_decoded),
            blocks_decoded=self.blocks_decoded,
            k_blocks_needed=k_blocks,
            missing_estimate=missing,
            error_count=self.error_count
        )
    
    def get_status_qr_data(self) -> str:
        """
        Generate compact status string for QR display back to sender.
        
        This creates a small QR code that the sender can scan to see
        receiver progress without network connectivity.
        """
        status = self.get_status_update()
        return status.to_compact_string()
    
    def get_completion_message(self) -> bytes:
        """Generate completion message to send to sender."""
        msg = struct.pack('B', MessageType.COMPLETION)
        msg += self.session.session_id if self.session else b'\x00' * 8
        return msg
    
    def is_complete(self) -> bool:
        """Check if decoding is complete."""
        if not self.session:
            return False
        return self.blocks_decoded >= self.session.k_blocks


class BiDirectionalProtocol:
    """
    High-level bidirectional protocol manager.
    
    This class orchestrates the bidirectional communication,
    providing a clean interface for integration with the
    existing encoder/decoder.
    
    DESIGN NOTE:
    The bidirectional channel is OPTIONAL and NON-ESSENTIAL.
    Transfers work fine without it (standard fountain code behavior).
    When available, it provides:
    - Faster completion (stop early when receiver is done)
    - Better UX (progress visibility on sender side)
    - Debugging (see which frames are problematic)
    """
    
    def __init__(self, is_sender: bool = True):
        """
        Initialize protocol manager.
        
        Args:
            is_sender: True for sender, False for receiver
        """
        self.is_sender = is_sender
        self.sender: Optional[BiDirectionalSender] = None
        self.receiver: Optional[BiDirectionalReceiver] = None
        
        if is_sender:
            pass  # Sender initialized with start_session()
        else:
            self.receiver = BiDirectionalReceiver()
    
    # Sender methods
    
    def start_session(self, file_hash: bytes, k_blocks: int,
                     block_size: int, total_frames: int) -> bytes:
        """
        Start a new transfer session (sender side).
        
        Returns:
            Session start message to display/transmit
        """
        self.sender = BiDirectionalSender(
            file_hash=file_hash,
            k_blocks=k_blocks,
            block_size=block_size,
            total_frames=total_frames
        )
        return self.sender.get_session_start_message()
    
    def check_status(self, status_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Check current session status.
        
        Args:
            status_data: Optional status update from receiver
            
        Returns:
            Status dictionary
        """
        if self.sender:
            if status_data:
                self.sender.process_ack(status_data)
            
            return {
                'session_id': self.sender.session.session_id.hex(),
                'frames_sent': self.sender.frames_sent,
                'is_complete': self.senderbytes_complete,
                'is_paused': self.sender.is_paused,
                'status_updates': len(self.sender.status_updates),
            }
        
        if self.receiver:
            status = self.receiver.get_status_update()
            return status.to_dict()
        
        return {}
    
    def should_continue(self) -> bool:
        """Check if transfer should continue."""
        if self.sender:
            return self.sender.should_continue_sending()
        if self.receiver:
            return not self.receiver.is_complete()
        return True
    
    # Receiver methods
    
    def receive_session_start(self, data: bytes) -> bool:
        """
        Receive session start from sender.
        
        Args:
            data: Session start message
            
        Returns:
            True if valid session
        """
        if not self.receiver:
            self.receiver = BiDirectionalReceiver()
        return self.receiver.process_session_start(data)
    
    def on_frame(self, frame_idx: int, success: bool) -> None:
        """Record frame receipt (receiver side)."""
        if self.receiver:
            self.receiver.on_frame_received(frame_idx, success)
    
    def on_decode_progress(self, blocks_decoded: int) -> None:
        """Update decode progress (receiver side)."""
        if self.receiver:
            self.receiver.on_blocks_decoded(blocks_decoded)
    
    def get_feedback_qr(self) -> Optional[str]:
        """
        Get compact status string for feedback QR.
        
        The receiver can display this as a QR code that the
        sender's camera can scan to see progress.
        """
        if self.receiver:
            return self.receiver.get_status_qr_data()
        return None


# Convenience functions

def create_sender_protocol(file_hash: bytes, k_blocks: int,
                          block_size: int, total_frames: int) -> BiDirectionalProtocol:
    """Create and configure sender-side protocol."""
    protocol = BiDirectionalProtocol(is_sender=True)
    protocol.start_session(file_hash, k_blocks, block_size, total_frames)
    return protocol


def create_receiver_protocol() -> BiDirectionalProtocol:
    """Create receiver-side protocol."""
    return BiDirectionalProtocol(is_sender=False)


# Testing
if __name__ == "__main__":
    print("🐱 Bidirectional Protocol Demo\n")
    
    # Simulate a transfer
    file_hash = hashlib.sha256(b"test data").digest()
    
    print("📤 Sender side:")
    sender = create_sender_protocol(file_hash, k_blocks=100, block_size=512, total_frames=150)
    session_msg = sender.sender.get_session_start_message()
    print(f"   Session ID: {sender.sender.session.session_id.hex()}")
    print(f"   Session message: {len(session_msg)} bytes")
    
    print("\n📥 Receiver side:")
    receiver = create_receiver_protocol()
    receiver.receive_session_start(session_msg)
    print(f"   Session received: {receiver.receiver.session.session_id.hex()}")
    
    # Simulate some frames
    for i in range(75):
        receiver.on_frame(i, success=True)
    receiver.on_decode_progress(50)
    
    status = receiver.receiver.get_status_update()
    print(f"\n📊 Status Update:")
    print(f"   Frames received: {status.frames_received}")
    print(f"   Blocks decoded: {status.blocks_decoded}/{status.k_blocks_needed}")
    print(f"   Progress: {100*status.blocks_decoded/status.k_blocks_needed:.1f}%")
    
    # Feedback QR
    feedback = receiver.get_feedback_qr()
    print(f"\n📱 Feedback QR data: {feedback}")
    
    # Continue until done
    receiver.on_decode_progress(100)
    print(f"\n✅ Transfer complete: {receiver.receiver.is_complete()}")
    
    print("\n🎉 Bidirectional protocol working!")
    print("💡 Note: This augments fountain codes, doesn't replace them")
