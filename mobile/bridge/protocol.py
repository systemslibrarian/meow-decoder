"""
Meow Bridge — JSON wire protocol message definitions.

This module defines the message types exchanged between the mobile QR scanner
app (React Native) and the CLI bridge server over WebSocket.

The phone is a **dumb scanner**: it sends raw QR bytes, receives progress and
results.  No crypto runs on the device.

See mobile/ARCHITECTURE.md for the full protocol specification.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

# ── Phone → CLI ──────────────────────────────────────────────────────────────


@dataclass
class ScanStart:
    """Sent once when the user begins scanning."""

    type: str = field(default="scan_start", init=False)
    device_id: str = ""
    timestamp_ms: int = 0

    def __post_init__(self):
        if self.timestamp_ms == 0:
            self.timestamp_ms = int(time.time() * 1000)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Frame:
    """One QR code frame captured by the phone camera."""

    type: str = field(default="frame", init=False)
    seq: int = 0
    qr_bytes_b64: str = ""
    timestamp_ms: int = 0

    def __post_init__(self):
        if self.timestamp_ms == 0:
            self.timestamp_ms = int(time.time() * 1000)

    @classmethod
    def from_raw(cls, seq: int, qr_bytes: bytes) -> "Frame":
        """Create a Frame from raw QR payload bytes."""
        return cls(seq=seq, qr_bytes_b64=base64.b64encode(qr_bytes).decode("ascii"))

    @property
    def qr_bytes(self) -> bytes:
        """Decode the base64 payload back to raw bytes."""
        return base64.b64decode(self.qr_bytes_b64)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class ScanEnd:
    """Sent when scanning is complete."""

    type: str = field(default="scan_end", init=False)
    total_frames_sent: int = 0
    timestamp_ms: int = 0

    def __post_init__(self):
        if self.timestamp_ms == 0:
            self.timestamp_ms = int(time.time() * 1000)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


# ── CLI → Phone ──────────────────────────────────────────────────────────────


@dataclass
class Ack:
    """Acknowledgement for a received frame."""

    type: str = field(default="ack", init=False)
    seq: int = 0
    accepted: bool = True
    reason: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Progress:
    """Decoding progress update."""

    type: str = field(default="progress", init=False)
    frames_received: int = 0
    frames_needed: int = 0
    blocks_decoded: int = 0
    blocks_total: int = 0
    percent: float = 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Result:
    """Final decode result."""

    type: str = field(default="result", init=False)
    success: bool = False
    output_file: str = ""
    output_size: int = 0
    elapsed_s: float = 0.0
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Error:
    """Fatal error."""

    type: str = field(default="error", init=False)
    code: str = "INTERNAL"
    message: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self))


# ── Error Codes ──────────────────────────────────────────────────────────────

HMAC_FAIL = "HMAC_FAIL"
DECODE_INCOMPLETE = "DECODE_INCOMPLETE"
QR_CORRUPT = "QR_CORRUPT"
MANIFEST_INVALID = "MANIFEST_INVALID"
INTERNAL = "INTERNAL"

# Maximum allowed QR payload size (bytes).  Frames exceeding this are rejected
# to prevent denial-of-service from a compromised phone.
MAX_FRAME_BYTES = 4096


# ── Parsing ──────────────────────────────────────────────────────────────────

_PHONE_MSG_TYPES = {
    "scan_start": ScanStart,
    "frame": Frame,
    "scan_end": ScanEnd,
}

_CLI_MSG_TYPES = {
    "ack": Ack,
    "progress": Progress,
    "result": Result,
    "error": Error,
}


def parse_phone_message(raw: str) -> ScanStart | Frame | ScanEnd:
    """Parse a JSON message from the phone.

    Raises ``ValueError`` on unknown or malformed messages.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    msg_type = data.get("type")
    cls = _PHONE_MSG_TYPES.get(msg_type)  # type: ignore[arg-type]
    if cls is None:
        raise ValueError(f"Unknown phone message type: {msg_type!r}")

    # Strip the 'type' key (it's set by __post_init__) and construct
    filtered = {k: v for k, v in data.items() if k != "type"}
    return cls(**filtered)


def parse_cli_message(raw: str) -> Ack | Progress | Result | Error:
    """Parse a JSON message from the CLI bridge.

    Raises ``ValueError`` on unknown or malformed messages.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    msg_type = data.get("type")
    cls = _CLI_MSG_TYPES.get(msg_type)  # type: ignore[arg-type]
    if cls is None:
        raise ValueError(f"Unknown CLI message type: {msg_type!r}")

    filtered = {k: v for k, v in data.items() if k != "type"}
    return cls(**filtered)
