"""
Mobile Bridge CLI Handler — Connects React Native scanner to meow-decode-gif.

This module implements the CLI-side of the mobile bridge protocol, accepting
QR frame data from the React Native scanner app via stdin, WebSocket, or file.

Usage:
    # Stdin mode (pipe from adb or similar)
    adb shell cat /sdcard/meow_frames.json | meow-decode-gif --mobile-bridge -o out.pdf -p "pass"

    # File mode
    meow-decode-gif --mobile-bridge --input-frames frames.json -o out.pdf -p "pass"

    # WebSocket mode (phone connects directly)
    meow-decode-gif --mobile-bridge --bridge-mode websocket --bridge-port 8765 -o out.pdf -p "pass"

    # Generate capture request for mobile app
    meow-decode-gif --mobile-bridge --output-request request.json
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from argparse import Namespace

# Import protocol messages from mobile/bridge
sys.path.insert(0, str(Path(__file__).parent.parent / "mobile"))
try:
    from bridge.protocol import (
        Ack,
        Error,
        Frame,
        Progress,
        Result,
        ScanEnd,
        ScanStart,
        parse_phone_message,
        MAX_FRAME_BYTES,
    )
except ImportError:
    # Fallback: define minimal protocol classes inline
    @dataclass
    class Frame:
        seq: int
        qr_bytes_b64: str
        timestamp_ms: int = 0

        @property
        def qr_bytes(self) -> bytes:
            import base64
            return base64.b64decode(self.qr_bytes_b64)

    def parse_phone_message(raw: str):
        data = json.loads(raw)
        if data.get("type") == "frame":
            return Frame(
                seq=data["seq"],
                qr_bytes_b64=data["qr_bytes_b64"],
                timestamp_ms=data.get("timestamp_ms", 0),
            )
        return data

    MAX_FRAME_BYTES = 4096

    @dataclass
    class Ack:
        seq: int
        accepted: bool
        reason: str = ""
        type: str = "ack"

        def to_json(self) -> str:
            return json.dumps(asdict(self))

    @dataclass
    class Progress:
        frames_received: int
        frames_needed: int
        blocks_decoded: int
        blocks_total: int
        percent: float
        type: str = "progress"

        def to_json(self) -> str:
            return json.dumps(asdict(self))

    @dataclass
    class Result:
        success: bool
        output_file: str
        output_size: int
        elapsed_s: float
        error: Optional[str] = None
        type: str = "result"

        def to_json(self) -> str:
            return json.dumps(asdict(self))

    @dataclass
    class Error:
        code: str
        message: str
        type: str = "error"

        def to_json(self) -> str:
            return json.dumps(asdict(self))


@dataclass
class CaptureRequest:
    """Request sent to mobile app to initiate capture."""

    action: str = "capture"
    session_id: str = ""
    expected_frames: int = 0
    timeout_seconds: int = 60

    def __post_init__(self):
        if not self.session_id:
            self.session_id = str(uuid.uuid4())

    def to_json(self) -> str:
        return json.dumps(asdict(self))


def write_capture_request(output_path: Path, expected_frames: int = 0, timeout: int = 60) -> None:
    """Write a capture request JSON file for the mobile app."""
    request = CaptureRequest(expected_frames=expected_frames, timeout_seconds=timeout)
    output_path.write_text(request.to_json())
    print(f"Wrote capture request to {output_path}")
    print(f"  Session ID: {request.session_id}")
    print(f"  Timeout: {timeout}s")


def read_frames_from_file(input_path: Path) -> list[bytes]:
    """Read captured frames from a JSON file exported by the mobile app."""
    data = json.loads(input_path.read_text())

    # Handle both array-of-frames and wrapped format
    if isinstance(data, list):
        frames_data = data
    elif isinstance(data, dict):
        frames_data = data.get("frames", [])
    else:
        raise ValueError(f"Invalid frames file format: expected list or dict")

    frames = []
    for item in frames_data:
        if isinstance(item, dict):
            frame = Frame(
                seq=item.get("seq", item.get("index", len(frames))),
                qr_bytes_b64=item.get("qr_bytes_b64", item.get("data", "")),
                timestamp_ms=item.get("timestamp_ms", 0),
            )
            frames.append((frame.seq, frame.qr_bytes))
        elif isinstance(item, str):
            # Raw base64 strings
            import base64
            frames.append((len(frames), base64.b64decode(item)))

    # Sort by sequence number
    frames.sort(key=lambda x: x[0])
    return [qr_bytes for _, qr_bytes in frames]


def read_frames_from_stdin(
    on_frame: Optional[Callable[[int, bytes], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> list[bytes]:
    """Read frames from stdin in JSON-lines format (one message per line)."""
    frames: dict[int, bytes] = {}
    total_expected = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = parse_phone_message(line)

            if hasattr(msg, "type"):
                if msg.type == "scan_start":
                    print(f"Scan started from device: {getattr(msg, 'device_id', 'unknown')}")
                    continue
                elif msg.type == "scan_end":
                    print(f"Scan complete: {getattr(msg, 'total_frames_sent', len(frames))} frames")
                    break
                elif msg.type == "frame":
                    if len(msg.qr_bytes) > MAX_FRAME_BYTES:
                        ack = Ack(seq=msg.seq, accepted=False, reason="frame too large")
                        print(ack.to_json(), flush=True)
                        continue

                    frames[msg.seq] = msg.qr_bytes

                    if on_frame:
                        on_frame(msg.seq, msg.qr_bytes)

                    # Send acknowledgement
                    ack = Ack(seq=msg.seq, accepted=True)
                    print(ack.to_json(), flush=True)

                    if on_progress:
                        on_progress(len(frames), total_expected)

        except (json.JSONDecodeError, ValueError) as e:
            err = Error(code="PARSE_ERROR", message=str(e))
            print(err.to_json(), file=sys.stderr, flush=True)

    # Return frames sorted by sequence
    return [frames[seq] for seq in sorted(frames.keys())]


async def run_websocket_bridge(
    port: int,
    password: str,
    output_path: Path,
    decode_callback: Callable[[list[bytes], str, Path], tuple[bool, str, int]],
) -> None:
    """Run WebSocket server for mobile bridge.

    Args:
        port: WebSocket server port
        password: Decryption password
        output_path: Output file path
        decode_callback: Function(frames, password, output) -> (success, error, size)
    """
    try:
        import websockets
    except ImportError:
        print("Error: websockets package required for WebSocket bridge mode", file=sys.stderr)
        print("  Install with: pip install websockets", file=sys.stderr)
        sys.exit(1)

    frames: dict[int, bytes] = {}
    start_time = time.time()

    async def handler(websocket):
        nonlocal frames, start_time

        async for message in websocket:
            try:
                msg = parse_phone_message(message)

                if hasattr(msg, "type"):
                    if msg.type == "scan_start":
                        frames = {}
                        start_time = time.time()
                        print(f"Scan started from: {getattr(msg, 'device_id', 'unknown')}")

                    elif msg.type == "frame":
                        if len(msg.qr_bytes) > MAX_FRAME_BYTES:
                            await websocket.send(
                                Ack(seq=msg.seq, accepted=False, reason="too large").to_json()
                            )
                            continue

                        frames[msg.seq] = msg.qr_bytes
                        await websocket.send(Ack(seq=msg.seq, accepted=True).to_json())

                        # Send progress update every 5 frames
                        if len(frames) % 5 == 0:
                            progress = Progress(
                                frames_received=len(frames),
                                frames_needed=0,  # Unknown until manifest decoded
                                blocks_decoded=0,
                                blocks_total=0,
                                percent=0.0,
                            )
                            await websocket.send(progress.to_json())

                    elif msg.type == "scan_end":
                        # Decode the frames
                        elapsed = time.time() - start_time
                        sorted_frames = [frames[seq] for seq in sorted(frames.keys())]

                        success, error, size = decode_callback(
                            sorted_frames, password, output_path
                        )

                        result = Result(
                            success=success,
                            output_file=str(output_path) if success else "",
                            output_size=size,
                            elapsed_s=elapsed,
                            error=error if not success else None,
                        )
                        await websocket.send(result.to_json())

            except Exception as e:
                await websocket.send(Error(code="INTERNAL", message=str(e)).to_json())

    async with websockets.serve(handler, "0.0.0.0", port):
        print(f"Mobile bridge WebSocket server listening on ws://0.0.0.0:{port}")
        print("Waiting for mobile app connection...")
        await asyncio.Future()  # Run forever


def handle_mobile_bridge(args: "Namespace", decode_frames_func: Callable) -> None:
    """Main entry point for mobile bridge mode.

    Args:
        args: Parsed CLI arguments
        decode_frames_func: Function to decode frames -> file
    """
    # Handle capture request generation
    if args.output_request:
        write_capture_request(args.output_request)
        sys.exit(0)

    # Handle file input mode
    if args.input_frames:
        if not args.input_frames.exists():
            print(f"Error: Frames file not found: {args.input_frames}", file=sys.stderr)
            sys.exit(1)

        print(f"Reading frames from {args.input_frames}...")
        frames = read_frames_from_file(args.input_frames)
        print(f"Loaded {len(frames)} frames")

        # Decode using the provided callback
        success = decode_frames_func(frames, args)
        sys.exit(0 if success else 1)

    # Handle stdin mode
    if args.bridge_mode == "stdin":
        print("Reading frames from stdin (JSON-lines format)...")
        frames = read_frames_from_stdin()
        print(f"Received {len(frames)} frames")

        success = decode_frames_func(frames, args)

        # Send result to stdout
        result = Result(
            success=success,
            output_file=str(args.output) if success else "",
            output_size=args.output.stat().st_size if success and args.output.exists() else 0,
            elapsed_s=0.0,
        )
        print(result.to_json())
        sys.exit(0 if success else 1)

    # Handle WebSocket mode
    if args.bridge_mode == "websocket":
        import asyncio

        def decode_callback(frames, password, output):
            # Create a minimal args namespace for the decode function
            class DecodeArgs:
                pass

            decode_args = DecodeArgs()
            decode_args.output = output
            decode_args.password = password
            decode_args.verbose = getattr(args, "verbose", False)

            try:
                success = decode_frames_func(frames, decode_args)
                size = output.stat().st_size if success and output.exists() else 0
                return (success, None, size)
            except Exception as e:
                return (False, str(e), 0)

        asyncio.run(
            run_websocket_bridge(
                port=args.bridge_port,
                password=args.password,
                output_path=args.output,
                decode_callback=decode_callback,
            )
        )
