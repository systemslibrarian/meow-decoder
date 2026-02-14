"""Tests for mobile_bridge.py — CLI handler for React Native scanner bridge."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

import pytest

from meow_decoder import mobile_bridge


class TestMobileBridgeDataClasses:
    """Tests for protocol data classes."""

    def test_frame_dataclass(self):
        """Test _Frame data class and qr_bytes property."""
        import base64

        raw = b"hello"
        b64 = base64.b64encode(raw).decode()

        frame = mobile_bridge._Frame(seq=0, qr_bytes_b64=b64, timestamp_ms=100)
        assert frame.seq == 0
        assert frame.qr_bytes == raw
        assert frame.timestamp_ms == 100

    def test_ack_dataclass(self):
        """Test _Ack serialization."""
        ack = mobile_bridge._Ack(seq=1, accepted=True, reason="")
        j = json.loads(ack.to_json())
        assert j["seq"] == 1
        assert j["accepted"] is True
        assert j["type"] == "ack"

    def test_ack_rejected(self):
        """Test _Ack with rejection reason."""
        ack = mobile_bridge._Ack(seq=2, accepted=False, reason="frame too large")
        j = json.loads(ack.to_json())
        assert j["accepted"] is False
        assert j["reason"] == "frame too large"

    def test_progress_dataclass(self):
        """Test _Progress serialization."""
        progress = mobile_bridge._Progress(
            frames_received=5,
            frames_needed=10,
            blocks_decoded=3,
            blocks_total=8,
            percent=50.0,
        )
        j = json.loads(progress.to_json())
        assert j["frames_received"] == 5
        assert j["percent"] == 50.0
        assert j["type"] == "progress"

    def test_result_dataclass(self):
        """Test _Result serialization."""
        result = mobile_bridge._Result(
            success=True,
            output_file="/tmp/out.pdf",
            output_size=1024,
            elapsed_s=2.5,
        )
        j = json.loads(result.to_json())
        assert j["success"] is True
        assert j["output_file"] == "/tmp/out.pdf"
        assert j["output_size"] == 1024
        assert j["type"] == "result"

    def test_result_with_error(self):
        """Test _Result with error message."""
        result = mobile_bridge._Result(
            success=False,
            output_file="",
            output_size=0,
            elapsed_s=0.1,
            error="Decryption failed",
        )
        j = json.loads(result.to_json())
        assert j["success"] is False
        assert j["error"] == "Decryption failed"

    def test_error_dataclass(self):
        """Test _Error serialization."""
        err = mobile_bridge._Error(code="PARSE_ERROR", message="Invalid JSON")
        j = json.loads(err.to_json())
        assert j["code"] == "PARSE_ERROR"
        assert j["message"] == "Invalid JSON"
        assert j["type"] == "error"


class TestCaptureRequest:
    """Tests for CaptureRequest."""

    def test_capture_request_defaults(self):
        """Test CaptureRequest with default values."""
        req = mobile_bridge.CaptureRequest()
        assert req.action == "capture"
        assert req.session_id  # Should be auto-generated UUID
        assert req.expected_frames == 0
        assert req.timeout_seconds == 60

    def test_capture_request_custom(self):
        """Test CaptureRequest with custom values."""
        req = mobile_bridge.CaptureRequest(expected_frames=100, timeout_seconds=120)
        assert req.expected_frames == 100
        assert req.timeout_seconds == 120

    def test_capture_request_to_json(self):
        """Test CaptureRequest JSON serialization."""
        req = mobile_bridge.CaptureRequest(expected_frames=50)
        j = json.loads(req.to_json())
        assert j["action"] == "capture"
        assert j["expected_frames"] == 50
        assert "session_id" in j

    def test_unique_session_ids(self):
        """Test that each CaptureRequest gets a unique session ID."""
        req1 = mobile_bridge.CaptureRequest()
        req2 = mobile_bridge.CaptureRequest()
        assert req1.session_id != req2.session_id


class TestWriteCaptureRequest:
    """Tests for write_capture_request function."""

    def test_write_capture_request(self, tmp_path):
        """Test writing capture request to file."""
        output = tmp_path / "request.json"
        mobile_bridge.write_capture_request(output, expected_frames=50, timeout=30)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["action"] == "capture"
        assert data["expected_frames"] == 50
        assert data["timeout_seconds"] == 30


class TestParsePhoneMessage:
    """Tests for _parse_phone_message."""

    def test_parse_frame_message(self):
        """Test parsing a frame message."""
        import base64

        raw = b"qr_data"
        msg = json.dumps(
            {
                "type": "frame",
                "seq": 5,
                "qr_bytes_b64": base64.b64encode(raw).decode(),
                "timestamp_ms": 12345,
            }
        )

        result = mobile_bridge._parse_phone_message(msg)
        assert result.seq == 5
        assert result.qr_bytes == raw

    def test_parse_non_frame_message(self):
        """Test parsing a non-frame message returns dict."""
        msg = json.dumps({"type": "scan_start", "device_id": "test-phone"})
        result = mobile_bridge._parse_phone_message(msg)
        assert isinstance(result, dict)
        assert result["type"] == "scan_start"


class TestReadFramesFromFile:
    """Tests for read_frames_from_file."""

    def test_read_array_format(self, tmp_path):
        """Test reading frames from array-of-dicts format."""
        import base64

        frames = [
            {"seq": 0, "qr_bytes_b64": base64.b64encode(b"frame0").decode()},
            {"seq": 1, "qr_bytes_b64": base64.b64encode(b"frame1").decode()},
        ]
        path = tmp_path / "frames.json"
        path.write_text(json.dumps(frames))

        result = mobile_bridge.read_frames_from_file(path)
        assert len(result) == 2
        assert result[0] == b"frame0"
        assert result[1] == b"frame1"

    def test_read_wrapped_format(self, tmp_path):
        """Test reading frames from dict-with-frames format."""
        import base64

        data = {
            "frames": [
                {"seq": 0, "qr_bytes_b64": base64.b64encode(b"data0").decode()},
            ]
        }
        path = tmp_path / "frames.json"
        path.write_text(json.dumps(data))

        result = mobile_bridge.read_frames_from_file(path)
        assert len(result) == 1
        assert result[0] == b"data0"

    def test_read_base64_strings(self, tmp_path):
        """Test reading raw base64 string array."""
        import base64

        frames = [
            base64.b64encode(b"raw0").decode(),
            base64.b64encode(b"raw1").decode(),
        ]
        path = tmp_path / "frames.json"
        path.write_text(json.dumps(frames))

        result = mobile_bridge.read_frames_from_file(path)
        assert len(result) == 2
        assert result[0] == b"raw0"

    def test_read_out_of_order(self, tmp_path):
        """Test that frames are sorted by sequence number."""
        import base64

        frames = [
            {"seq": 2, "qr_bytes_b64": base64.b64encode(b"c").decode()},
            {"seq": 0, "qr_bytes_b64": base64.b64encode(b"a").decode()},
            {"seq": 1, "qr_bytes_b64": base64.b64encode(b"b").decode()},
        ]
        path = tmp_path / "frames.json"
        path.write_text(json.dumps(frames))

        result = mobile_bridge.read_frames_from_file(path)
        assert result == [b"a", b"b", b"c"]

    def test_read_invalid_format(self, tmp_path):
        """Test that invalid format raises ValueError."""
        path = tmp_path / "bad.json"
        path.write_text('"just a string"')

        with pytest.raises(ValueError, match="Invalid frames file format"):
            mobile_bridge.read_frames_from_file(path)


class TestHandleMobileBridge:
    """Tests for handle_mobile_bridge entry point."""

    def test_output_request_mode(self, tmp_path):
        """Test capture request generation mode."""
        output_req = tmp_path / "req.json"
        args = SimpleNamespace(
            output_request=output_req,
            input_frames=None,
            bridge_mode="stdin",
            bridge_port=8765,
            password="test",
            output=tmp_path / "out.pdf",
            verbose=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            mobile_bridge.handle_mobile_bridge(args, lambda f, a: True)

        assert exc_info.value.code == 0
        assert output_req.exists()

    def test_file_input_mode(self, tmp_path):
        """Test file input mode."""
        import base64

        frames_path = tmp_path / "frames.json"
        frames = [
            {"seq": 0, "qr_bytes_b64": base64.b64encode(b"frame0").decode()},
        ]
        frames_path.write_text(json.dumps(frames))

        args = SimpleNamespace(
            output_request=None,
            input_frames=frames_path,
            bridge_mode="stdin",
            bridge_port=8765,
            password="test",
            output=tmp_path / "out.pdf",
            verbose=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            mobile_bridge.handle_mobile_bridge(args, lambda frames, a: True)

        assert exc_info.value.code == 0

    def test_file_input_not_found(self, tmp_path):
        """Test file input mode with missing file."""
        args = SimpleNamespace(
            output_request=None,
            input_frames=Path("/nonexistent/frames.json"),
            bridge_mode="stdin",
            bridge_port=8765,
            password="test",
            output=tmp_path / "out.pdf",
            verbose=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            mobile_bridge.handle_mobile_bridge(args, lambda f, a: True)

        assert exc_info.value.code == 1
