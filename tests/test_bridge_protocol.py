"""Tests for the mobile bridge wire protocol (MT-8)."""

import json
import pytest
import sys
import os

# mobile/bridge is not a package under meow_decoder, so add it to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mobile"))

from bridge.protocol import (
    ScanStart,
    Frame,
    ScanEnd,
    Ack,
    Progress,
    Result,
    Error,
    parse_phone_message,
    parse_cli_message,
    MAX_FRAME_BYTES,
)


class TestPhoneMessages:
    def test_scan_start(self):
        msg = ScanStart(device_id="test-phone")
        assert msg.type == "scan_start"
        assert msg.device_id == "test-phone"
        assert msg.timestamp_ms > 0
        data = json.loads(msg.to_json())
        assert data["type"] == "scan_start"

    def test_frame_from_raw(self):
        raw = b"\x00\x01\x02\x03"
        f = Frame.from_raw(seq=5, qr_bytes=raw)
        assert f.type == "frame"
        assert f.seq == 5
        assert f.qr_bytes == raw
        data = json.loads(f.to_json())
        assert data["seq"] == 5

    def test_frame_roundtrip_bytes(self):
        raw = b"hello meow" * 10
        f = Frame.from_raw(seq=0, qr_bytes=raw)
        assert f.qr_bytes == raw

    def test_scan_end(self):
        msg = ScanEnd(total_frames_sent=42)
        assert msg.type == "scan_end"
        assert msg.total_frames_sent == 42
        data = json.loads(msg.to_json())
        assert data["total_frames_sent"] == 42


class TestCLIMessages:
    def test_ack(self):
        msg = Ack(seq=3, accepted=True)
        data = json.loads(msg.to_json())
        assert data["type"] == "ack"
        assert data["accepted"] is True

    def test_ack_rejected(self):
        msg = Ack(seq=7, accepted=False, reason="too large")
        data = json.loads(msg.to_json())
        assert data["accepted"] is False
        assert data["reason"] == "too large"

    def test_progress(self):
        msg = Progress(
            frames_received=20,
            frames_needed=30,
            blocks_decoded=10,
            blocks_total=20,
            percent=50.0,
        )
        data = json.loads(msg.to_json())
        assert data["percent"] == 50.0

    def test_result_success(self):
        msg = Result(
            success=True,
            output_file="secret.pdf",
            output_size=1024,
            elapsed_s=2.5,
        )
        data = json.loads(msg.to_json())
        assert data["success"] is True
        assert data["error"] is None

    def test_result_failure(self):
        msg = Result(success=False, error="Wrong password")
        data = json.loads(msg.to_json())
        assert data["success"] is False
        assert data["error"] == "Wrong password"

    def test_error(self):
        msg = Error(code="HMAC_FAIL", message="bad password")
        data = json.loads(msg.to_json())
        assert data["type"] == "error"
        assert data["code"] == "HMAC_FAIL"


class TestParsing:
    def test_parse_scan_start(self):
        raw = json.dumps({"type": "scan_start", "device_id": "phone1", "timestamp_ms": 100})
        msg = parse_phone_message(raw)
        assert isinstance(msg, ScanStart)
        assert msg.device_id == "phone1"

    def test_parse_frame(self):
        import base64
        payload = base64.b64encode(b"qr data").decode()
        raw = json.dumps({"type": "frame", "seq": 0, "qr_bytes_b64": payload, "timestamp_ms": 100})
        msg = parse_phone_message(raw)
        assert isinstance(msg, Frame)
        assert msg.qr_bytes == b"qr data"

    def test_parse_scan_end(self):
        raw = json.dumps({"type": "scan_end", "total_frames_sent": 10, "timestamp_ms": 200})
        msg = parse_phone_message(raw)
        assert isinstance(msg, ScanEnd)
        assert msg.total_frames_sent == 10

    def test_parse_unknown_phone_type(self):
        raw = json.dumps({"type": "unknown"})
        with pytest.raises(ValueError, match="Unknown phone message"):
            parse_phone_message(raw)

    def test_parse_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_phone_message("not json{")

    def test_parse_ack(self):
        raw = json.dumps({"type": "ack", "seq": 1, "accepted": True, "reason": ""})
        msg = parse_cli_message(raw)
        assert isinstance(msg, Ack)

    def test_parse_progress(self):
        raw = json.dumps({
            "type": "progress",
            "frames_received": 5,
            "frames_needed": 10,
            "blocks_decoded": 3,
            "blocks_total": 7,
            "percent": 42.9,
        })
        msg = parse_cli_message(raw)
        assert isinstance(msg, Progress)
        assert msg.percent == 42.9

    def test_parse_result(self):
        raw = json.dumps({
            "type": "result",
            "success": True,
            "output_file": "out.pdf",
            "output_size": 500,
            "elapsed_s": 1.0,
            "error": None,
        })
        msg = parse_cli_message(raw)
        assert isinstance(msg, Result)
        assert msg.success is True

    def test_parse_error(self):
        raw = json.dumps({"type": "error", "code": "INTERNAL", "message": "oops"})
        msg = parse_cli_message(raw)
        assert isinstance(msg, Error)
        assert msg.code == "INTERNAL"

    def test_parse_unknown_cli_type(self):
        with pytest.raises(ValueError, match="Unknown CLI message"):
            parse_cli_message(json.dumps({"type": "nope"}))


class TestConstants:
    def test_max_frame_bytes(self):
        assert MAX_FRAME_BYTES == 4096
