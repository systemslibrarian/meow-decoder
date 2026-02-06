"""Tests for tamper timeline visualization (MT-7)."""

import json
import pytest

from meow_decoder.tamper_report import FrameResult, TamperReport

pytestmark = [pytest.mark.security]


class TestFrameResult:
    def test_basic(self):
        r = FrameResult(index=0, valid=True, detail="ok")
        assert r.index == 0
        assert r.valid is True
        assert r.detail == "ok"


class TestTamperReportCounting:
    def test_empty(self):
        rpt = TamperReport()
        assert rpt.total_frames == 0
        assert rpt.valid_count == 0
        assert rpt.invalid_count == 0
        assert rpt.success_rate == 0.0

    def test_all_valid(self):
        rpt = TamperReport()
        for i in range(10):
            rpt.record(i, True)
        assert rpt.total_frames == 10
        assert rpt.valid_count == 10
        assert rpt.invalid_count == 0
        assert rpt.success_rate == 1.0

    def test_all_invalid(self):
        rpt = TamperReport()
        for i in range(5):
            rpt.record(i, False, "bad")
        assert rpt.total_frames == 5
        assert rpt.valid_count == 0
        assert rpt.invalid_count == 5
        assert rpt.success_rate == 0.0

    def test_mixed(self):
        rpt = TamperReport()
        rpt.record(0, True)
        rpt.record(1, False, "MAC mismatch")
        rpt.record(2, True)
        assert rpt.total_frames == 3
        assert rpt.valid_count == 2
        assert rpt.invalid_count == 1
        assert abs(rpt.success_rate - 2.0 / 3.0) < 1e-9


class TestClusterDetection:
    def test_no_clusters_when_all_valid(self):
        rpt = TamperReport()
        for i in range(20):
            rpt.record(i, True)
        clusters = rpt.detect_clusters()
        assert clusters == []

    def test_single_failure_no_cluster(self):
        rpt = TamperReport()
        for i in range(20):
            rpt.record(i, i != 10)
        clusters = rpt.detect_clusters(window=5, threshold=0.6)
        assert clusters == []  # 1/5 = 0.2, below threshold

    def test_clustered_failures_detected(self):
        rpt = TamperReport()
        for i in range(20):
            # Frames 5-9 all fail
            rpt.record(i, i < 5 or i >= 10)
        clusters = rpt.detect_clusters(window=5, threshold=0.6)
        assert len(clusters) >= 1
        # The cluster should start around frame 5
        assert clusters[0]["start"] <= 5
        assert clusters[0]["failures"] >= 3

    def test_multiple_clusters(self):
        rpt = TamperReport()
        for i in range(30):
            # Cluster 1: frames 2-6, Cluster 2: frames 20-24
            if 2 <= i <= 6 or 20 <= i <= 24:
                rpt.record(i, False)
            else:
                rpt.record(i, True)
        clusters = rpt.detect_clusters(window=5, threshold=0.6)
        assert len(clusters) >= 2

    def test_empty_report_no_clusters(self):
        rpt = TamperReport()
        clusters = rpt.detect_clusters()
        assert clusters == []


class TestAsciiTimeline:
    def test_empty_report(self):
        rpt = TamperReport()
        result = rpt.ascii_timeline()
        assert "no frames" in result.lower()

    def test_all_valid_shows_blocks(self):
        rpt = TamperReport()
        for i in range(60):
            rpt.record(i, True)
        result = rpt.ascii_timeline(width=60)
        assert "█" in result
        assert "Tamper Timeline" in result
        assert "No suspicious" in result

    def test_all_invalid_shows_light_blocks(self):
        rpt = TamperReport()
        for i in range(10):
            rpt.record(i, False, "bad")
        result = rpt.ascii_timeline(width=10)
        assert "░" in result
        assert "Failed frames" in result

    def test_mixed_shows_mixed_chars(self):
        rpt = TamperReport()
        # First half valid, second half invalid
        for i in range(20):
            rpt.record(i, i < 10)
        result = rpt.ascii_timeline(width=20)
        assert "█" in result
        assert "░" in result

    def test_cluster_warning_in_output(self):
        rpt = TamperReport()
        for i in range(20):
            rpt.record(i, i < 5 or i >= 10)
        result = rpt.ascii_timeline()
        assert "Suspicious clusters" in result or "suspicious" in result.lower()

    def test_failed_frames_capped(self):
        rpt = TamperReport()
        for i in range(50):
            rpt.record(i, False)
        result = rpt.ascii_timeline()
        assert "... and" in result  # should cap at 20


class TestJsonOutput:
    def test_json_roundtrip(self):
        rpt = TamperReport()
        rpt.record(0, True)
        rpt.record(1, False, "MAC mismatch")
        rpt.record(2, True)
        raw = rpt.to_json()
        data = json.loads(raw)
        assert data["total_frames"] == 3
        assert data["valid"] == 2
        assert data["invalid"] == 1
        assert len(data["frames"]) == 3
        assert data["frames"][1]["valid"] is False
        assert data["frames"][1]["detail"] == "MAC mismatch"

    def test_json_has_clusters(self):
        rpt = TamperReport()
        for i in range(20):
            rpt.record(i, i < 5 or i >= 10)
        raw = rpt.to_json()
        data = json.loads(raw)
        assert "clusters" in data
        assert isinstance(data["clusters"], list)
        assert len(data["clusters"]) >= 1

    def test_json_success_rate(self):
        rpt = TamperReport()
        rpt.record(0, True)
        rpt.record(1, True)
        rpt.record(2, False)
        data = json.loads(rpt.to_json())
        assert abs(data["success_rate"] - 0.6667) < 0.01
