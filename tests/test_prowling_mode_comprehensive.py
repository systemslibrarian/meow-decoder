#!/usr/bin/env python3
"""
🐾 Comprehensive tests for prowling_mode.py
Targets ~75-85% coverage for low-memory decoding paths.
"""

import os
import io
import gc
import tempfile
from pathlib import Path

import pytest

from meow_decoder.prowling_mode import (
    ProwlingConfig,
    MemoryProwler,
    DiskBasedKibbleCollector,
    create_prowling_decoder,
)


@pytest.fixture
def prowling_config(tmp_path):
    """Default prowling config with temp file."""
    return ProwlingConfig(temp_file=tmp_path / "blocks.meow", max_ram_mb=50, block_size=8)


@pytest.fixture
def collector(prowling_config):
    """Small collector for tests."""
    return DiskBasedKibbleCollector(num_posts=3, post_size=8, config=prowling_config)


class TestMemoryProwler:
    """Memory monitoring tests."""

    def test_get_current_ram_no_psutil(self, monkeypatch, prowling_config):
        monkeypatch.setattr("meow_decoder.prowling_mode.HAS_PSUTIL", False)
        prowler = MemoryProwler(prowling_config)
        assert prowler.get_current_ram_mb() is None

    def test_get_available_ram_no_psutil(self, monkeypatch, prowling_config):
        monkeypatch.setattr("meow_decoder.prowling_mode.HAS_PSUTIL", False)
        prowler = MemoryProwler(prowling_config)
        assert prowler.get_available_ram_mb() is None

    def test_check_memory_over_limit(self, monkeypatch, prowling_config, capsys):
        prowler = MemoryProwler(prowling_config)
        monkeypatch.setattr(prowler, "get_current_ram_mb", lambda: 999)
        ok = prowler.check_memory()
        assert ok is False
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_check_memory_warn_threshold(self, monkeypatch, prowling_config, capsys):
        prowler = MemoryProwler(prowling_config)
        monkeypatch.setattr(
            prowler, "get_current_ram_mb", lambda: prowling_config.warn_threshold_mb + 1
        )
        ok = prowler.check_memory()
        assert ok is True
        captured = capsys.readouterr()
        assert "approaching" in captured.out

    def test_force_gc_calls_gc(self, prowling_config, monkeypatch):
        prowler = MemoryProwler(prowling_config)
        calls = []

        def mock_gc():
            calls.append(1)
            return 0

        monkeypatch.setattr(gc, "collect", mock_gc)
        prowler.force_gc()
        assert len(calls) == 1

    def test_get_current_ram_handles_psutil_errors(self, monkeypatch, prowling_config):
        import meow_decoder.prowling_mode as pm

        class _AccessDenied(Exception):
            pass

        access_denied = getattr(getattr(pm, "psutil", None), "AccessDenied", _AccessDenied)

        class DummyProcess:
            def memory_info(self):
                raise access_denied()

        monkeypatch.setattr(pm, "HAS_PSUTIL", True)
        monkeypatch.setattr(
            pm,
            "psutil",
            type("P", (), {"Process": lambda: DummyProcess(), "AccessDenied": access_denied}),
        )
        prowler = MemoryProwler(prowling_config)
        assert prowler.get_current_ram_mb() is None

    def test_get_available_ram_handles_psutil_errors(self, monkeypatch, prowling_config):
        import meow_decoder.prowling_mode as pm

        class _Error(Exception):
            pass

        error_type = getattr(getattr(pm, "psutil", None), "Error", _Error)

        class DummyPsutil:
            Error = error_type

            def virtual_memory(self):
                raise error_type()

        monkeypatch.setattr(pm, "HAS_PSUTIL", True)
        monkeypatch.setattr(pm, "psutil", DummyPsutil())
        prowler = MemoryProwler(prowling_config)
        assert prowler.get_available_ram_mb() is None


class TestDiskBasedKibbleCollector:
    """Disk-based collector behavior tests."""

    def test_initializes_temp_file(self, collector):
        assert collector.temp_file.exists()
        size = collector.temp_file.stat().st_size
        assert size == collector.num_posts * collector.post_size

    def test_custom_temp_file_used(self, tmp_path):
        custom = tmp_path / "custom_blocks.meow"
        config = ProwlingConfig(temp_file=custom, max_ram_mb=10, block_size=8)
        collector = DiskBasedKibbleCollector(num_posts=2, post_size=8, config=config)
        assert collector.temp_file == custom
        assert custom.exists()

    def test_write_and_read_post(self, collector):
        data = b"ABCDEFGH"
        collector.write_post_to_disk(1, data)
        read_back = collector.read_post_from_disk(1)
        assert read_back == data

    def test_collect_kibble_degree_one_solves_post(self, collector):
        data = b"ABCDEFGH"
        done = collector.collect_kibble_streaming(seed=1, post_indices=[0], data=data)
        assert done is False
        assert 0 in collector.solved_posts
        assert collector.posts_found == 1

    def test_collect_kibble_reduces_known_post(self, collector):
        # Solve post 0 first
        collector.write_post_to_disk(0, b"\x01" * 8)
        data = bytes([2] * 8)
        # Kibble references solved post and unknown post -> should reduce
        done = collector.collect_kibble_streaming(seed=1, post_indices=[0, 1], data=data)
        assert done is False
        # Now solve post 1 via pending processing
        assert 1 in collector.solved_posts

    def test_collect_kibble_fully_reduced_discards(self, collector):
        collector.write_post_to_disk(0, b"\x01" * 8)
        data = b"\x01" * 8
        done = collector.collect_kibble_streaming(seed=1, post_indices=[0], data=data)
        assert done is False

    def test_pending_kibbles_cap_and_gc(self, collector, monkeypatch):
        collector.pending_kibbles = [([0, 1], b"x" * 8) for _ in range(1000)]
        gc_calls = []

        monkeypatch.setattr(collector.prowler, "force_gc", lambda: gc_calls.append(1))
        collector.collect_kibble_streaming(seed=2, post_indices=[1, 2], data=b"y" * 8)
        assert len(collector.pending_kibbles) == 1000

        # Trigger periodic GC when length % 100 == 0
        collector.pending_kibbles = [([0, 1], b"z" * 8) for _ in range(99)]
        collector.collect_kibble_streaming(seed=3, post_indices=[1, 2], data=b"y" * 8)
        assert gc_calls

    def test_pending_kibbles_processed(self, collector):
        # Add a pending kibble that can be solved after post 0 is found
        data = b"\x05" * 8
        collector.pending_kibbles.append(([0], data))
        collector.write_post_to_disk(0, data)
        collector._process_pending_streaming()
        assert 0 in collector.solved_posts

    def test_get_reconstructed_data_requires_complete(self, collector):
        with pytest.raises(RuntimeError):
            collector.get_reconstructed_data(original_length=8)

    def test_get_reconstructed_data_cleans_temp(self, collector):
        # Solve all posts
        collector.write_post_to_disk(0, b"A" * 8)
        collector.write_post_to_disk(1, b"B" * 8)
        collector.write_post_to_disk(2, b"C" * 8)
        assert collector.is_satisfied() is True
        data = collector.get_reconstructed_data(original_length=24)
        assert data == b"A" * 8 + b"B" * 8 + b"C" * 8
        assert not collector.temp_file.exists()

    def test_get_reconstructed_data_handles_cleanup_errors(self, collector, monkeypatch):
        collector.write_post_to_disk(0, b"A" * 8)
        collector.write_post_to_disk(1, b"B" * 8)
        collector.write_post_to_disk(2, b"C" * 8)
        monkeypatch.setattr(
            collector.temp_file, "unlink", lambda: (_ for _ in ()).throw(OSError("fail"))
        )
        data = collector.get_reconstructed_data(original_length=24)
        assert data.startswith(b"A" * 8)

    def test_get_stats_fields(self, collector, monkeypatch):
        monkeypatch.setattr(collector.prowler, "get_current_ram_mb", lambda: 42)
        stats = collector.get_stats()
        assert stats["current_ram_mb"] == 42
        assert stats["total_posts"] == collector.num_posts


class TestProwlingFactory:
    """Factory tests."""

    def test_create_prowling_decoder(self, capsys):
        decoder = create_prowling_decoder(num_posts=2, post_size=8, max_ram_mb=64)
        assert isinstance(decoder, DiskBasedKibbleCollector)
        captured = capsys.readouterr()
        assert "Prowling Mode Activated" in captured.out

    def test_create_prowling_decoder_caps_block_size(self):
        decoder = create_prowling_decoder(num_posts=2, post_size=1024, max_ram_mb=64)
        assert decoder.config.block_size == 256
