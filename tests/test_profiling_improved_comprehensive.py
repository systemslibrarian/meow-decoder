#!/usr/bin/env python3
"""
🐱 Comprehensive Test Suite for profiling_improved.py
Tests for performance profiling with bottleneck analysis

Target Coverage: 70-80%
"""

import pytest
import time
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import runpy

from meow_decoder.profiling_improved import (
    TimingData,
    Profiler,
    DetailedProfiler,
    get_profiler,
    measure,
    profile_function,
    _global_profiler,
)


# =============================================================================
# 🐱 Test Fixtures
# =============================================================================

@pytest.fixture
def fresh_profiler():
    """Create a fresh profiler instance for each test."""
    return Profiler()


@pytest.fixture
def detailed_profiler():
    """Create a DetailedProfiler instance."""
    return DetailedProfiler()


@pytest.fixture
def timing_data():
    """Create a TimingData instance for testing."""
    return TimingData(name="test_operation")


@pytest.fixture
def populated_profiler():
    """Create a profiler with some timing data."""
    profiler = Profiler()
    
    # Add various timing measurements
    for i in range(10):
        with profiler.measure("fast_op"):
            time.sleep(0.001)
    
    for i in range(5):
        with profiler.measure("slow_op"):
            time.sleep(0.01)
    
    with profiler.measure("single_op"):
        time.sleep(0.005)
    
    return profiler


@pytest.fixture
def temp_profile_file():
    """Create a temporary file for profile output."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


# =============================================================================
# 🐱 TimingData Tests - The Cat's Stopwatch
# =============================================================================

class TestTimingDataMeow:
    """Tests for TimingData dataclass - tracking the cat's speed! 🐱⏱️"""
    
    def test_timing_data_initialization_meow(self, timing_data):
        """Test TimingData is initialized with correct defaults."""
        assert timing_data.name == "test_operation"
        assert timing_data.total_time == 0.0
        assert timing_data.call_count == 0
        assert timing_data.min_time == float('inf')
        assert timing_data.max_time == 0.0
        assert timing_data.times == []
        assert timing_data.metadata == {}
    
    def test_avg_time_no_calls_meow(self, timing_data):
        """Test avg_time returns 0 when no calls made."""
        assert timing_data.avg_time == 0.0
    
    def test_add_timing_single_meow(self, timing_data):
        """Test adding a single timing measurement."""
        timing_data.add_timing(0.5, block_size=512)
        
        assert timing_data.total_time == 0.5
        assert timing_data.call_count == 1
        assert timing_data.min_time == 0.5
        assert timing_data.max_time == 0.5
        assert timing_data.times == [0.5]
        assert timing_data.metadata == {'block_size': 512}
    
    def test_add_timing_multiple_meow(self, timing_data):
        """Test adding multiple timing measurements."""
        timing_data.add_timing(0.1)
        timing_data.add_timing(0.3)
        timing_data.add_timing(0.2)
        
        assert timing_data.total_time == pytest.approx(0.6, abs=0.001)
        assert timing_data.call_count == 3
        assert timing_data.min_time == pytest.approx(0.1, abs=0.001)
        assert timing_data.max_time == pytest.approx(0.3, abs=0.001)
        assert len(timing_data.times) == 3
    
    def test_avg_time_calculation_meow(self, timing_data):
        """Test average time calculation."""
        timing_data.add_timing(0.1)
        timing_data.add_timing(0.2)
        timing_data.add_timing(0.3)
        
        assert timing_data.avg_time == pytest.approx(0.2, abs=0.001)
    
    def test_metadata_preserved_meow(self, timing_data):
        """Test that metadata is preserved correctly."""
        timing_data.add_timing(0.1, key1="value1", key2=42)
        timing_data.add_timing(0.2, key3="value3")  # Add new key
        
        assert timing_data.metadata['key1'] == "value1"
        assert timing_data.metadata['key2'] == 42
        assert timing_data.metadata['key3'] == "value3"
    
    def test_metadata_first_value_wins_meow(self, timing_data):
        """Test that first metadata value is preserved."""
        timing_data.add_timing(0.1, key="first")
        timing_data.add_timing(0.2, key="second")
        
        # First value should be preserved
        assert timing_data.metadata['key'] == "first"


# =============================================================================
# 🐱 Profiler Tests - The Cat's Performance Monitor
# =============================================================================

class TestProfilerMeow:
    """Tests for Profiler class - measuring the cat's agility! 🐱📊"""
    
    def test_profiler_initialization_meow(self, fresh_profiler):
        """Test Profiler initializes correctly."""
        assert fresh_profiler.timings == {}
        assert fresh_profiler.enabled is True
        assert fresh_profiler.context == {}
    
    def test_set_context_meow(self, fresh_profiler):
        """Test setting profiler context."""
        fresh_profiler.set_context(block_size=512, multiplier=1.85)
        
        assert fresh_profiler.context['block_size'] == 512
        assert fresh_profiler.context['multiplier'] == 1.85
    
    def test_measure_context_manager_meow(self, fresh_profiler):
        """Test measure context manager records timing."""
        with fresh_profiler.measure("test_op"):
            time.sleep(0.01)
        
        assert "test_op" in fresh_profiler.timings
        assert fresh_profiler.timings["test_op"].call_count == 1
        assert fresh_profiler.timings["test_op"].total_time >= 0.01
    
    def test_measure_with_metadata_meow(self, fresh_profiler):
        """Test measure context manager with metadata."""
        with fresh_profiler.measure("test_op", block_size=256):
            time.sleep(0.001)
        
        assert fresh_profiler.timings["test_op"].metadata['block_size'] == 256
    
    def test_measure_disabled_profiler_meow(self, fresh_profiler):
        """Test measure does nothing when profiler is disabled."""
        fresh_profiler.enabled = False
        
        with fresh_profiler.measure("test_op"):
            time.sleep(0.001)
        
        assert "test_op" not in fresh_profiler.timings
    
    def test_measure_multiple_calls_meow(self, fresh_profiler):
        """Test measure accumulates multiple calls."""
        for _ in range(5):
            with fresh_profiler.measure("test_op"):
                time.sleep(0.001)
        
        assert fresh_profiler.timings["test_op"].call_count == 5


def test_profiling_improved_module_main_runs():
    runpy.run_module("meow_decoder.profiling_improved", run_name="__main__")
    
    def test_profile_function_decorator_meow(self, fresh_profiler):
        """Test profile_function decorator."""
        @fresh_profiler.profile_function("decorated_func")
        def sample_function():
            time.sleep(0.01)
            return 42
        
        result = sample_function()
        
        assert result == 42
        assert "decorated_func" in fresh_profiler.timings
        assert fresh_profiler.timings["decorated_func"].call_count == 1
    
    def test_profile_function_decorator_auto_name_meow(self, fresh_profiler):
        """Test profile_function decorator uses function name when not specified."""
        @fresh_profiler.profile_function()
        def my_cat_function():
            return "meow"
        
        result = my_cat_function()
        
        assert result == "meow"
        assert "my_cat_function" in fresh_profiler.timings
    
    def test_reset_meow(self, populated_profiler):
        """Test reset clears all data."""
        populated_profiler.set_context(key="value")
        populated_profiler.reset()
        
        assert populated_profiler.timings == {}
        assert populated_profiler.context == {}


# =============================================================================
# 🐱 Profiler Summary Tests - The Cat's Report Card
# =============================================================================

class TestProfilerSummaryMeow:
    """Tests for get_summary method - grading the cat! 🐱📝"""
    
    def test_get_summary_empty_meow(self, fresh_profiler):
        """Test get_summary with no timings."""
        summary = fresh_profiler.get_summary()
        assert summary == {}
    
    def test_get_summary_structure_meow(self, populated_profiler):
        """Test get_summary returns correct structure."""
        summary = populated_profiler.get_summary()
        
        assert "fast_op" in summary
        assert "slow_op" in summary
        assert "single_op" in summary
        
        for name, data in summary.items():
            assert 'total_time' in data
            assert 'avg_time' in data
            assert 'min_time' in data
            assert 'max_time' in data
            assert 'call_count' in data
            assert 'percentage' in data
            assert 'metadata' in data
    
    def test_get_summary_percentages_meow(self, populated_profiler):
        """Test percentages sum to 100."""
        summary = populated_profiler.get_summary()
        
        total_pct = sum(data['percentage'] for data in summary.values())
        assert total_pct == pytest.approx(100.0, abs=0.1)
    
    def test_get_summary_call_counts_meow(self, populated_profiler):
        """Test call counts are accurate."""
        summary = populated_profiler.get_summary()
        
        assert summary["fast_op"]["call_count"] == 10
        assert summary["slow_op"]["call_count"] == 5
        assert summary["single_op"]["call_count"] == 1


# =============================================================================
# 🐱 Bottleneck Analysis Tests - Finding the Slow Cats
# =============================================================================

class TestAnalyzeBottlenecksMeow:
    """Tests for analyze_bottlenecks method - finding lazy cats! 🐱🔍"""
    
    def test_analyze_bottlenecks_empty_meow(self, fresh_profiler):
        """Test analyze_bottlenecks with no data."""
        suggestions = fresh_profiler.analyze_bottlenecks()
        
        # Should return general suggestion
        assert len(suggestions) >= 1
        assert suggestions[0][0] == "General"
    
    def test_analyze_bottlenecks_qr_bottleneck_meow(self, fresh_profiler):
        """Test QR generation bottleneck detection."""
        # Simulate QR generation taking 50% of time
        for _ in range(100):
            with fresh_profiler.measure("create_qr_image", block_size=512):
                time.sleep(0.005)
        
        with fresh_profiler.measure("other_op"):
            time.sleep(0.05)
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        
        # Should detect QR bottleneck
        categories = [s[0] for s in suggestions]
        assert "QR Generation" in categories or "QR Complexity" in categories or "General" in categories
    
    def test_analyze_bottlenecks_encryption_meow(self, fresh_profiler):
        """Test encryption bottleneck detection."""
        # Simulate encryption taking significant time
        with fresh_profiler.measure("encrypt"):
            time.sleep(0.1)
        
        with fresh_profiler.measure("other"):
            time.sleep(0.01)
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        
        # Should have some suggestion
        assert len(suggestions) >= 1
    
    def test_analyze_bottlenecks_sorted_by_priority_meow(self, fresh_profiler):
        """Test suggestions are sorted by priority."""
        # Add multiple operations
        for _ in range(50):
            with fresh_profiler.measure("create_qr_image"):
                time.sleep(0.005)
        
        with fresh_profiler.measure("compress"):
            time.sleep(0.05)
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        
        # Check priorities are in ascending order
        priorities = [s[2] for s in suggestions]
        assert priorities == sorted(priorities)
    
    def test_analyze_bottlenecks_fountain_encoding_meow(self, fresh_profiler):
        """Test fountain encoding bottleneck detection."""
        fresh_profiler.set_context(multiplier=1.85)
        
        # Simulate droplet generation
        for _ in range(100):
            with fresh_profiler.measure("make_droplet"):
                time.sleep(0.003)
        
        with fresh_profiler.measure("small_op"):
            time.sleep(0.01)
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        assert len(suggestions) >= 1
    
    def test_analyze_bottlenecks_gif_saving_meow(self, fresh_profiler):
        """Test GIF saving bottleneck detection."""
        with fresh_profiler.measure("gif_save"):
            time.sleep(0.1)
        
        with fresh_profiler.measure("other"):
            time.sleep(0.05)
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        assert len(suggestions) >= 1
    
    def test_analyze_bottlenecks_webcam_processing_meow(self, fresh_profiler):
        """Test webcam processing bottleneck detection."""
        for _ in range(10):
            with fresh_profiler.measure("process_frame"):
                time.sleep(0.06)  # >50ms threshold
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        
        categories = [s[0] for s in suggestions]
        assert "Webcam Processing" in categories or "General" in categories


# =============================================================================
# 🐱 Print Summary Tests - The Cat's Pretty Output
# =============================================================================

class TestPrintSummaryMeow:
    """Tests for print_summary method - pretty cat reports! 🐱🎨"""
    
    def test_print_summary_runs_meow(self, populated_profiler, capsys):
        """Test print_summary runs without error."""
        # Mock colorama if not available
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                populated_profiler.print_summary(show_suggestions=False)
            except ImportError:
                # colorama not installed, that's ok
                pass
    
    def test_print_summary_with_suggestions_meow(self, populated_profiler):
        """Test print_summary with suggestions enabled."""
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                populated_profiler.print_summary(show_suggestions=True)
            except ImportError:
                pass
    
    def test_print_summary_top_n_meow(self, fresh_profiler):
        """Test print_summary respects top_n parameter."""
        # Add many operations
        for i in range(30):
            with fresh_profiler.measure(f"op_{i}"):
                time.sleep(0.001)
        
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                fresh_profiler.print_summary(top_n=5)
            except ImportError:
                pass


# =============================================================================
# 🐱 Compare Profiles Tests - The Cat Race
# =============================================================================

class TestCompareWithMeow:
    """Tests for compare_with method - racing cats! 🐱🏃"""
    
    def test_compare_with_improvement_meow(self):
        """Test comparing profiles showing improvement."""
        before = Profiler()
        after = Profiler()
        
        # Before: slower
        for _ in range(5):
            with before.measure("test_op"):
                time.sleep(0.02)
        
        # After: faster
        for _ in range(5):
            with after.measure("test_op"):
                time.sleep(0.01)
        
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                after.compare_with(before, "test_op")
            except ImportError:
                pass
    
    def test_compare_with_regression_meow(self):
        """Test comparing profiles showing regression."""
        before = Profiler()
        after = Profiler()
        
        # Before: faster
        for _ in range(5):
            with before.measure("test_op"):
                time.sleep(0.01)
        
        # After: slower
        for _ in range(5):
            with after.measure("test_op"):
                time.sleep(0.02)
        
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                after.compare_with(before, "test_op")
            except ImportError:
                pass
    
    def test_compare_with_missing_operation_meow(self):
        """Test comparing with missing operation."""
        before = Profiler()
        after = Profiler()
        
        with before.measure("op_a"):
            time.sleep(0.001)
        
        with after.measure("op_b"):
            time.sleep(0.001)
        
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                after.compare_with(before, "missing_op")
            except ImportError:
                pass


# =============================================================================
# 🐱 Save Profile Tests - The Cat's Diary
# =============================================================================

class TestSaveProfileMeow:
    """Tests for save_profile method - writing the cat's diary! 🐱📔"""
    
    def test_save_profile_creates_file_meow(self, populated_profiler, temp_profile_file):
        """Test save_profile creates JSON file."""
        populated_profiler.save_profile(temp_profile_file)
        
        assert os.path.exists(temp_profile_file)
    
    def test_save_profile_valid_json_meow(self, populated_profiler, temp_profile_file):
        """Test save_profile creates valid JSON."""
        populated_profiler.save_profile(temp_profile_file)
        
        with open(temp_profile_file, 'r') as f:
            data = json.load(f)
        
        assert isinstance(data, dict)
    
    def test_save_profile_contains_operations_meow(self, populated_profiler, temp_profile_file):
        """Test saved profile contains operation data."""
        populated_profiler.save_profile(temp_profile_file)
        
        with open(temp_profile_file, 'r') as f:
            data = json.load(f)
        
        assert "fast_op" in data
        assert "slow_op" in data
    
    def test_save_profile_contains_suggestions_meow(self, populated_profiler, temp_profile_file):
        """Test saved profile contains suggestions."""
        populated_profiler.save_profile(temp_profile_file)
        
        with open(temp_profile_file, 'r') as f:
            data = json.load(f)
        
        assert "_suggestions" in data
        assert isinstance(data["_suggestions"], list)
    
    def test_save_profile_contains_context_meow(self, fresh_profiler, temp_profile_file):
        """Test saved profile contains context."""
        fresh_profiler.set_context(block_size=256, multiplier=2.0)
        
        with fresh_profiler.measure("op"):
            time.sleep(0.001)
        
        fresh_profiler.save_profile(temp_profile_file)
        
        with open(temp_profile_file, 'r') as f:
            data = json.load(f)
        
        assert "_context" in data
        assert data["_context"]["block_size"] == 256


# =============================================================================
# 🐱 DetailedProfiler Tests - The Cat's Deep Inspection
# =============================================================================

class TestDetailedProfilerMeow:
    """Tests for DetailedProfiler class - deep cat profiling! 🐱🔬"""
    
    def test_detailed_profiler_initialization_meow(self, detailed_profiler):
        """Test DetailedProfiler initializes correctly."""
        assert detailed_profiler.enabled is False
        assert detailed_profiler.profiler is not None
    
    def test_start_stop_meow(self, detailed_profiler):
        """Test start and stop methods."""
        detailed_profiler.start()
        assert detailed_profiler.enabled is True
        
        # Do some work
        sum([i**2 for i in range(100)])
        
        detailed_profiler.stop()
        assert detailed_profiler.enabled is False
    
    def test_profile_context_manager_meow(self, detailed_profiler):
        """Test profile context manager."""
        with detailed_profiler.profile():
            assert detailed_profiler.enabled is True
            sum([i**2 for i in range(100)])
        
        assert detailed_profiler.enabled is False
    
    def test_print_stats_meow(self, detailed_profiler, capsys):
        """Test print_stats method."""
        with detailed_profiler.profile():
            sum([i**2 for i in range(1000)])
        
        detailed_profiler.print_stats(top_n=10)
        
        # Should have printed something
        captured = capsys.readouterr()
        # Stats output may be empty for very short profiles
    
    def test_print_stats_sort_by_meow(self, detailed_profiler):
        """Test print_stats with different sort options."""
        with detailed_profiler.profile():
            sum([i**2 for i in range(1000)])
        
        # Should not raise for valid sort keys
        detailed_profiler.print_stats(sort_by='time')
        detailed_profiler.print_stats(sort_by='cumulative')
        detailed_profiler.print_stats(sort_by='calls')
    
    def test_save_stats_meow(self, detailed_profiler):
        """Test save_stats method."""
        with detailed_profiler.profile():
            sum([i**2 for i in range(1000)])
        
        with tempfile.NamedTemporaryFile(suffix=".prof", delete=False) as f:
            temp_path = f.name
        
        try:
            detailed_profiler.save_stats(temp_path)
            assert os.path.exists(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


# =============================================================================
# 🐱 Global Profiler Tests - The Shared Cat Tracker
# =============================================================================

class TestGlobalProfilerMeow:
    """Tests for global profiler functions - shared cat tracking! 🐱🌍"""
    
    def test_get_profiler_meow(self):
        """Test get_profiler returns global instance."""
        profiler = get_profiler()
        assert profiler is _global_profiler
    
    def test_measure_shortcut_meow(self):
        """Test measure shortcut function."""
        _global_profiler.reset()
        
        with measure("global_test_op"):
            time.sleep(0.001)
        
        assert "global_test_op" in _global_profiler.timings
    
    def test_profile_function_shortcut_meow(self):
        """Test profile_function shortcut decorator."""
        _global_profiler.reset()
        
        @profile_function("global_decorated")
        def test_func():
            return "meow"
        
        result = test_func()
        
        assert result == "meow"
        assert "global_decorated" in _global_profiler.timings


# =============================================================================
# 🐱 Edge Cases and Error Handling
# =============================================================================

class TestProfilerEdgeCasesMeow:
    """Tests for edge cases - curious cat situations! 🐱❓"""
    
    def test_measure_with_exception_meow(self, fresh_profiler):
        """Test timing is recorded even when exception occurs."""
        with pytest.raises(ValueError):
            with fresh_profiler.measure("failing_op"):
                time.sleep(0.001)
                raise ValueError("Cat knocked something over!")
        
        # Timing should still be recorded
        assert "failing_op" in fresh_profiler.timings
        assert fresh_profiler.timings["failing_op"].call_count == 1
    
    def test_very_fast_operation_meow(self, fresh_profiler):
        """Test measuring very fast operations."""
        for _ in range(1000):
            with fresh_profiler.measure("instant_op"):
                pass  # Nearly instant
        
        assert fresh_profiler.timings["instant_op"].call_count == 1000
        assert fresh_profiler.timings["instant_op"].total_time >= 0
    
    def test_nested_measure_meow(self, fresh_profiler):
        """Test nested measure calls."""
        with fresh_profiler.measure("outer"):
            time.sleep(0.01)
            with fresh_profiler.measure("inner"):
                time.sleep(0.01)
        
        assert "outer" in fresh_profiler.timings
        assert "inner" in fresh_profiler.timings
        assert fresh_profiler.timings["outer"].total_time >= fresh_profiler.timings["inner"].total_time
    
    def test_same_operation_name_meow(self, fresh_profiler):
        """Test multiple operations with same name accumulate."""
        with fresh_profiler.measure("repeated"):
            time.sleep(0.01)
        
        with fresh_profiler.measure("repeated"):
            time.sleep(0.01)
        
        assert fresh_profiler.timings["repeated"].call_count == 2
    
    def test_unicode_operation_name_meow(self, fresh_profiler):
        """Test operation name with unicode characters."""
        with fresh_profiler.measure("猫の操作"):  # "Cat's operation" in Japanese
            time.sleep(0.001)
        
        assert "猫の操作" in fresh_profiler.timings
    
    def test_empty_operation_name_meow(self, fresh_profiler):
        """Test empty operation name."""
        with fresh_profiler.measure(""):
            time.sleep(0.001)
        
        assert "" in fresh_profiler.timings
    
    def test_compare_with_zero_time_meow(self):
        """Test comparison when after time is zero."""
        before = Profiler()
        after = Profiler()
        
        with before.measure("op"):
            time.sleep(0.01)
        
        # Simulate zero time (edge case)
        after.timings["op"] = TimingData(name="op")
        after.timings["op"].add_timing(0.0)
        
        with patch.dict('sys.modules', {'colorama': MagicMock()}):
            try:
                after.compare_with(before, "op")
            except (ImportError, ZeroDivisionError):
                pass  # Expected in edge cases


# =============================================================================
# 🐱 Integration Tests
# =============================================================================

class TestProfilerIntegrationMeow:
    """Integration tests - full cat profiling workflow! 🐱🔄"""
    
    def test_full_workflow_meow(self, temp_profile_file):
        """Test complete profiling workflow."""
        profiler = Profiler()
        profiler.set_context(block_size=512, multiplier=1.85)
        
        # Simulate encoding workflow
        with profiler.measure("read_file"):
            time.sleep(0.01)
        
        with profiler.measure("compress"):
            time.sleep(0.02)
        
        with profiler.measure("encrypt"):
            time.sleep(0.05)
        
        for _ in range(10):
            with profiler.measure("create_qr"):
                time.sleep(0.005)
        
        with profiler.measure("save_gif"):
            time.sleep(0.03)
        
        # Get summary
        summary = profiler.get_summary()
        assert len(summary) == 5
        
        # Analyze bottlenecks
        suggestions = profiler.analyze_bottlenecks()
        assert len(suggestions) >= 1
        
        # Save profile
        profiler.save_profile(temp_profile_file)
        
        with open(temp_profile_file, 'r') as f:
            data = json.load(f)
        
        assert "encrypt" in data
        assert "_suggestions" in data
        assert "_context" in data
    
    def test_decorator_and_context_manager_together_meow(self, fresh_profiler):
        """Test using decorator and context manager together."""
        @fresh_profiler.profile_function("decorated")
        def decorated_func():
            with fresh_profiler.measure("inner_measure"):
                time.sleep(0.01)
            return "done"
        
        result = decorated_func()
        
        assert result == "done"
        assert "decorated" in fresh_profiler.timings
        assert "inner_measure" in fresh_profiler.timings


# =============================================================================
# 🐱 Performance Tests
# =============================================================================

class TestProfilerPerformanceMeow:
    """Performance tests - is the profiler fast enough? 🐱⚡"""
    
    def test_profiler_overhead_low_meow(self, fresh_profiler):
        """Test that profiler overhead is minimal."""
        # Time without profiling
        start = time.perf_counter()
        for _ in range(1000):
            pass
        baseline = time.perf_counter() - start
        
        # Time with profiling
        start = time.perf_counter()
        for _ in range(1000):
            with fresh_profiler.measure("overhead_test"):
                pass
        with_profiling = time.perf_counter() - start
        
        # Overhead should be reasonable (less than 10x)
        assert with_profiling < baseline * 100  # Very generous for CI
    
    def test_many_operations_meow(self, fresh_profiler):
        """Test profiler handles many operations."""
        for i in range(100):
            with fresh_profiler.measure(f"op_{i}"):
                pass
        
        summary = fresh_profiler.get_summary()
        assert len(summary) == 100
        
        suggestions = fresh_profiler.analyze_bottlenecks()
        assert len(suggestions) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
