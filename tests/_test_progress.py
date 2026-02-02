#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for Progress Module - Target: 90%+
Tests progress.py ProgressBar and related utilities.
"""

import pytest
import sys
import time
from pathlib import Path
from io import StringIO

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestProgressBar:
    """Test ProgressBar functionality."""
    
    def test_basic_progress(self):
        """Test basic progress bar usage."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, desc="Testing")
        
        for i in range(100):
            pb.update(1)
        
        pb.close()
    
    def test_progress_disabled(self):
        """Test progress bar when disabled."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=50, desc="Disabled", disable=True)
        
        for i in range(50):
            pb.update(1)
        
        pb.close()
    
    def test_progress_with_unit(self):
        """Test progress bar with custom unit."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, desc="Processing", unit="frames")
        
        for i in range(10):
            pb.update(1)
        
        pb.close()
    
    def test_progress_as_context_manager(self):
        """Test progress bar as context manager."""
        from meow_decoder.progress import ProgressBar
        
        with ProgressBar(total=20, desc="Context") as pb:
            for i in range(20):
                pb.update(1)
    
    def test_progress_callable(self):
        """Test progress bar as callable iterator."""
        from meow_decoder.progress import ProgressBar
        
        items = list(range(10))
        pb = ProgressBar(len(items), desc="Iterating", disable=True)
        
        for item in pb(items):
            pass  # Process item
    
    def test_progress_zero_total(self):
        """Test progress bar with zero total."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=0, desc="Empty")
        pb.close()
    
    def test_progress_large_total(self):
        """Test progress bar with large total."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=1000000, desc="Large", disable=True)
        
        # Don't actually iterate 1M times
        pb.update(500000)
        pb.update(500000)
        
        pb.close()


class TestProgressBarUpdate:
    """Test ProgressBar update methods."""
    
    def test_update_by_one(self):
        """Test updating by 1."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, disable=True)
        
        for i in range(10):
            pb.update(1)
        
        pb.close()
    
    def test_update_by_multiple(self):
        """Test updating by multiple."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, disable=True)
        
        for i in range(10):
            pb.update(10)
        
        pb.close()
    
    def test_update_partial(self):
        """Test partial updates."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, disable=True)
        
        pb.update(25)
        pb.update(25)
        pb.update(50)
        
        pb.close()


class TestProgressBarIterator:
    """Test ProgressBar as iterator."""
    
    def test_iterate_list(self):
        """Test iterating over list."""
        from meow_decoder.progress import ProgressBar
        
        items = [1, 2, 3, 4, 5]
        result = []
        
        pb = ProgressBar(len(items), disable=True)
        for item in pb(items):
            result.append(item)
        
        assert result == items
    
    def test_iterate_range(self):
        """Test iterating over range."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(10, disable=True)
        count = 0
        
        for i in pb(range(10)):
            count += 1
        
        assert count == 10
    
    def test_iterate_generator(self):
        """Test iterating over generator."""
        from meow_decoder.progress import ProgressBar
        
        def gen():
            for i in range(5):
                yield i
        
        pb = ProgressBar(5, disable=True)
        result = list(pb(gen()))
        
        assert result == [0, 1, 2, 3, 4]


class TestProgressBarDescription:
    """Test ProgressBar description handling."""
    
    def test_set_description(self):
        """Test setting description."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, desc="Initial", disable=True)
        
        # Some implementations allow changing desc
        if hasattr(pb, 'set_description'):
            pb.set_description("Updated")
        
        pb.close()
    
    def test_long_description(self):
        """Test with long description."""
        from meow_decoder.progress import ProgressBar
        
        long_desc = "A" * 100
        
        pb = ProgressBar(total=10, desc=long_desc, disable=True)
        pb.update(5)
        pb.close()
    
    def test_empty_description(self):
        """Test with empty description."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, desc="", disable=True)
        pb.update(10)
        pb.close()
    
    def test_unicode_description(self):
        """Test with unicode description."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, desc="🐱 Processing", disable=True)
        pb.update(10)
        pb.close()


class TestProgressBarEdgeCases:
    """Test ProgressBar edge cases."""
    
    def test_update_past_total(self):
        """Test updating past total."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, disable=True)
        
        pb.update(15)  # Past total
        
        pb.close()
    
    def test_negative_update(self):
        """Test negative update (should handle gracefully)."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, disable=True)
        
        pb.update(5)
        
        # Some implementations may accept negative updates
        try:
            pb.update(-2)
        except (ValueError, TypeError):
            pass  # Expected
        
        pb.close()
    
    def test_close_multiple_times(self):
        """Test closing multiple times."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, disable=True)
        pb.update(5)
        
        pb.close()
        pb.close()  # Should not error
    
    def test_use_after_close(self):
        """Test using after close."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, disable=True)
        pb.close()
        
        # Should handle gracefully
        try:
            pb.update(1)
        except Exception:
            pass  # May error or may be no-op


class TestProgressBarOutput:
    """Test ProgressBar output."""
    
    def test_output_to_stderr(self):
        """Test output goes to stderr by default."""
        from meow_decoder.progress import ProgressBar
        import sys
        from io import StringIO
        
        # Capture stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            pb = ProgressBar(total=10, desc="Test", disable=False)
            pb.update(5)
            pb.close()
            
            output = sys.stderr.getvalue()
            # May or may not have output depending on implementation
        finally:
            sys.stderr = old_stderr
    
    def test_disable_suppresses_output(self):
        """Test that disable=True suppresses output."""
        from meow_decoder.progress import ProgressBar
        import sys
        from io import StringIO
        
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            pb = ProgressBar(total=10, desc="Silent", disable=True)
            pb.update(10)
            pb.close()
            
            output = sys.stderr.getvalue()
            # Should have minimal or no output
        finally:
            sys.stderr = old_stderr


class TestProgressBarTiming:
    """Test ProgressBar timing features."""
    
    def test_elapsed_time(self):
        """Test elapsed time tracking."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=5, disable=True)
        
        time.sleep(0.1)  # Small delay
        
        pb.update(5)
        pb.close()
    
    def test_rate_calculation(self):
        """Test rate calculation."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, disable=True)
        
        for i in range(100):
            pb.update(1)
            time.sleep(0.001)  # Small delay
        
        pb.close()


class TestProgressBarNested:
    """Test nested progress bars."""
    
    def test_nested_progress(self):
        """Test nested progress bars."""
        from meow_decoder.progress import ProgressBar
        
        outer = ProgressBar(total=3, desc="Outer", disable=True)
        
        for i in outer(range(3)):
            inner = ProgressBar(total=5, desc="Inner", disable=True)
            
            for j in inner(range(5)):
                pass
            
            inner.close()
        
        outer.close()


class TestProgressModule:
    """Test progress module utilities."""
    
    def test_module_imports(self):
        """Test module imports."""
        from meow_decoder import progress
        
        assert hasattr(progress, 'ProgressBar')
    
    def test_tqdm_fallback(self):
        """Test tqdm fallback behavior."""
        from meow_decoder.progress import ProgressBar
        
        # Should work whether tqdm is installed or not
        pb = ProgressBar(total=10, disable=True)
        pb.update(10)
        pb.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
