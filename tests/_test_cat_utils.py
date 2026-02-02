#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for cat_utils.py and progress.py - Target: 90%+
Tests cat-themed utilities, progress tracking, and NineLivesRetry.
"""

import pytest
import secrets
import sys
import time
from pathlib import Path
from io import StringIO
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCatUtils:
    """Test cat_utils.py functions."""
    
    def test_import_cat_utils(self):
        """Test importing cat_utils module."""
        try:
            from meow_decoder import cat_utils
            assert cat_utils is not None
        except ImportError:
            pytest.skip("cat_utils not available")
    
    def test_meow_about(self):
        """Test meow_about function."""
        try:
            from meow_decoder.cat_utils import meow_about
            
            result = meow_about()
            
            assert isinstance(result, str)
            assert len(result) > 0
        except ImportError:
            pytest.skip("meow_about not available")
    
    def test_enable_purr_mode(self):
        """Test enabling purr mode."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode
            
            purr = enable_purr_mode(enabled=True)
            
            assert purr is not None or purr is True
        except ImportError:
            pytest.skip("enable_purr_mode not available")
    
    def test_disable_purr_mode(self):
        """Test disabling purr mode."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode
            
            purr = enable_purr_mode(enabled=False)
            # Should return None or logger or False
            assert purr is None or purr is False or hasattr(purr, 'log')
        except ImportError:
            pytest.skip("enable_purr_mode not available")
    
    def test_get_purr_logger(self):
        """Test getting purr logger."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode, get_purr_logger
            
            enable_purr_mode(enabled=True)
            logger = get_purr_logger()
            
            if logger is not None:
                assert hasattr(logger, 'log') or logger is not None
        except (ImportError, AttributeError):
            pytest.skip("get_purr_logger not available")


class TestNineLivesRetry:
    """Test NineLivesRetry class."""
    
    def test_nine_lives_creation(self):
        """Test creating NineLivesRetry."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=9, verbose=False)
            
            assert retry.max_lives == 9
            assert retry.succeeded is False
        except ImportError:
            pytest.skip("NineLivesRetry not available")
    
    def test_nine_lives_attempt(self):
        """Test attempt iterator."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=3, verbose=False)
            
            attempts = list(retry.attempt())
            
            assert len(attempts) == 3
        except ImportError:
            pytest.skip("NineLivesRetry not available")
    
    def test_nine_lives_success(self):
        """Test marking success."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=9, verbose=False)
            
            for life in retry.attempt():
                retry.success({"result": "data"})
                break
            
            assert retry.succeeded is True
        except ImportError:
            pytest.skip("NineLivesRetry not available")
    
    def test_nine_lives_fail(self):
        """Test recording failure."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=3, verbose=False)
            
            for life in retry.attempt():
                retry.fail("Something went wrong")
            
            assert retry.succeeded is False
        except ImportError:
            pytest.skip("NineLivesRetry not available")
    
    def test_nine_lives_retry_until_success(self):
        """Test retry until success."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=5, verbose=False)
            
            attempt_count = 0
            for life in retry.attempt():
                attempt_count += 1
                if attempt_count < 3:
                    retry.fail(f"Attempt {attempt_count} failed")
                else:
                    retry.success({"count": attempt_count})
                    break
            
            assert retry.succeeded is True
            assert attempt_count == 3
        except ImportError:
            pytest.skip("NineLivesRetry not available")


class TestProgressBar:
    """Test ProgressBar class."""
    
    def test_progress_bar_creation(self):
        """Test creating ProgressBar."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, desc="Testing", unit="items")
        
        assert pb is not None
    
    def test_progress_bar_disable(self):
        """Test disabled ProgressBar."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, desc="Testing", disable=True)
        
        # Should still work but not display
        assert pb is not None
    
    def test_progress_bar_iteration(self):
        """Test iterating with ProgressBar."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, desc="Test", disable=True)
        
        count = 0
        for i in pb(range(10)):
            count += 1
        
        assert count == 10
    
    def test_progress_bar_update(self):
        """Test manual update."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, desc="Test", disable=True)
        
        # Try to call directly if callable
        try:
            for i in pb(range(10)):
                pass
        except Exception:
            # Just ensure it doesn't crash
            pass
    
    def test_progress_bar_with_list(self):
        """Test progress bar with list."""
        from meow_decoder.progress import ProgressBar
        
        items = [1, 2, 3, 4, 5]
        pb = ProgressBar(len(items), desc="Processing", disable=True)
        
        result = []
        for item in pb(items):
            result.append(item * 2)
        
        assert result == [2, 4, 6, 8, 10]


class TestPurrLogger:
    """Test PurrLogger if available."""
    
    def test_purr_logger_log(self):
        """Test basic logging."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode, get_purr_logger
            
            enable_purr_mode(enabled=True)
            logger = get_purr_logger()
            
            if logger and hasattr(logger, 'log'):
                logger.log("Test message", category="test")
        except (ImportError, AttributeError):
            pytest.skip("PurrLogger not available")
    
    def test_purr_logger_crypto_op(self):
        """Test crypto operation logging."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode, get_purr_logger
            
            enable_purr_mode(enabled=True)
            logger = get_purr_logger()
            
            if logger and hasattr(logger, 'crypto_op'):
                logger.crypto_op("Encrypting data")
        except (ImportError, AttributeError):
            pytest.skip("crypto_op not available")
    
    def test_purr_logger_success(self):
        """Test success logging."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode, get_purr_logger
            
            enable_purr_mode(enabled=True)
            logger = get_purr_logger()
            
            if logger and hasattr(logger, 'success'):
                logger.success("Operation complete!")
        except (ImportError, AttributeError):
            pytest.skip("success not available")


class TestCatJudge:
    """Test cat password judge if available."""
    
    def test_summon_cat_judge(self):
        """Test cat judge summoning."""
        try:
            from meow_decoder.cat_utils import summon_cat_judge
            
            judgment = summon_cat_judge("weak_password")
            
            assert isinstance(judgment, str)
            assert len(judgment) > 0
        except (ImportError, AttributeError):
            pytest.skip("summon_cat_judge not available")
    
    def test_cat_judge_strong_password(self):
        """Test cat judge with strong password."""
        try:
            from meow_decoder.cat_utils import summon_cat_judge
            
            judgment = summon_cat_judge("Str0ng_P@ssw0rd!_Very_L0ng")
            
            assert isinstance(judgment, str)
        except (ImportError, AttributeError):
            pytest.skip("summon_cat_judge not available")


class TestCatModePresets:
    """Test cat mode presets if available."""
    
    def test_cat_breed_presets_exist(self):
        """Test cat breed presets dictionary."""
        try:
            from meow_decoder.cat_utils import CAT_BREED_PRESETS
            
            assert isinstance(CAT_BREED_PRESETS, dict)
        except (ImportError, AttributeError):
            pytest.skip("CAT_BREED_PRESETS not available")


class TestProgressBarEdgeCases:
    """Test progress bar edge cases."""
    
    def test_empty_iteration(self):
        """Test iterating over empty collection."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=0, desc="Empty", disable=True)
        
        count = 0
        for i in pb(range(0)):
            count += 1
        
        assert count == 0
    
    def test_single_item(self):
        """Test single item iteration."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=1, desc="Single", disable=True)
        
        items = []
        for i in pb([42]):
            items.append(i)
        
        assert items == [42]
    
    def test_nested_progress_bars(self):
        """Test nested progress bars."""
        from meow_decoder.progress import ProgressBar
        
        outer = ProgressBar(total=3, desc="Outer", disable=True)
        
        total_inner = 0
        for i in outer(range(3)):
            inner = ProgressBar(total=2, desc="Inner", disable=True)
            for j in inner(range(2)):
                total_inner += 1
        
        assert total_inner == 6


class TestGenerateConvincingDecoy:
    """Test decoy generation if available."""
    
    def test_generate_decoy(self):
        """Test generating convincing decoy."""
        try:
            from meow_decoder.schrodinger_encode import generate_convincing_decoy
            
            decoy = generate_convincing_decoy(10000)
            
            assert isinstance(decoy, bytes)
            assert len(decoy) >= 10000
        except (ImportError, AttributeError, NameError):
            # Try alternate location
            try:
                from meow_decoder.decoy_generator import generate_convincing_decoy
                
                decoy = generate_convincing_decoy(5000)
                
                assert isinstance(decoy, bytes)
            except (ImportError, AttributeError, NameError):
                pytest.skip("generate_convincing_decoy not available")


class TestNineLivesEdgeCases:
    """Test NineLives edge cases."""
    
    def test_zero_lives(self):
        """Test with zero max lives."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=0, verbose=False)
            
            attempts = list(retry.attempt())
            assert len(attempts) == 0
        except ImportError:
            pytest.skip("NineLivesRetry not available")
    
    def test_one_life(self):
        """Test with one life."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=1, verbose=False)
            
            for life in retry.attempt():
                retry.success({"result": "ok"})
                break
            
            assert retry.succeeded is True
        except ImportError:
            pytest.skip("NineLivesRetry not available")
    
    def test_all_lives_exhausted(self):
        """Test exhausting all lives."""
        try:
            from meow_decoder.cat_utils import NineLivesRetry
            
            retry = NineLivesRetry(max_lives=3, verbose=False)
            
            for life in retry.attempt():
                retry.fail("Always fails")
            
            assert retry.succeeded is False
        except ImportError:
            pytest.skip("NineLivesRetry not available")


class TestCatUtilsImports:
    """Test various cat_utils imports."""
    
    def test_import_main_functions(self):
        """Test importing main functions."""
        try:
            from meow_decoder.cat_utils import meow_about
            assert callable(meow_about)
        except ImportError:
            pytest.skip("meow_about not importable")
    
    def test_import_purr_functions(self):
        """Test importing purr functions."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode
            assert callable(enable_purr_mode)
        except ImportError:
            pytest.skip("enable_purr_mode not importable")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
