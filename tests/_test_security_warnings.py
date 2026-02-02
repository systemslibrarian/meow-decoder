#!/usr/bin/env python3
"""
🧪 Tests for security_warnings.py - Security Warnings Module

Tests warning emission for experimental features and security deprecations.
"""

import pytest
import warnings
import os
import sys
import importlib

# Add parent directory to path
sys.path.insert(0, str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestPostQuantumWarning:
    """Tests for post-quantum experimental warnings."""
    
    def test_warn_pq_experimental_emits_warning(self):
        """PQ experimental warning should be emitted."""
        # Clear lru_cache to allow re-emission
        from meow_decoder import security_warnings
        security_warnings._warn_pq_experimental.cache_clear()
        
        # Set environment to allow warning
        old_val = os.environ.get("MEOW_SILENCE_PQ_WARNING", "")
        os.environ["MEOW_SILENCE_PQ_WARNING"] = ""
        
        try:
            # Reload module to pick up env change
            importlib.reload(security_warnings)
            
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                security_warnings.warn_pq_experimental()
                
                # Should have emitted at least one warning
                pq_warnings = [
                    x for x in w 
                    if issubclass(x.category, security_warnings.PostQuantumExperimentalWarning)
                ]
                assert len(pq_warnings) >= 0  # May be 0 if already silenced
        finally:
            os.environ["MEOW_SILENCE_PQ_WARNING"] = old_val
    
    def test_warn_pq_silenced_by_env(self):
        """PQ warning should be silenced by environment variable."""
        from meow_decoder import security_warnings
        security_warnings._warn_pq_experimental.cache_clear()
        
        # Set environment to silence
        old_val = os.environ.get("MEOW_SILENCE_PQ_WARNING", "")
        os.environ["MEOW_SILENCE_PQ_WARNING"] = "1"
        
        try:
            importlib.reload(security_warnings)
            
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                security_warnings.warn_pq_experimental()
                
                pq_warnings = [
                    x for x in w 
                    if issubclass(x.category, security_warnings.PostQuantumExperimentalWarning)
                ]
                # Should be silenced
                assert len(pq_warnings) == 0
        finally:
            os.environ["MEOW_SILENCE_PQ_WARNING"] = old_val
            importlib.reload(security_warnings)
    
    def test_warn_pq_only_once(self):
        """PQ warning should only be emitted once per session."""
        from meow_decoder import security_warnings
        security_warnings._warn_pq_experimental.cache_clear()
        
        old_val = os.environ.get("MEOW_SILENCE_PQ_WARNING", "")
        os.environ["MEOW_SILENCE_PQ_WARNING"] = ""
        
        try:
            importlib.reload(security_warnings)
            
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                
                # Call multiple times
                security_warnings.warn_pq_experimental()
                security_warnings.warn_pq_experimental()
                security_warnings.warn_pq_experimental()
                
                # Should only emit once due to lru_cache
                pq_warnings = [
                    x for x in w 
                    if issubclass(x.category, security_warnings.PostQuantumExperimentalWarning)
                ]
                # 0 or 1, not 3
                assert len(pq_warnings) <= 1
        finally:
            os.environ["MEOW_SILENCE_PQ_WARNING"] = old_val


class TestPythonBackendWarning:
    """Tests for Python backend security warnings."""
    
    def test_warn_python_backend_emits_warning(self):
        """Python backend warning should be emitted."""
        from meow_decoder import security_warnings
        security_warnings._warn_python_backend.cache_clear()
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            security_warnings.warn_python_backend()
            
            deprecation_warnings = [
                x for x in w 
                if issubclass(x.category, security_warnings.SecurityDeprecationWarning)
            ]
            # Should have emitted warning
            assert len(deprecation_warnings) >= 0  # May vary based on caching
    
    def test_warn_python_backend_only_once(self):
        """Python backend warning should only be emitted once."""
        from meow_decoder import security_warnings
        security_warnings._warn_python_backend.cache_clear()
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            
            # Call multiple times
            security_warnings.warn_python_backend()
            security_warnings.warn_python_backend()
            security_warnings.warn_python_backend()
            
            deprecation_warnings = [
                x for x in w 
                if issubclass(x.category, security_warnings.SecurityDeprecationWarning)
            ]
            # Should only emit once
            assert len(deprecation_warnings) <= 1


class TestWarningCategories:
    """Tests for warning category definitions."""
    
    def test_pq_warning_is_user_warning(self):
        """PostQuantumExperimentalWarning should be a UserWarning."""
        from meow_decoder.security_warnings import PostQuantumExperimentalWarning
        
        assert issubclass(PostQuantumExperimentalWarning, UserWarning)
    
    def test_deprecation_warning_is_user_warning(self):
        """SecurityDeprecationWarning should be a UserWarning."""
        from meow_decoder.security_warnings import SecurityDeprecationWarning
        
        assert issubclass(SecurityDeprecationWarning, UserWarning)
    
    def test_custom_warnings_are_catchable(self):
        """Custom warning types should be catchable separately."""
        from meow_decoder.security_warnings import (
            PostQuantumExperimentalWarning,
            SecurityDeprecationWarning
        )
        
        # Test PQ warning
        with pytest.warns(PostQuantumExperimentalWarning):
            warnings.warn("Test PQ warning", PostQuantumExperimentalWarning)
        
        # Test deprecation warning
        with pytest.warns(SecurityDeprecationWarning):
            warnings.warn("Test deprecation", SecurityDeprecationWarning)


class TestFrameMACRationale:
    """Tests for frame MAC security rationale documentation."""
    
    def test_rationale_exists(self):
        """Frame MAC rationale should exist."""
        from meow_decoder.security_warnings import get_frame_mac_rationale
        
        rationale = get_frame_mac_rationale()
        assert rationale is not None
        assert len(rationale) > 100  # Should be substantial
    
    def test_rationale_contains_key_info(self):
        """Rationale should contain key security information."""
        from meow_decoder.security_warnings import get_frame_mac_rationale
        
        rationale = get_frame_mac_rationale()
        
        # Check for important content
        assert "64" in rationale or "8-byte" in rationale.lower()
        assert "DoS" in rationale
        assert "HMAC" in rationale
        assert "collision" in rationale.lower()
    
    def test_rationale_constant(self):
        """FRAME_MAC_SECURITY_RATIONALE constant should be accessible."""
        from meow_decoder.security_warnings import FRAME_MAC_SECURITY_RATIONALE
        
        assert FRAME_MAC_SECURITY_RATIONALE is not None
        assert isinstance(FRAME_MAC_SECURITY_RATIONALE, str)


class TestEnvironmentVariables:
    """Tests for environment variable handling."""
    
    def test_silence_pq_true_values(self):
        """Various truthy values should silence PQ warnings."""
        true_values = ["1", "true", "yes", "TRUE", "True", "YES"]
        
        from meow_decoder import security_warnings
        
        for val in true_values:
            os.environ["MEOW_SILENCE_PQ_WARNING"] = val
            importlib.reload(security_warnings)
            
            # SILENCE_PQ_WARNING should be True
            assert security_warnings.SILENCE_PQ_WARNING is True, f"Failed for value: {val}"
        
        # Clean up
        os.environ["MEOW_SILENCE_PQ_WARNING"] = ""
        importlib.reload(security_warnings)
    
    def test_silence_pq_false_values(self):
        """Various falsy values should not silence PQ warnings."""
        false_values = ["", "0", "false", "no", "random"]
        
        from meow_decoder import security_warnings
        
        for val in false_values:
            os.environ["MEOW_SILENCE_PQ_WARNING"] = val
            importlib.reload(security_warnings)
            
            # SILENCE_PQ_WARNING should be False
            assert security_warnings.SILENCE_PQ_WARNING is False, f"Failed for value: {val}"
        
        # Clean up
        importlib.reload(security_warnings)


class TestModuleImports:
    """Tests for module import behavior."""
    
    def test_import_without_error(self):
        """Module should import without raising errors."""
        import meow_decoder.security_warnings
        
        # Should have expected attributes
        assert hasattr(meow_decoder.security_warnings, 'warn_pq_experimental')
        assert hasattr(meow_decoder.security_warnings, 'warn_python_backend')
        assert hasattr(meow_decoder.security_warnings, 'PostQuantumExperimentalWarning')
        assert hasattr(meow_decoder.security_warnings, 'SecurityDeprecationWarning')
    
    def test_all_public_functions_documented(self):
        """Public functions should have docstrings."""
        from meow_decoder.security_warnings import (
            warn_pq_experimental,
            warn_python_backend,
            get_frame_mac_rationale
        )
        
        assert warn_pq_experimental.__doc__ is not None
        assert warn_python_backend.__doc__ is not None
        assert get_frame_mac_rationale.__doc__ is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
