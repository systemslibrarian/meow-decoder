import pytest

import unittest
import secrets
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.duress_mode import (
    DuressHandler, DuressConfig, DuressMode, 
    generate_static_decoy, setup_duress
)

class TestDuressModes(unittest.TestCase):
    
    def test_static_decoy_determinism(self):
        """Test that generate_static_decoy is deterministic based on salt."""
        salt1 = b"salt_for_file_A"
        salt2 = b"salt_for_file_B"
        
        decoy1_a = generate_static_decoy(salt1, size=100)
        decoy1_b = generate_static_decoy(salt1, size=100)
        decoy2 = generate_static_decoy(salt2, size=100)
        
        # Determinism
        self.assertEqual(decoy1_a, decoy1_b, "Decoy must be consistent for same salt")
        
        # Uniqueness
        self.assertNotEqual(decoy1_a, decoy2, "Decoy must differ for different salts")
        
        # Properties
        self.assertEqual(len(decoy1_a), 100)
        
    def test_decoy_mode_execution(self):
        """Test DEC0Y mode returns data."""
        config = DuressConfig(mode=DuressMode.DECOY, panic_enabled=False)
        handler = DuressHandler(config)
        
        salt = secrets.token_bytes(16)
        result = handler.execute_emergency_response([], salt=salt)
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, bytes)
        self.assertTrue(len(result) > 0)
        
        # Should match static generation
        expected = generate_static_decoy(salt)
        self.assertEqual(result, expected)

    def test_panic_mode_execution_enabled(self):
        """Test PANIC mode returns None when enabled."""
        config = DuressConfig(mode=DuressMode.PANIC, panic_enabled=True)
        handler = DuressHandler(config)
        
        result = handler.execute_emergency_response([], salt=b"any")
        self.assertIsNone(result)

    def test_panic_mode_execution_disabled(self):
        """Test PANIC mode falls back (returns None but logic might vary) if disabled."""
        # Current implementation: if panic_disabled, it falls through to DECOY logic if salt provided.
        config = DuressConfig(mode=DuressMode.PANIC, panic_enabled=False)
        handler = DuressHandler(config)
        
        salt = secrets.token_bytes(16)
        result = handler.execute_emergency_response([], salt=salt)
        
        # Logic says: if panic disabled, pass. Then 'if salt: return decoy'.
        self.assertIsNotNone(result)
        self.assertIsInstance(result, bytes) 

    def test_check_password_flow(self):
        """Test the check_password flow integration."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)
        
        # Check real
        valid, duress = handler.check_password("real", salt)
        self.assertTrue(valid)
        self.assertFalse(duress)
        
        # Check duress
        valid, duress = handler.check_password("duress", salt)
        self.assertTrue(valid)
        self.assertTrue(duress)
        self.assertTrue(handler.was_triggered)

if __name__ == '__main__':
    unittest.main()
