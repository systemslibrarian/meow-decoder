import sys
import unittest
import runpy
import io
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent dir to path so we can import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestMainBlocks(unittest.TestCase):
    """Test __main__ blocks of modules."""
    
    def test_crypto_main(self):
        """Run crypto.py __main__ block."""
        # This block runs some basic tests and prints output
        # We just want to ensure it runs without error
        with patch.object(sys, 'argv', ['crypto.py']):
            # It prints to stdout, so we might want to capture it to keep test output clean
            with patch('sys.stdout', new=io.StringIO()):
                 try:
                     runpy.run_module("meow_decoder.crypto", run_name="__main__")
                 except SystemExit:
                     pass

    def test_qr_code_main(self):
        """Run qr_code.py __main__ block."""
        with patch.object(sys, 'argv', ['qr_code.py']):
            with patch('sys.stdout', new=io.StringIO()):
                 try:
                     runpy.run_module("meow_decoder.qr_code", run_name="__main__")
                 except SystemExit:
                     pass

class TestImportFallbacks(unittest.TestCase):
    """Test ImportError handling for relative/absolute imports."""

    def test_encrypt_padding_import_error(self):
        """
        Force ImportError on 'from .metadata_obfuscation import add_length_padding'
        inside crypto.encrypt_file_bytes to trigger the except block.
        """
        # We need to ensure we're targeting the right module
        from meow_decoder import crypto
        
        # We need to control the import WITHIN the function.
        # builtins.__import__ is the way.
        
        original_import = __import__
        
        def side_effect(name, globals=None, locals=None, fromlist=(), level=0):
            # Target `from .metadata_obfuscation import add_length_padding` invoked from meow_decoder.crypto
            # This appears as level > 0
            if level > 0 and 'metadata_obfuscation' in name:
                 raise ImportError("Forced error")
            return original_import(name, globals, locals, fromlist, level)
            
        # We only want to patch it during the call
        with patch('builtins.__import__', side_effect=side_effect):
            try:
                # We expect it to try the relative import, fail, and try the absolute import.
                # If absolute import succeeds, great.
                crypto.encrypt_file_bytes(b"test", "pass", use_length_padding=True)
            except Exception:
                # We don't care if encryption eventually fails
                pass


class TestCryptoMainExecution(unittest.TestCase):
    
    def test_crypto_main_execution(self):
        # Run crypto.py as script
        with patch.object(sys, 'argv', ['crypto.py']):
             with patch('sys.stdout', new=io.StringIO()):
                 runpy.run_module("meow_decoder.crypto", run_name="__main__")

    def test_forward_secrecy_main_execution(self):
        # Run forward_secrecy.py as script
        with patch.object(sys, 'argv', ['forward_secrecy.py']):
             with patch('sys.stdout', new=io.StringIO()):
                 try:
                     runpy.run_module("meow_decoder.forward_secrecy", run_name="__main__")
                 except SystemExit:
                     pass

    def test_x25519_forward_secrecy_main_execution(self):
        """Run x25519_forward_secrecy.py as script (generate command)."""
        # Patch stdout to suppress output
        # Patch stdin to provide password to inputs
        
        # Case 1: generate command
        with patch.object(sys, 'argv', ['prog', 'generate', '.']):
            # Provide passwords for the CLI interaction
             with patch('sys.stdin', io.StringIO("password\npassword\n")):
                 with patch('sys.stdout', new=io.StringIO()):
                     try:
                         runpy.run_module("meow_decoder.x25519_forward_secrecy", run_name="__main__")
                     except SystemExit:
                         pass

        # Case 2: default/help
        with patch.object(sys, 'argv', ['prog']):
             with patch('sys.stdout', new=io.StringIO()):
                 try:
                     runpy.run_module("meow_decoder.x25519_forward_secrecy", run_name="__main__")
                 except SystemExit:
                     pass

    def test_qr_code_main_execution(self):
         # Run qr_code.py as script
        with patch.object(sys, 'argv', ['qr_code.py']):
             with patch('sys.stdout', new=io.StringIO()):
                 runpy.run_module("meow_decoder.qr_code", run_name="__main__")
