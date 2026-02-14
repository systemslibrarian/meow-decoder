"""Tests for setup module (1-to-1 mapping).

Validates setup.py syntax is valid Python.
"""

import ast
from pathlib import Path

import pytest


class TestSetup:
    def test_setup_syntax_valid(self):
        setup_path = Path(__file__).parent.parent / "meow_decoder" / "setup.py"
        if setup_path.exists():
            with open(setup_path) as f:
                content = f.read()
            ast.parse(content)
        else:
            pytest.skip("setup.py not found in meow_decoder/")
