#!/usr/bin/env python3
"""Run coverage tests and generate report."""
import subprocess
import sys
import os

os.environ['MEOW_TEST_MODE'] = '1'

# Run pytest with coverage
result = subprocess.run([
    sys.executable, '-m', 'pytest',
    'tests/',
    '-x',  # Stop on first failure
    '--cov=meow_decoder',
    '--cov-report=term-missing',
    '--cov-report=html',
    '--no-header',
    '-q',
    '--tb=short'
], cwd='/workspaces/meow-decoder')

sys.exit(result.returncode)
