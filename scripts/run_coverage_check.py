#!/usr/bin/env python3
"""
Run test suite with coverage and report results.
Execute this script directly to see coverage progress.
"""

import subprocess
import sys
import os

def main():
    os.environ['MEOW_TEST_MODE'] = '1'
    
    result = subprocess.run(
        [
            sys.executable, '-m', 'pytest', 
            'tests/', 
            '-v',
            '--cov=meow_decoder',
            '--cov-report=term-missing',
            '--cov-fail-under=70',  # Start with 70%, increase to 90%
            '--tb=short',
            '-x',  # Stop on first failure for faster feedback
        ],
        cwd='/workspaces/meow-decoder',
        capture_output=False
    )
    
    return result.returncode

if __name__ == '__main__':
    sys.exit(main())
