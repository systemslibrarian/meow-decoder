#!/bin/bash
set -e

echo "===== COMMAND 1: cargo test -p crypto_core =====" > /workspaces/meow-decoder/_test_output.txt
cd /workspaces/meow-decoder
cargo test -p crypto_core 2>&1 | tail -10 >> /workspaces/meow-decoder/_test_output.txt 2>&1
echo "EXIT_CODE_1=$?" >> /workspaces/meow-decoder/_test_output.txt

echo "" >> /workspaces/meow-decoder/_test_output.txt
echo "===== COMMAND 2: pytest selected tests =====" >> /workspaces/meow-decoder/_test_output.txt
MEOW_TEST_MODE=1 python -m pytest tests/test_crypto_enforcement.py tests/test_pq_crypto.py tests/test_pq_crypto_real.py tests/test_audit_fixes.py -v 2>&1 | tail -40 >> /workspaces/meow-decoder/_test_output.txt 2>&1
echo "EXIT_CODE_2=$?" >> /workspaces/meow-decoder/_test_output.txt

echo "" >> /workspaces/meow-decoder/_test_output.txt
echo "===== COMMAND 3: pytest -q (all tests) =====" >> /workspaces/meow-decoder/_test_output.txt
MEOW_TEST_MODE=1 python -m pytest -q 2>&1 | tail -20 >> /workspaces/meow-decoder/_test_output.txt 2>&1
echo "EXIT_CODE_3=$?" >> /workspaces/meow-decoder/_test_output.txt

echo "" >> /workspaces/meow-decoder/_test_output.txt
echo "===== DONE =====" >> /workspaces/meow-decoder/_test_output.txt
