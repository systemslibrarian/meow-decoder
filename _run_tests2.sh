#!/bin/bash
# No set -e, let all commands run

OUTPUT=/workspaces/meow-decoder/_test_output.txt
echo "STARTED" > "$OUTPUT"

echo "===== COMMAND 1: cargo test -p crypto_core =====" >> "$OUTPUT"
cd /workspaces/meow-decoder
cargo test -p crypto_core 2>&1 | tail -10 >> "$OUTPUT" 2>&1
echo "EXIT_CODE_1=$?" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "===== COMMAND 2: pytest selected tests =====" >> "$OUTPUT"
MEOW_TEST_MODE=1 /usr/local/bin/python -m pytest tests/test_crypto_enforcement.py tests/test_pq_crypto.py tests/test_pq_crypto_real.py tests/test_audit_fixes.py -v 2>&1 | tail -40 >> "$OUTPUT" 2>&1
echo "EXIT_CODE_2=$?" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "===== COMMAND 3: pytest -q (all tests) =====" >> "$OUTPUT"
MEOW_TEST_MODE=1 /usr/local/bin/python -m pytest -q 2>&1 | tail -20 >> "$OUTPUT" 2>&1
echo "EXIT_CODE_3=$?" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "===== DONE =====" >> "$OUTPUT"
