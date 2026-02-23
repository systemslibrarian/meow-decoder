#!/bin/bash
# Test all fuzz scripts using the venv Python (which has atheris)
PYTHON=/workspaces/meow-decoder/.venv/bin/python
export MEOW_TEST_MODE=1
export MEOW_CRYPTO_BACKEND=rust

mkdir -p fuzz/corpus/manifest fuzz/corpus/fountain fuzz/crashes

scripts=(
  "fuzz/fuzz_manifest.py fuzz/corpus/manifest"
  "fuzz/fuzz_fountain.py fuzz/corpus/fountain"
  "fuzz/fuzz_crypto.py fuzz/corpus/manifest"
  "fuzz/fuzz_windows_guard.py"
  "fuzz/fuzz_mouse_gesture.py"
  "fuzz/fuzz_tamper_detection.py"
  "fuzz/fuzz_adversarial_stego.py"
  "fuzz/fuzz_ratchet.py"
  "fuzz/fuzz_manifest_signing.py"
  "fuzz/fuzz_pq_ratchet_beacon.py"
  "fuzz/fuzz_master_ratchet.py"
  "fuzz/fuzz_schrodinger.py"
  "fuzz/fuzz_crypto_backend.py"
  "fuzz/fuzz_shamir.py"
  "fuzz/fuzz_memory_guard.py"
  "fuzz/fuzz_dual_stream.py"
  "fuzz/fuzz_stego_multilayer.py"
)

FAILURES=0
for cmd in "${scripts[@]}"; do
  echo "=== $PYTHON $cmd ==="
  timeout 5s $PYTHON $cmd 2>&1 | head -10
  RC=$?
  if [ $RC -eq 0 ] || [ $RC -eq 124 ]; then
    echo "RC=$RC OK"
  else
    echo "RC=$RC FAIL ← WOULD BREAK CI"
    FAILURES=$((FAILURES+1))
  fi
  echo ""
done

echo "============================="
echo "Failures: $FAILURES"
