#!/bin/bash
export MEOW_TEST_MODE=1
export MEOW_CRYPTO_BACKEND=rust

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

for cmd in "${scripts[@]}"; do
  echo "=== python $cmd ==="
  timeout 4s python $cmd 2>&1 | head -8
  RC=$?
  if [ $RC -eq 0 ] || [ $RC -eq 124 ]; then
    echo "RC=$RC OK"
  else
    echo "RC=$RC FAIL"
  fi
  echo ""
done
