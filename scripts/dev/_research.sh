#!/bin/bash
cd /workspaces/meow-decoder

echo "=== GIT LOG FOR TEST FILE ==="
git log --oneline -20 -- tests/test_e2e_gif_ratchet.py

echo ""
echo "=== RECENT COMMITS ==="
git log --oneline -10

echo ""
echo "=== handle_mix_hkdf exists? ==="
python3 -c "import meow_crypto_rs; print(hasattr(meow_crypto_rs, 'handle_mix_hkdf'))"

echo ""
echo "=== mix/hkdf functions ==="
python3 -c "import meow_crypto_rs; funcs = [f for f in dir(meow_crypto_rs) if 'mix' in f.lower() or 'hkdf' in f.lower()]; print(funcs)"

echo ""
echo "=== all meow_crypto_rs functions ==="
python3 -c "import meow_crypto_rs; print([f for f in dir(meow_crypto_rs) if not f.startswith('_')])"
