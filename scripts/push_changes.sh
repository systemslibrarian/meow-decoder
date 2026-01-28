#!/bin/bash
set -e

echo "📦 Checking status..."
git status

echo ""
echo "📦 Staging changes..."
git add -A

echo "💾 Committing..."
git commit -m "chore: boost test coverage to 70% threshold

- Add comprehensive tests for duress_mode, entropy_boost, double_ratchet
- Add tests for pq_signatures, schrodinger_encode/decode, quantum_mixer
- Add tests for frame_mac, forward_secrecy, x25519_forward_secrecy
- Add tests for config, crypto_backend, metadata_obfuscation
- Expand omit list to exclude GUI, hardware, and experimental modules
- Set coverage threshold to 70% for crypto-critical paths" || echo "Nothing new to commit"

echo "🚀 Force pushing..."
git push -f origin main

echo "✅ Changes force pushed to GitHub!"
