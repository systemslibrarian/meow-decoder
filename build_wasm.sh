#!/bin/bash
set -e
cd /workspaces/meow-decoder/crypto_core
wasm-pack build --target web --release --features wasm-pq
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../examples/
echo "Build complete!"
ls -la ../examples/crypto_core*
