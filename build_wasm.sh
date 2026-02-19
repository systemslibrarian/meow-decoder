#!/bin/bash
set -e
cd /workspaces/meow-decoder/crypto_core
wasm-pack build --target web --release --features wasm-pq
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../examples/
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../web_demo/static/
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../web_demo/
echo "Build complete!"
ls -la ../examples/crypto_core* ../web_demo/static/crypto_core* ../web_demo/crypto_core*
