#!/bin/bash
set -e
cd /workspaces/meow-decoder/crypto_core
# wasm-fountain bundles the Luby Transform encoder/decoder into the
# same crypto_core_bg.wasm so the web demo gets byte-identical fountain
# output to the Python encoder. See docs/FOUNTAIN_RUST_WASM_MIGRATION.md
# Phase 3.
wasm-pack build --target web --release --features "wasm-pq wasm-fountain"
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../examples/
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../web_demo/static/
cp pkg/crypto_core.js pkg/crypto_core_bg.wasm ../web_demo/
echo "Build complete!"
ls -la ../examples/crypto_core* ../web_demo/static/crypto_core* ../web_demo/crypto_core*
