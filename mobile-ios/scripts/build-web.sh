#!/usr/bin/env bash
# build-web.sh — stage the meow-decoder WASM web demo into dist/ for Capacitor.
#
# This script is the equivalent of cipher-mix's "vite build --base ./" step.
# It collects the standalone HTML demo + every asset it references into
# mobile-ios/dist/, rewriting parent-relative paths to be self-contained,
# so `cap sync ios` ships a single bundle that runs from a file:// origin
# inside WKWebView — no network, no Flask, no path tricks.
#
# Inputs (all relative to repo root):
#   web_demo/wasm_browser_example_FULL.html    → dist/index.html
#   web_demo/*.js                              → dist/
#   web_demo/static/                           → dist/static/
#   web_demo/manifest.json, web_demo/sw.js     → dist/
#   assets/                                    → dist/assets/
#   crypto_core/pkg/                           → dist/crypto_core/pkg/
#
# Path rewrites in index.html:
#   "../assets/"     → "assets/"
#   "../crypto_core/" → "crypto_core/"
#   (everything under web_demo/ already uses paths that resolve from dist/.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MOBILE_IOS_DIR/.." && pwd)"
DIST="$MOBILE_IOS_DIR/dist"

WEB_DEMO="$REPO_ROOT/web_demo"
ASSETS="$REPO_ROOT/assets"
CRYPTO_PKG="$REPO_ROOT/crypto_core/pkg"

if [[ ! -f "$WEB_DEMO/wasm_browser_example_FULL.html" ]]; then
    echo "error: $WEB_DEMO/wasm_browser_example_FULL.html not found" >&2
    exit 1
fi

if [[ ! -d "$CRYPTO_PKG" ]]; then
    echo "error: $CRYPTO_PKG not found — build the crypto_core wasm first" >&2
    echo "       (cd crypto_core && wasm-pack build --target web --out-dir pkg)" >&2
    exit 1
fi

echo "==> staging dist/ at $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

# 1. The web demo's JS, manifest, service worker, static/ subtree.
#    Use rsync so we skip node_modules, instance/, test artifacts, and *.py.
rsync -a \
    --exclude 'node_modules/' \
    --exclude 'instance/' \
    --exclude 'test-results/' \
    --exclude '__pycache__/' \
    --exclude '__tests__/' \
    --exclude '_e2e_*' \
    --exclude 'templates/' \
    --exclude 'start.sh' \
    --exclude '*.py' \
    --exclude '*.txt' \
    --exclude 'package*.json' \
    --exclude 'README.md' \
    --exclude 'wasm_browser_example_FULL.html' \
    --exclude 'crypto_core.js' \
    --exclude 'crypto_core_bg.wasm' \
    --exclude 'crypto_core.d.ts' \
    "$WEB_DEMO/" "$DIST/"

# 2. The single-file demo becomes the SPA's index.html with parent-relative
#    paths rewritten to live alongside it.
sed \
    -e 's|\.\./assets/|assets/|g' \
    -e 's|\.\./crypto_core/|crypto_core/|g' \
    "$WEB_DEMO/wasm_browser_example_FULL.html" > "$DIST/index.html"

# 3. Assets and the wasm pkg.
mkdir -p "$DIST/assets" "$DIST/crypto_core/pkg"
rsync -a "$ASSETS/" "$DIST/assets/"
rsync -a "$CRYPTO_PKG/" "$DIST/crypto_core/pkg/"

# 4. PWA manifest lives under examples/ in the source tree; rewrite its
#    parent-relative asset paths and pin start_url to the bundled index.
sed \
    -e 's|"\.\./assets/|"assets/|g' \
    -e 's|"start_url":[[:space:]]*"\.\/[^"]*"|"start_url": "./index.html"|' \
    "$REPO_ROOT/examples/manifest.json" > "$DIST/manifest.json"

# 5. Sanity check — every <script src> and <link href> resolves within dist/.
node "$SCRIPT_DIR/verify-bundle.mjs"

echo "==> dist/ ready ($(du -sh "$DIST" | cut -f1))"
