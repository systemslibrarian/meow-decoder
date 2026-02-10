#!/bin/bash
# prepare_pythonanywhere.sh
# Prepares the WASM demo files for upload to PythonAnywhere

set -e

DEPLOY_DIR="pythonanywhere-deploy"

echo "🐱 Preparing Meow Decoder WASM demo for PythonAnywhere..."

# Check if WASM is built
if [ ! -f "crypto_core/pkg/crypto_core.js" ]; then
    echo "❌ WASM not built! Run 'make build-wasm' first."
    exit 1
fi

# Create directory structure
rm -rf "$DEPLOY_DIR"
mkdir -p "$DEPLOY_DIR/crypto_core/pkg"
mkdir -p "$DEPLOY_DIR/assets"

# Copy and rename HTML
cp examples/wasm_browser_example.html "$DEPLOY_DIR/index.html"

# Copy Web Worker
cp examples/crypto-worker.js "$DEPLOY_DIR/crypto-worker.js"

# Copy Service Worker for caching
cp examples/sw.js "$DEPLOY_DIR/sw.js"

# Fix paths in the HTML (../ to ./)
sed -i 's|\.\./crypto_core/pkg|./crypto_core/pkg|g' "$DEPLOY_DIR/index.html"
sed -i 's|\.\./assets|./assets|g' "$DEPLOY_DIR/index.html"

# Fix worker path in the HTML (already correct, but ensure consistency)
# Worker uses ../crypto_core/pkg which needs to become ./crypto_core/pkg
sed -i 's|\.\./crypto_core/pkg|./crypto_core/pkg|g' "$DEPLOY_DIR/crypto-worker.js"

# Copy WASM package
cp -r crypto_core/pkg/* "$DEPLOY_DIR/crypto_core/pkg/"

# Copy assets
cp -r assets/* "$DEPLOY_DIR/assets/"

# Create Flask app
cat > "$DEPLOY_DIR/flask_app.py" << 'EOF'
from flask import Flask, send_from_directory, jsonify
import mimetypes
import os

# Register WASM MIME type
mimetypes.add_type('application/wasm', '.wasm')

app = Flask(__name__)

# Use current directory as demo dir (adjust for PythonAnywhere)
DEMO_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    return send_from_directory(DEMO_DIR, 'index.html')

@app.route('/crypto-worker.js')
def serve_worker():
    response = send_from_directory(DEMO_DIR, 'crypto-worker.js')
    response.headers['Content-Type'] = 'application/javascript'
    return response

@app.route('/sw.js')
def serve_service_worker():
    response = send_from_directory(DEMO_DIR, 'sw.js')
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Service-Worker-Allowed'] = '/'
    return response

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    return send_from_directory(os.path.join(DEMO_DIR, 'assets'), filename)

@app.route('/crypto_core/pkg/<path:filename>')
def serve_wasm_pkg(filename):
    response = send_from_directory(
        os.path.join(DEMO_DIR, 'crypto_core', 'pkg'),
        filename
    )
    if filename.endswith('.wasm'):
        response.headers['Content-Type'] = 'application/wasm'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'app': 'Meow Decoder WASM Demo'})

if __name__ == '__main__':
    app.run(debug=True)
EOF

# Calculate sizes
WASM_SIZE=$(du -sh "$DEPLOY_DIR/crypto_core/pkg/" | cut -f1)
TOTAL_SIZE=$(du -sh "$DEPLOY_DIR" | cut -f1)

echo ""
echo "✅ Files ready in $DEPLOY_DIR/"
echo ""
echo "📁 Contents:"
find "$DEPLOY_DIR" -type f | sed 's|^|   |'
echo ""
echo "📊 Sizes:"
echo "   WASM package: $WASM_SIZE"
echo "   Total: $TOTAL_SIZE"
echo ""
echo "📤 Upload options:"
echo "   1. Upload folder via PythonAnywhere Files tab"
echo "   2. Or use: scp -r $DEPLOY_DIR/* user@ssh.pythonanywhere.com:~/meow-demo/"
echo ""
echo "📖 See examples/PYTHONANYWHERE_HOSTING.md for full instructions"
