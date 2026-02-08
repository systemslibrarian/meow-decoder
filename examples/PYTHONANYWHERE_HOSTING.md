# 🌐 Hosting the WASM Demo on PythonAnywhere

This guide explains how to host the Meow Decoder WASM browser demo on [PythonAnywhere](https://www.pythonanywhere.com).

## Prerequisites

- A PythonAnywhere account (free tier works!)
- The WASM module built locally (`make build-wasm`)

## Option 1: Static Files Only (Simplest)

PythonAnywhere can serve static files directly. This is the easiest approach.

### Step 1: Prepare the Files

You need these files/folders from your local build:

```
crypto_core/pkg/           # The built WASM module
├── crypto_core.js
├── crypto_core_bg.wasm
├── crypto_core.d.ts
├── package.json
└── ...

examples/
└── wasm_browser_example.html

assets/
└── meow-decoder-logo.svg
```

### Step 2: Create Directory Structure on PythonAnywhere

1. Log into PythonAnywhere
2. Go to **Files** tab
3. Create this structure in your home directory:

```
/home/yourusername/
└── meow-demo/
    ├── index.html              # Renamed from wasm_browser_example.html
    ├── assets/
    │   └── meow-decoder-logo.svg
    └── crypto_core/
        └── pkg/
            ├── crypto_core.js
            ├── crypto_core_bg.wasm
            └── ...
```

### Step 3: Update the HTML Paths

Before uploading, edit `wasm_browser_example.html`:

Change this line:
```javascript
const wasmModule = await import('../crypto_core/pkg/crypto_core.js');
```

To:
```javascript
const wasmModule = await import('./crypto_core/pkg/crypto_core.js');
```

And change the logo path:
```html
<img src="./assets/meow-decoder-logo.svg" alt="Meow Decoder" class="logo">
```

### Step 4: Create a Flask App

1. Go to **Web** tab → **Add a new web app**
2. Choose **Flask** and Python 3.10+
3. Replace the generated `flask_app.py` with:

```python
from flask import Flask, send_from_directory
import os

app = Flask(__name__)

# Path to your demo files
DEMO_DIR = '/home/yourusername/meow-demo'

@app.route('/')
def index():
    return send_from_directory(DEMO_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(DEMO_DIR, filename)

# Critical: Serve WASM with correct MIME type
@app.route('/crypto_core/pkg/<path:filename>')
def serve_wasm(filename):
    response = send_from_directory(
        os.path.join(DEMO_DIR, 'crypto_core', 'pkg'), 
        filename
    )
    if filename.endswith('.wasm'):
        response.headers['Content-Type'] = 'application/wasm'
    return response
```

### Step 5: Configure Static Files (Alternative)

Instead of Flask routing, you can use PythonAnywhere's static file mapping:

1. **Web** tab → scroll to **Static files**
2. Add these mappings:

| URL | Directory |
|-----|-----------|
| `/` | `/home/yourusername/meow-demo` |
| `/assets` | `/home/yourusername/meow-demo/assets` |
| `/crypto_core` | `/home/yourusername/meow-demo/crypto_core` |

3. **Important:** Add a custom MIME type for `.wasm` files:
   - Go to **Web** tab → **WSGI configuration file**
   - Or add to your `flask_app.py`:

```python
import mimetypes
mimetypes.add_type('application/wasm', '.wasm')
```

### Step 6: Upload Files

**Option A: Via Web Interface**
1. Go to **Files** tab
2. Navigate to `/home/yourusername/meow-demo/`
3. Click **Upload a file** for each file
4. For folders, create them first, then upload contents

**Option B: Via Git (Recommended)**
```bash
# On PythonAnywhere Bash console:
cd ~
git clone https://github.com/systemslibrarian/meow-decoder.git
mkdir -p meow-demo/crypto_core
cp meow-decoder/examples/wasm_browser_example.html meow-demo/index.html
cp -r meow-decoder/assets meow-demo/
# Note: You'll need to build WASM locally and upload pkg/ folder
```

**Option C: Via SCP/SFTP**
```bash
# From your local machine:
scp -r crypto_core/pkg/ yourusername@ssh.pythonanywhere.com:~/meow-demo/crypto_core/
scp examples/wasm_browser_example.html yourusername@ssh.pythonanywhere.com:~/meow-demo/index.html
scp -r assets/ yourusername@ssh.pythonanywhere.com:~/meow-demo/
```

### Step 7: Reload and Test

1. Go to **Web** tab
2. Click **Reload** (big green button)
3. Visit `https://yourusername.pythonanywhere.com/`

---

## Option 2: Full Flask App with API

For a more complete setup with potential future API endpoints:

### flask_app.py

```python
from flask import Flask, send_from_directory, jsonify
import mimetypes
import os

# Register WASM MIME type
mimetypes.add_type('application/wasm', '.wasm')

app = Flask(__name__)

# Configuration
DEMO_DIR = '/home/yourusername/meow-demo'

@app.route('/')
def index():
    """Serve the main demo page"""
    return send_from_directory(DEMO_DIR, 'index.html')

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve asset files (logo, etc.)"""
    return send_from_directory(os.path.join(DEMO_DIR, 'assets'), filename)

@app.route('/crypto_core/pkg/<path:filename>')
def serve_wasm_pkg(filename):
    """Serve WASM package with correct headers"""
    response = send_from_directory(
        os.path.join(DEMO_DIR, 'crypto_core', 'pkg'),
        filename
    )
    
    # Set correct MIME types
    if filename.endswith('.wasm'):
        response.headers['Content-Type'] = 'application/wasm'
    elif filename.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript'
    
    # Enable CORS for WASM loading
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'app': 'Meow Decoder WASM Demo'
    })

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
```

---

## Troubleshooting

### "Failed to load WASM" Error

**Cause:** WASM file not served with correct MIME type.

**Fix:** Ensure `application/wasm` MIME type is set:
```python
mimetypes.add_type('application/wasm', '.wasm')
```

### CORS Errors

**Cause:** Browser blocking cross-origin requests.

**Fix:** Add CORS headers:
```python
response.headers['Access-Control-Allow-Origin'] = '*'
```

### 404 on WASM Files

**Cause:** Path mismatch between HTML and server.

**Fix:** Check the import path in the HTML matches your server structure:
```javascript
// If index.html is at root, use:
const wasmModule = await import('./crypto_core/pkg/crypto_core.js');
```

### QR Code Not Showing

**Cause:** CDN libraries blocked or not loading.

**Fix:** The demo has fallback QR generation via API services. Check browser console for errors.

### "Module not found" in Browser Console

**Cause:** WASM module not built or not uploaded.

**Fix:** 
1. Build locally: `make build-wasm`
2. Upload the entire `crypto_core/pkg/` folder

---

## File Checklist

Before deploying, ensure you have:

- [ ] `index.html` (renamed from `wasm_browser_example.html`)
- [ ] `assets/meow-decoder-logo.svg`
- [ ] `crypto_core/pkg/crypto_core.js`
- [ ] `crypto_core/pkg/crypto_core_bg.wasm`
- [ ] `crypto_core/pkg/crypto_core.d.ts`
- [ ] `crypto_core/pkg/package.json`
- [ ] Paths updated in HTML to use `./` instead of `../`
- [ ] Flask app configured with WASM MIME type

---

## Free Tier Limitations

PythonAnywhere free tier:
- ✅ Serves static files fine
- ✅ WASM works (it's just a static file)
- ⚠️ Limited to `yourusername.pythonanywhere.com` domain
- ⚠️ Apps sleep after inactivity (first load may be slow)
- ✅ HTTPS included

---

## Quick Deploy Script

Run this locally to prepare files for upload:

```bash
#!/bin/bash
# prepare_pythonanywhere.sh

mkdir -p pythonanywhere-deploy/crypto_core/pkg
mkdir -p pythonanywhere-deploy/assets

# Copy and rename HTML
cp examples/wasm_browser_example.html pythonanywhere-deploy/index.html

# Fix paths in the HTML
sed -i 's|\.\./crypto_core/pkg|./crypto_core/pkg|g' pythonanywhere-deploy/index.html
sed -i 's|\.\./assets|./assets|g' pythonanywhere-deploy/index.html

# Copy WASM package
cp -r crypto_core/pkg/* pythonanywhere-deploy/crypto_core/pkg/

# Copy assets
cp -r assets/* pythonanywhere-deploy/assets/

echo "Files ready in pythonanywhere-deploy/"
echo "Upload this folder to PythonAnywhere"
```

---

## Example URLs

After deployment, your demo will be at:
- **Main page:** `https://yourusername.pythonanywhere.com/`
- **Health check:** `https://yourusername.pythonanywhere.com/health`

---

**🐾 Happy hosting! 😸**
