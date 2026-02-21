# 😻 Meow Decoder Web Demo

A minimal Flask web interface for Meow Decoder featuring **Cat Mode** as a flagship demonstration of steganographic QR code camouflage.

## Features

- **🔒 Encode Files**: Upload any file (up to 8 MB) and convert to animated GIF
- **🔓 Decode GIFs**: Recover original files from Meow Decoder GIFs
- **😻 Cat Mode**: Flagship feature that camouflages QR codes in photographic cat images
- **⚠️ Duress Mode**: Dual-password plausible deniability
- **📊 Fountain Codes**: Configurable redundancy for frame loss tolerance
- **🔐 AES-256-GCM**: Military-grade encryption with Argon2id key derivation

## Quick Start (Local Development)

### Prerequisites

- Python 3.10+
- System dependencies for pyzbar:
  - **Ubuntu/Debian**: `sudo apt-get install libzbar0`
  - **macOS**: `brew install zbar`
  - **Alpine Linux**: `apk add zbar`

### Installation

1. **Clone the repository** (if not already done):
   ```bash
   cd /workspaces/meow-decoder
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r web_demo/requirements.txt
   pip install -r requirements.txt  # Core meow_decoder dependencies
   ```

3. **Run the Flask app**:
   ```bash
   cd web_demo
   python app.py
   ```

4. **Open in browser**:
   ```
   http://localhost:5000
   ```

## Codespace Quickstart

If you're running in a GitHub Codespace:

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r web_demo/requirements.txt

# Run the app
cd web_demo
python app.py
```

The Codespace will automatically forward port 5000, and you'll get a notification with a clickable URL.

## PythonAnywhere Deployment

### Step 1: Upload Code

1. Sign up for a free account at [PythonAnywhere](https://www.pythonanywhere.com)
2. Open a Bash console and clone the repository:
   ```bash
   git clone https://github.com/systemslibrarian/meow-decoder.git
   cd meow-decoder
   ```

### Step 2: Create Virtual Environment

```bash
mkvirtualenv meow-decoder --python=python3.10
workon meow-decoder

# Install dependencies
pip install -r requirements.txt
pip install -r web_demo/requirements.txt
```

### Step 3: Configure Web App

1. Go to **Web** tab in PythonAnywhere dashboard
2. Click **Add a new web app**
3. Choose **Manual configuration** (not Flask wizard)
4. Select **Python 3.10**

### Step 4: Edit WSGI Configuration

Click on the WSGI configuration file link and replace contents with:

```python
import sys
import os

# Add project directory to path
project_home = '/home/YOUR_USERNAME/meow-decoder'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Add web_demo directory to path
web_demo_dir = os.path.join(project_home, 'web_demo')
if web_demo_dir not in sys.path:
    sys.path.insert(0, web_demo_dir)

# Import Flask app
from app import app as application
```

**Replace `YOUR_USERNAME`** with your PythonAnywhere username.

### Step 5: Configure Virtualenv

In the Web tab, scroll to **Virtualenv** section and enter:
```
/home/YOUR_USERNAME/.virtualenvs/meow-decoder
```

### Step 6: Create Instance Directory

```bash
cd ~/meow-decoder/web_demo
mkdir -p instance/uploads instance/outputs
chmod 755 instance
```

### Step 7: Reload and Test

1. Click the **Reload** button in the Web tab
2. Visit your app at `https://YOUR_USERNAME.pythonanywhere.com`

## Configuration

### File Size Limit

Default: **50 MB** upload limit (set in `app.py` line 30), with an **8 MB** limit for encoding operations (enforced at `app.py` line 130).

To change the upload limit:
```python
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
```

### Allowed File Extensions

Default: `txt, pdf, png, jpg, jpeg, gif, bin, zip, doc, docx`

Edit in `app.py` line 43:
```python
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bin', 'zip'}
```

### File Cleanup

Files older than **30 minutes** are automatically deleted.

To change, edit `app.py` line 50:
```python
cleanup_old_files(max_age_minutes=60)  # 1 hour
```

### Disable Modes

To disable Schrödinger or Duress modes server-side, edit `templates/encode.html` and remove the corresponding `<option>` tags from the mode selector dropdown.

## Cat Mode 😻

Cat Mode is the **flagship feature** of this demo. When enabled:

1. **Encoder** uses bundled cat carrier images (`assets/demo_logo_eyes.gif`)
2. **QR codes** are embedded steganographically in photographic cat images
3. **Output uses APNG** (lossless animated PNG) — GIF palette quantization destroys LSB stego data
4. **Decoder** automatically detects and extracts QR codes from cat camouflage via LSB extraction fallback
5. **UI** displays Cat Mode badge (😻) on encoded files

### How Cat Mode Works

- **Steganography Level**: Defaults to level 2 (balanced visibility/capacity)
- **Carrier Images**: Bundled cat photos from `assets/` directory
- **Output Format**: APNG (`.png`) — lossless pixel preservation for stego fidelity
- **Redundancy**: 2.5× fountain code redundancy (compensates for any stego channel noise)
- **Plausible Deniability**: QR codes look like cat photos at casual inspection
- **Scanning**: Decoder auto-detects stego mode and extracts LSBs before QR scanning

### Technical Details

- **Why APNG, not GIF?** GIF uses 256-color palette quantization which corrupts LSB-embedded data. APNG is lossless, preserving all embedded pixel values through save/load cycles.
- **Stego Extraction Fallback**: `decode_gif.py` first tries direct QR scanning. If no QR codes are found (stego frames look like photos), it automatically tries LSB extraction at depths 2, 1, and 3.
- **Frame MAC Tracking**: Original GIF/APNG frame indices are preserved through extraction so per-frame MAC verification uses the correct index.

### Limitations

- Cat Mode is **cosmetic camouflage** (not forensic-proof steganography)
- Output is APNG format (`.png`), not GIF — some viewers may not animate APNG files
- Best used for aesthetic purposes and casual plausible deniability

## Security Notes

### Demo Environment Warning

This is a **demonstration instance**. The UI displays a banner warning:

> ⚠️ **Demo Environment Only**
> This is a demonstration instance. Do not upload sensitive files.
> Files are automatically deleted after 30 minutes.

For production use:

1. **Deploy on trusted infrastructure** (your own server, not public host)
2. **Use HTTPS** (mandatory for password security)
3. **Implement authentication** (add user accounts)
4. **Audit logs** (track who encodes/decodes what)
5. **Rate limiting** (prevent abuse)

### Uniform Error Messages

Decoding errors return **uniform messages** that don't reveal:
- Whether the password was incorrect
- Whether duress mode was involved
- Whether the file was corrupted

This prevents timing attacks and distinguishers that could compromise plausible deniability.

### Password Handling

- Passwords are **never logged or stored**
- Argon2id key derivation runs on server (intentional: prevents weak client devices)
- Use **strong, unique passwords** (20+ characters recommended)

## Troubleshooting

### "No module named 'pyzbar'"

Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install libzbar0

# macOS
brew install zbar

# Alpine Linux
apk add zbar
```

### "Permission denied" on instance/ directory

```bash
chmod 755 web_demo/instance
chmod 755 web_demo/instance/uploads
chmod 755 web_demo/instance/outputs
```

### "413 Request Entity Too Large"

File exceeds 8 MB limit. Either:
1. Compress the file before encoding
2. Increase `MAX_CONTENT_LENGTH` in `app.py` (not recommended for public demos)

### Cat Mode not working

Verify bundled carrier exists:
```bash
ls -lh assets/demo_logo_eyes.gif
```

If missing, clone the full repository (carrier images may not be in minimal distributions).

### Decoding fails with "uniform error"

Possible causes:
- Wrong password
- Corrupted GIF file
- Not a Meow Decoder GIF (must be created by this tool)
- Cat Mode camouflage too aggressive (try re-encoding with lower stego level)

## Development

### Project Structure

```
web_demo/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── wsgi.py                     # PythonAnywhere WSGI file
├── start.sh                    # Startup script
├── README.md                   # This file
├── test_all_modes.py           # Full test suite (20 tests)
├── test_cat_mode.py            # Cat mode tests
├── static/                     # Static assets (WASM, JS, CSS)
├── templates/
│   ├── base.html              # Base template with navigation
│   ├── cat_mode.html          # Cat mode page
│   ├── decode.html            # Decoding page
│   ├── decode_result.html     # Decoding result page
│   ├── demo.html              # Demo page
│   ├── encode.html            # Encoding page
│   ├── modes.html             # Mode selection page
│   ├── result.html            # Encoding result page
│   ├── schrodinger.html       # Schrödinger mode page
│   └── webcam.html            # Webcam scanner page
└── instance/                   # Runtime data (gitignored)
    ├── uploads/               # Uploaded files (temp)
    └── outputs/               # Generated GIFs (temp)
```

### Adding New Modes

1. Add mode to `templates/encode.html` dropdown
2. Update `encode_page()` in `app.py` to handle new mode
3. Add mode-specific configuration logic
4. Add mode badge CSS in `templates/base.html`
5. Update mode emoji in `get_mode_emoji()` function

### Testing Locally

```bash
# Encode a test file
cd web_demo
echo "Hello, World!" > test.txt

# Start Flask app
python app.py

# Visit http://localhost:5000 and:
# 1. Upload test.txt
# 2. Select Cat Mode
# 3. Set password "test123"
# 4. Click Encode
# 5. Download resulting GIF
# 6. Go to Decode page
# 7. Upload GIF, enter password "test123"
# 8. Verify recovered file matches original
```

## Performance

### Encoding Times (approximate)

- **1 KB file**: ~1 second
- **100 KB file**: ~3 seconds
- **1 MB file**: ~10 seconds
- **8 MB file**: ~60 seconds

Times vary based on:
- Argon2id key derivation (20 iterations, 512 MiB memory)
- Fountain encoding redundancy
- QR frame generation
- Server CPU speed

### Memory Usage

- **Peak memory**: ~200-500 MB per encoding operation
- **Baseline**: ~50 MB (Flask + dependencies)

For high-traffic deployments, consider:
- Nginx reverse proxy with request queuing
- Gunicorn with multiple workers
- Redis task queue (Celery) for async encoding

## License

Meow Decoder is open source (see main project LICENSE file).

## Links

- **Main Repository**: https://github.com/systemslibrarian/meow-decoder
- **Documentation**: https://github.com/systemslibrarian/meow-decoder/blob/main/docs/
- **Quick Start Guide**: https://github.com/systemslibrarian/meow-decoder/blob/main/QUICKSTART.md

## Support

For issues specific to the web demo, please open an issue on GitHub with the `web-demo` label.

For general Meow Decoder questions, see the main project README.

---

**🐱 Made with <3 and cats by the Meow Decoder team**
