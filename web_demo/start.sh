#!/bin/bash
# 😻 Meow Decoder Web Demo - Quick Start Script

set -e  # Exit on error

echo "🐱 Meow Decoder Web Demo - Quick Start"
echo "======================================"
echo ""

# Check if we're in the right directory
if [ ! -f "app.py" ]; then
    echo "❌ Error: app.py not found"
    echo "   Please run this script from the web_demo/ directory"
    echo ""
    echo "   cd /workspaces/meow-decoder/web_demo"
    echo "   bash start.sh"
    exit 1
fi

# Check Python version
echo "🔍 Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Found: Python $PYTHON_VERSION"

# Check if dependencies are installed
echo ""
echo "📦 Checking dependencies..."

MISSING_DEPS=0

python3 -c "import flask" 2>/dev/null || {
    echo "   ❌ Flask not installed"
    MISSING_DEPS=1
}

python3 -c "import PIL" 2>/dev/null || {
    echo "   ❌ Pillow not installed"
    MISSING_DEPS=1
}

python3 -c "import qrcode" 2>/dev/null || {
    echo "   ❌ qrcode not installed"
    MISSING_DEPS=1
}

python3 -c "import cv2" 2>/dev/null || {
    echo "   ❌ opencv-python not installed"
    MISSING_DEPS=1
}

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo "⚠️  Missing dependencies detected!"
    echo ""
    read -p "   Install now? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "📥 Installing dependencies..."
        
        if pip install --break-system-packages -q -r requirements.txt; then
            echo "   ✅ Dependencies installed"
        else
            echo "   ❌ Installation failed"
            echo ""
            echo "   Try manually:"
            echo "   pip install -r requirements.txt"
            exit 1
        fi
    else
        echo ""
        echo "❌ Cannot continue without dependencies"
        echo "   Install manually and try again:"
        echo "   pip install -r requirements.txt"
        exit 1
    fi
fi

echo "   ✅ All dependencies present"

# Check for cat carrier
echo ""
echo "😻 Checking Cat Mode carrier..."
CAT_CARRIER="../assets/demo_logo_eyes.gif"

if [ -f "$CAT_CARRIER" ]; then
    echo "   ✅ Cat carrier found: $CAT_CARRIER"
else
    echo "   ⚠️  Cat carrier not found at: $CAT_CARRIER"
    echo "   Cat Mode will be disabled"
fi

# Create instance directories
echo ""
echo "📁 Setting up instance directories..."
mkdir -p instance/uploads instance/outputs
chmod 755 instance
echo "   ✅ Directories created"

# Check for test mode
echo ""
if [ "$MEOW_TEST_MODE" = "1" ]; then
    echo "⚡ TEST MODE ENABLED (fast Argon2id)"
    echo "   Key derivation: 32 MiB, 1 iteration (fast, not secure)"
else
    echo "🔒 PRODUCTION MODE (secure Argon2id)"
    echo "   Key derivation: 512 MiB, 20 iterations (slow, secure)"
    echo ""
    echo "   💡 Tip: Enable test mode for faster development:"
    echo "      export MEOW_TEST_MODE=1"
    echo "      bash start.sh"
fi

# Display startup message
echo ""
echo "======================================"
echo "🚀 Starting Flask development server"
echo "======================================"
echo ""
echo "   URL: http://localhost:5000"
echo ""
echo "   Features:"
echo "   - 😻 Cat Mode (flagship feature)"
echo "   - 🔒 Normal Mode (standard QR)"
echo "   - ⚠️ Duress Mode (dual-password)"
echo ""
echo "   Max file size: 8 MB"
echo "   Auto-cleanup: 30 minutes"
echo ""
echo "   Press Ctrl+C to stop"
echo ""
echo "======================================"
echo ""

# Start Flask app
python3 app.py
