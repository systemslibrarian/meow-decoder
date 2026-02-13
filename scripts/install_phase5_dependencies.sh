#!/bin/bash
# Install dependencies for Phase 5 Week 1 tasks
# Run with: bash scripts/install_phase5_dependencies.sh

set -e  # Exit on error

echo "════════════════════════════════════════════════════════════════════════════"
echo "🔧 Installing Phase 5 Week 1 Dependencies"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

# Detect OS
if [ -f /etc/alpine-release ]; then
    OS="alpine"
elif [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
elif [ "$(uname)" == "Darwin" ]; then
    OS="macos"
else
    OS="unknown"
fi

echo "📋 Detected OS: $OS"
echo ""

# Check if we need sudo (not running as root)
SUDO=""
if [ "$EUID" -ne 0 ] && command -v sudo &> /dev/null; then
    SUDO="sudo"
    echo "⚠️  Not running as root, will use sudo for system packages"
    echo ""
fi

# Install system dependencies based on OS
case "$OS" in
    alpine)
        echo "📦 Installing Alpine Linux packages..."
        $SUDO apk update
        $SUDO apk add --no-cache \
            ffmpeg \
            build-base \
            cairo-dev \
            pango-dev \
            jpeg-dev \
            giflib-dev \
            librsvg-dev \
            pixman-dev \
            pkgconfig \
            python3 \
            py3-pip
        ;;
    
    debian)
        echo "📦 Installing Debian/Ubuntu packages..."
        sudo apt-get update
        sudo apt-get install -y \
            ffmpeg \
            build-essential \
            libcairo2-dev \
            libpango1.0-dev \
            libjpeg-dev \
            libgif-dev \
            librsvg2-dev \
            libpixman-1-dev \
            pkg-config
        ;;
    
    macos)
        echo "📦 Installing macOS packages with Homebrew..."
        brew install ffmpeg pkg-config cairo pango libpng jpeg giflib librsvg pixman
        ;;
    
    *)
        echo "❌ Unknown OS - please install dependencies manually:"
        echo "   - ffmpeg"
        echo "   - cairo, pango, jpeg, giflib, librsvg (development libraries)"
        echo "   - build tools (gcc, make, pkg-config)"
        exit 1
        ;;
esac

echo ""
echo "✅ System dependencies installed"
echo ""

# Reinstall canvas (needs to rebuild native bindings)
echo "📦 Installing/rebuilding node-canvas..."
cd /workspaces/meow-decoder
npm install canvas --build-from-source

echo ""
echo "📦 Installing Playwright browsers..."
if [ "$OS" = "alpine" ]; then
    # Alpine: Skip browser installation (not officially supported)
    echo "⚠️  Alpine detected: Skipping Playwright browser installation"
    echo "   Note: Cross-browser tests will be skipped on Alpine"
    echo "   For full testing, use Ubuntu/Debian or run in CI"
else
    # Other OS: Install with system dependencies
    npx playwright install chromium firefox webkit --with-deps
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "✅ All dependencies installed successfully!"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Generate golden videos:  npm run generate-golden-videos"
echo "  2. Generate error tests:    npm run generate-error-tests"
echo "  3. Run cross-browser tests: npm run test:browsers"
echo ""
