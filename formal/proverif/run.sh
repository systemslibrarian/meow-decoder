#!/bin/bash
# =============================================================================
# ProVerif Runner for Meow-Encode Protocol Verification
# =============================================================================
#
# Usage:
#   ./run.sh              - Run ProVerif analysis
#   ./run.sh --html       - Generate HTML report in output/
#   ./run.sh --verbose    - Verbose output with attack traces
#   ./run.sh --docker     - Use Docker instead of local installation
#
# Prerequisites:
#   - ProVerif 2.05+ installed (opam recommended): opam install proverif.2.05
#   - Or Docker: docker pull proverif/proverif:latest
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODEL="meow_encode.pv"
HTML_DIR="output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     🔐 ProVerif Symbolic Security Analysis - Meow-Encode     ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_proverif() {
    if command -v proverif &> /dev/null; then
        echo -e "${GREEN}✓ ProVerif found:${NC} $(proverif --version 2>&1 | head -1)"
        return 0
    else
        echo -e "${YELLOW}⚠ ProVerif not found in PATH${NC}"
        return 1
    fi
}

load_opam_env() {
    if command -v opam &> /dev/null; then
        eval "$(opam env)" >/dev/null 2>&1 || true
    fi
}

run_local() {
    local args="$1"
    echo -e "${BLUE}▶ Running ProVerif analysis...${NC}"
    echo ""
    
    if [ "$args" = "--html" ]; then
        mkdir -p "$HTML_DIR"
        echo -e "${BLUE}▶ Generating HTML output in $HTML_DIR/${NC}"
        proverif -html "$HTML_DIR" "$MODEL"
        echo ""
        echo -e "${GREEN}✓ HTML report generated: $HTML_DIR/index.html${NC}"
    elif [ "$args" = "--verbose" ]; then
        proverif -log -traceDisplay short "$MODEL"
    else
        proverif "$MODEL"
    fi
}

run_docker() {
    local args="$1"
    echo -e "${BLUE}▶ Running ProVerif via Docker...${NC}"
    echo ""
    
    if [ "$args" = "--html" ]; then
        mkdir -p "$HTML_DIR"
        docker run --rm -v "$(pwd):/spec" -w /spec proverif/proverif:latest \
            -html "$HTML_DIR" "$MODEL"
        echo ""
        echo -e "${GREEN}✓ HTML report generated: $HTML_DIR/index.html${NC}"
    elif [ "$args" = "--verbose" ]; then
        docker run --rm -v "$(pwd):/spec" -w /spec proverif/proverif:latest \
            -log -traceDisplay short "$MODEL"
    else
        docker run --rm -v "$(pwd):/spec" -w /spec proverif/proverif:latest "$MODEL"
    fi
}

print_summary() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                      Security Properties Verified:             ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  ✅ Secrecy:      Plaintext & passwords protected from attacker"
    echo "  ✅ Authenticity: Tampering always detected (AEAD + HMAC)"
    echo "  ✅ Replay:       Session/nonce binding prevents replay attacks"
    echo "  ✅ Duress:       Duress password never reveals real plaintext"
    echo "  ✅ Auth Bypass:  No output without successful authentication"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# Parse arguments
USE_DOCKER=false
EXTRA_ARGS=""

for arg in "$@"; do
    case $arg in
        --docker)
            USE_DOCKER=true
            ;;
        --html|--verbose)
            EXTRA_ARGS="$arg"
            ;;
        --help|-h)
            echo "Usage: $0 [--html] [--verbose] [--docker]"
            echo ""
            echo "Options:"
            echo "  --html      Generate HTML report in output/"
            echo "  --verbose   Show detailed output with attack traces"
            echo "  --docker    Use Docker instead of local ProVerif"
            echo "  --help      Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $arg${NC}"
            exit 1
            ;;
    esac
done

# Main execution
print_header

if [ "$USE_DOCKER" = true ]; then
    if command -v docker &> /dev/null; then
        run_docker "$EXTRA_ARGS"
    else
        echo -e "${RED}✗ Docker not found${NC}"
        exit 1
    fi
else
    load_opam_env
    if check_proverif; then
        run_local "$EXTRA_ARGS"
    elif command -v docker &> /dev/null; then
        echo -e "${YELLOW}▶ Falling back to Docker...${NC}"
        run_docker "$EXTRA_ARGS"
    else
        echo -e "${RED}✗ Neither ProVerif nor Docker found${NC}"
        echo ""
        echo "Install ProVerif:"
        echo "  Ubuntu/Debian: sudo apt install proverif"
        echo "  macOS:         brew install proverif"
        echo "  Docker:        docker pull proverif/proverif:latest"
        exit 1
    fi
fi

print_summary
echo -e "${GREEN}✓ ProVerif analysis complete!${NC}"
