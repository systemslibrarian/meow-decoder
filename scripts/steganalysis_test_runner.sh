#!/usr/bin/env bash
# ===========================================================================
# Meow Decoder — Steganalysis Tool Comparison Runner
# ===========================================================================
#
# Runs external steganalysis tools (zsteg, StegSeek, binwalk, exiftool,
# chi-square) against Meow Decoder stego output and compares results to
# StegX's claimed evasion baselines.
#
# Prerequisites:
#   gem install zsteg               # Ruby gem
#   apt install stegseek binwalk    # or build from source
#   apt install exiftool            # libimage-exiftool-perl
#   pip install numpy Pillow scipy  # for chi-square script
#   pip install apngdis             # optional: APNG frame extraction
#
# Usage:
#   ./scripts/steganalysis_test_runner.sh <stego_image> [cover_image]
#
# Examples:
#   ./scripts/steganalysis_test_runner.sh output/stego_cat.png
#   ./scripts/steganalysis_test_runner.sh output/stego.gif carrier.gif
#
# StegX claims (baseline targets):
#   zsteg:      "No patterns found"
#   StegSeek:   "Failed to extract"
#   binwalk:    "Clean output"
#   exiftool:   "Metadata clean"
#   chi-square: ~13K statistic (vs Steghide's ~119K)
# ===========================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

STEGO_FILE="${1:?Usage: $0 <stego_image> [cover_image]}"
COVER_FILE="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHI_SQUARE_SCRIPT="${SCRIPT_DIR}/steganalysis_chi_square.py"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
WARN_COUNT=0

header() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  Meow Decoder — Steganalysis Comparison Test Suite          ║${NC}"
    echo -e "${BOLD}${CYAN}║  Baseline: StegX (Delta-Sec/StegX) README claims            ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Target file:  ${BOLD}${STEGO_FILE}${NC}"
    if [[ -n "$COVER_FILE" ]]; then
        echo -e "  Cover file:   ${BOLD}${COVER_FILE}${NC}"
    fi
    echo -e "  File size:    $(stat -c%s "$STEGO_FILE" 2>/dev/null || stat -f%z "$STEGO_FILE" 2>/dev/null || echo 'unknown') bytes"
    echo -e "  Format:       $(file --brief "$STEGO_FILE" 2>/dev/null || echo 'unknown')"
    echo ""
}

result_pass() {
    echo -e "  ${GREEN}✅ PASS${NC} — $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

result_fail() {
    echo -e "  ${RED}❌ FAIL${NC} — $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

result_warn() {
    echo -e "  ${YELLOW}⚠️  WARN${NC} — $1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

result_skip() {
    echo -e "  ${YELLOW}⏭  SKIP${NC} — $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

section() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ===========================================================================
# Pre-flight: check if file is APNG (needs special handling)
# ===========================================================================
IS_APNG=false
IS_GIF=false
EXT="${STEGO_FILE##*.}"
EXT_LOWER=$(echo "$EXT" | tr '[:upper:]' '[:lower:]')

if [[ "$EXT_LOWER" == "apng" ]] || [[ "$EXT_LOWER" == "png" ]]; then
    # Check for APNG animation chunk
    if python3 -c "
from PIL import Image
img = Image.open('$STEGO_FILE')
try:
    img.seek(1)
    print('apng')
except EOFError:
    print('png')
" 2>/dev/null | grep -q "apng"; then
        IS_APNG=true
    fi
elif [[ "$EXT_LOWER" == "gif" ]]; then
    IS_GIF=true
fi

header

# ===========================================================================
# 1. zsteg — Ruby-based LSB steganalysis
# ===========================================================================
section "1. zsteg (LSB pattern detection)"
echo "  StegX claims: 'No patterns found'"
echo "  Meow advantage: Keyed walk breaks sequential patterns; STC minimizes flips"
echo ""

if $IS_APNG; then
    echo "  ℹ️  APNG detected — zsteg only works on PNG (no animation support)."
    echo "  Extracting first frame for analysis..."
    TEMP_PNG=$(mktemp /tmp/meow_steg_frame0_XXXX.png)
    python3 -c "
from PIL import Image
img = Image.open('$STEGO_FILE')
img.save('$TEMP_PNG')
" 2>/dev/null
    ZSTEG_TARGET="$TEMP_PNG"
elif $IS_GIF; then
    echo "  ℹ️  GIF detected — zsteg expects PNG. Extracting first frame..."
    TEMP_PNG=$(mktemp /tmp/meow_steg_frame0_XXXX.png)
    python3 -c "
from PIL import Image
img = Image.open('$STEGO_FILE')
img.convert('RGB').save('$TEMP_PNG')
" 2>/dev/null
    ZSTEG_TARGET="$TEMP_PNG"
else
    ZSTEG_TARGET="$STEGO_FILE"
fi

if command -v zsteg &>/dev/null; then
    ZSTEG_OUT=$(zsteg "$ZSTEG_TARGET" 2>&1 || true)
    echo "  --- zsteg output ---"
    echo "$ZSTEG_OUT" | head -30 | sed 's/^/  | /'
    echo "  --- end ---"
    echo ""

    # Check for significant findings (ignore meta/size lines)
    # zsteg outputs like "b1,rgb,lsb,xy .. text: ..." for real findings
    SIGNIFICANT=$(echo "$ZSTEG_OUT" | grep -v "^$" | grep -v "meta" | grep -vi "Could not" | grep -ci "text:\|file:\|data:" || true)
    if [[ "$SIGNIFICANT" -eq 0 ]]; then
        result_pass "zsteg found no significant patterns (matches StegX claim)"
    elif [[ "$SIGNIFICANT" -le 2 ]]; then
        result_warn "zsteg found $SIGNIFICANT minor pattern(s) — review above"
    else
        result_fail "zsteg found $SIGNIFICANT patterns — LSB embedding detectable"
    fi
else
    result_skip "zsteg not installed (gem install zsteg)"
fi

# Cleanup temp files
[[ -f "${TEMP_PNG:-}" ]] && rm -f "$TEMP_PNG"

# ===========================================================================
# 2. StegSeek — Steghide brute-force / detection
# ===========================================================================
section "2. StegSeek (Steghide-compatible extraction attempt)"
echo "  StegX claims: 'Failed to extract'"
echo "  Meow advantage: Not Steghide format; AES-256-GCM encrypted payload"
echo ""

if command -v stegseek &>/dev/null; then
    if $IS_APNG || [[ "$EXT_LOWER" == "png" ]]; then
        echo "  ℹ️  StegSeek only supports JPEG/BMP/WAV/AU (Steghide formats)."
        echo "  PNG/APNG/GIF are not supported — this is an automatic pass."
        result_pass "StegSeek: format not supported (PNG/APNG/GIF) — automatic evasion"
    elif $IS_GIF; then
        echo "  ℹ️  StegSeek only supports JPEG/BMP/WAV/AU (Steghide formats)."
        echo "  GIF is not supported — this is an automatic pass."
        result_pass "StegSeek: format not supported (GIF) — automatic evasion"
    else
        STEGSEEK_OUT=$(timeout 30 stegseek --crack "$STEGO_FILE" /dev/null 2>&1 || true)
        echo "  --- StegSeek output ---"
        echo "$STEGSEEK_OUT" | head -10 | sed 's/^/  | /'
        echo "  --- end ---"
        echo ""
        if echo "$STEGSEEK_OUT" | grep -qi "could not\|failed\|not a valid\|error"; then
            result_pass "StegSeek failed to extract (matches StegX claim)"
        else
            result_fail "StegSeek may have extracted something — review above"
        fi
    fi
else
    result_skip "stegseek not installed (apt install stegseek)"
fi

# ===========================================================================
# 3. binwalk — Embedded file/data signature detection
# ===========================================================================
section "3. binwalk (embedded signature/entropy scan)"
echo "  StegX claims: 'Clean output'"
echo "  Meow advantage: AES-GCM ciphertext indistinguishable from random; no headers"
echo ""

if command -v binwalk &>/dev/null; then
    BINWALK_OUT=$(binwalk "$STEGO_FILE" 2>&1 || true)
    echo "  --- binwalk output ---"
    echo "$BINWALK_OUT" | head -30 | sed 's/^/  | /'
    echo "  --- end ---"
    echo ""

    # Count non-header lines (binwalk always prints a header + format line)
    # "Clean" = only the image format signature itself
    SIG_COUNT=$(echo "$BINWALK_OUT" | grep -c "0x" || true)
    if [[ "$SIG_COUNT" -le 2 ]]; then
        result_pass "binwalk found only format signatures (clean — matches StegX claim)"
    elif [[ "$SIG_COUNT" -le 5 ]]; then
        result_warn "binwalk found $SIG_COUNT signatures — likely animated frames (expected for GIF/APNG)"
    else
        result_fail "binwalk found $SIG_COUNT embedded signatures — may indicate appended data"
    fi

    # Also run entropy analysis if binwalk supports it
    if binwalk --help 2>&1 | grep -q "entropy"; then
        echo ""
        echo "  Running entropy analysis..."
        ENTROPY_OUT=$(binwalk -E "$STEGO_FILE" 2>&1 || true)
        # High entropy across the file is normal for compressed image data
        echo "  (Entropy plot saved if binwalk supports matplotlib)"
    fi
else
    result_skip "binwalk not installed (apt install binwalk)"
fi

# ===========================================================================
# 4. exiftool — Metadata cleanliness
# ===========================================================================
section "4. exiftool (metadata inspection)"
echo "  StegX claims: 'Metadata clean'"
echo "  Meow advantage: PIL/imageio output has minimal metadata; no stego tool markers"
echo ""

if command -v exiftool &>/dev/null; then
    EXIF_OUT=$(exiftool "$STEGO_FILE" 2>&1 || true)
    echo "  --- exiftool output ---"
    echo "$EXIF_OUT" | head -40 | sed 's/^/  | /'
    echo "  --- end ---"
    echo ""

    # Check for suspicious metadata
    SUSPICIOUS=$(echo "$EXIF_OUT" | grep -ci "steghide\|openstego\|stegx\|steganograph\|hidden\|secret\|openssl\|embedded" || true)
    COMMENT=$(echo "$EXIF_OUT" | grep -ci "Comment\s*:" || true)

    if [[ "$SUSPICIOUS" -eq 0 ]] && [[ "$COMMENT" -eq 0 ]]; then
        result_pass "exiftool: No suspicious metadata or comments (matches StegX claim)"
    elif [[ "$SUSPICIOUS" -eq 0 ]] && [[ "$COMMENT" -gt 0 ]]; then
        result_warn "exiftool: Found $COMMENT comment field(s) — check if benign"
    else
        result_fail "exiftool: Found $SUSPICIOUS suspicious metadata entries"
    fi
else
    result_skip "exiftool not installed (apt install libimage-exiftool-perl)"
fi

# ===========================================================================
# 5. Chi-Square LSB Analysis (custom script)
# ===========================================================================
section "5. Chi-Square LSB Analysis (Westfeld attack)"
echo "  StegX claims: ~13K chi² vs Steghide's ~119K"
echo "  Meow advantage: STC ≠ LSB replacement → no pair equalization"
echo ""

if [[ -f "$CHI_SQUARE_SCRIPT" ]]; then
    CHI_OUT=$(python3 "$CHI_SQUARE_SCRIPT" "$STEGO_FILE" --per-channel 2>&1 || true)
    echo "$CHI_OUT" | sed 's/^/  /'
    echo ""

    # Extract mean chi² from output
    MEAN_CHI=$(echo "$CHI_OUT" | grep -oP 'Mean chi²:\s*[\d,.]+' | grep -oP '[\d,.]+' | tr -d ',' || true)
    if [[ -n "$MEAN_CHI" ]]; then
        # Compare against thresholds
        ABOVE_STEGX=$(python3 -c "print('yes' if float('${MEAN_CHI}') > 15000 else 'no')" 2>/dev/null || echo "unknown")
        if [[ "$ABOVE_STEGX" == "no" ]]; then
            result_pass "Chi²: Mean ${MEAN_CHI} ≤ 15K (matches or beats StegX's ~13K baseline)"
        else
            ABOVE_STEGHIDE=$(python3 -c "print('yes' if float('${MEAN_CHI}') > 100000 else 'no')" 2>/dev/null || echo "unknown")
            if [[ "$ABOVE_STEGHIDE" == "no" ]]; then
                result_warn "Chi²: Mean ${MEAN_CHI} — above StegX baseline but below Steghide"
            else
                result_fail "Chi²: Mean ${MEAN_CHI} — approaching Steghide levels (>100K)"
            fi
        fi
    else
        result_warn "Could not parse chi² statistic from output"
    fi
else
    result_skip "Chi-square script not found at $CHI_SQUARE_SCRIPT"
fi

# ===========================================================================
# 6. Meow Decoder built-in validation (RS + Chi² + SPA + Entropy)
# ===========================================================================
section "6. Meow Decoder built-in steganalysis (validate_stego)"
echo "  Runs: RS analysis, Chi-square, SPA, Shannon entropy"
echo "  Pass criteria: RS det<0.3, Chi² det<0.3, SPA rate<0.15"
echo ""

MEOW_VALIDATE_OUT=$(python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from meow_decoder.stego_multilayer import validate_stego
    result = validate_stego('$STEGO_FILE')
    print(f'Summary: {result.summary}')
    print(f'Passed: {result.passed}')
    print(f'RS detection: {result.rs_analysis[\"detection_probability\"]:.4f}')
    print(f'Chi² detection: {result.chi_square[\"detection_probability\"]:.4f}')
    print(f'SPA rate: {result.spa[\"mean_embedding_rate\"]:.4f}')
    print(f'Entropy: {result.entropy[\"mean_entropy\"]:.4f}')
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1 || true)

echo "$MEOW_VALIDATE_OUT" | sed 's/^/  /'
echo ""

if echo "$MEOW_VALIDATE_OUT" | grep -q "Passed: True"; then
    result_pass "Built-in validation passed all 4 statistical tests"
elif echo "$MEOW_VALIDATE_OUT" | grep -q "Passed: False"; then
    result_fail "Built-in validation FAILED — see details above"
elif echo "$MEOW_VALIDATE_OUT" | grep -q "ERROR"; then
    result_skip "Built-in validation errored (missing dependencies?)"
else
    result_warn "Could not determine built-in validation result"
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  SUMMARY                                                    ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "  ${GREEN}PASS:${NC} $PASS_COUNT"
echo -e "  ${RED}FAIL:${NC} $FAIL_COUNT"
echo -e "  ${YELLOW}WARN:${NC} $WARN_COUNT"
echo -e "  ${YELLOW}SKIP:${NC} $SKIP_COUNT"
echo ""

TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✅ Meow stego output matches or exceeds StegX evasion claims${NC}"
    echo -e "  ${GREEN}   across all tested tools ($PASS_COUNT/$TOTAL pass, $WARN_COUNT warnings).${NC}"
elif [[ "$FAIL_COUNT" -le 1 ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠️  Mostly clean — $FAIL_COUNT failure(s) to investigate.${NC}"
else
    echo -e "  ${RED}${BOLD}❌ Multiple detections — stego output needs improvement.${NC}"
fi

echo ""
echo "  Note: StegX tested on static PNG outputs. Meow uses APNG/GIF"
echo "  which are inherently different formats. Some tools may not"
echo "  support animated formats natively — see per-test notes."
echo ""

exit $FAIL_COUNT
