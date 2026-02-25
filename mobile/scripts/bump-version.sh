#!/usr/bin/env bash
# bump-version.sh — Update the app version in ALL source-of-truth locations.
#
# Usage:
#   ./scripts/bump-version.sh 3.3.0
#
# Updates:
#   1. package.json          → "version": "X.Y.Z"
#   2. src/constants/config.ts → APP_VERSION = 'X.Y.Z'
#   3. ios/MeowCapture/Info.plist → CFBundleShortVersionString
#
# Verifies all three files were updated and prints a summary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 3.3.0"
  exit 1
fi

NEW_VERSION="$1"

# Validate semver format (X.Y.Z)
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: Version must be semver (X.Y.Z), got: $NEW_VERSION"
  exit 1
fi

echo "Bumping version to $NEW_VERSION..."

# 1. package.json
PKG="$ROOT_DIR/package.json"
if [[ -f "$PKG" ]]; then
  sed -i "s/\"version\": \"[0-9]*\.[0-9]*\.[0-9]*\"/\"version\": \"$NEW_VERSION\"/" "$PKG"
  echo "  ✓ package.json"
else
  echo "  ✗ package.json NOT FOUND"
  exit 1
fi

# 2. src/constants/config.ts
CONFIG="$ROOT_DIR/src/constants/config.ts"
if [[ -f "$CONFIG" ]]; then
  sed -i "s/APP_VERSION = '[0-9]*\.[0-9]*\.[0-9]*'/APP_VERSION = '$NEW_VERSION'/" "$CONFIG"
  echo "  ✓ src/constants/config.ts"
else
  echo "  ✗ src/constants/config.ts NOT FOUND"
  exit 1
fi

# 3. ios/MeowCapture/Info.plist — CFBundleShortVersionString
PLIST="$ROOT_DIR/ios/MeowCapture/Info.plist"
if [[ -f "$PLIST" ]]; then
  # Replace the <string> immediately after CFBundleShortVersionString
  sed -i "/<key>CFBundleShortVersionString<\/key>/{n;s/<string>[0-9]*\.[0-9]*\.[0-9]*<\/string>/<string>$NEW_VERSION<\/string>/;}" "$PLIST"
  echo "  ✓ ios/MeowCapture/Info.plist"
else
  echo "  ✗ ios/MeowCapture/Info.plist NOT FOUND"
  exit 1
fi

# Verify all sources agree
echo ""
echo "Verification:"
grep -o "\"version\": \"$NEW_VERSION\"" "$PKG" && echo "  package.json OK" || echo "  package.json MISMATCH"
grep -o "APP_VERSION = '$NEW_VERSION'" "$CONFIG" && echo "  config.ts OK" || echo "  config.ts MISMATCH"
grep -o "<string>$NEW_VERSION</string>" "$PLIST" | head -1 && echo "  Info.plist OK" || echo "  Info.plist MISMATCH"

echo ""
echo "Done. Remember to commit: git add -A && git commit -m 'chore: bump version to $NEW_VERSION'"
