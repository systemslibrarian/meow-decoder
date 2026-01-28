#!/bin/bash
set -e

echo "📦 Committing changes..."
cd /workspaces/meow-decoder

git add -A
git commit -m "fix: update workflows and add ci script - ready for testing"

echo "🚀 Pushing to GitHub..."
git push origin yubikey-integration

echo "✅ Changes synced to GitHub!"
echo ""
echo "Current branch: yubikey-integration"
echo "Ready for next work..."
