#!/bin/bash
set -e

echo "📦 Staging changes..."
git add .

echo "💾 Committing changes..."
# Allow empty if already committed
git commit -m "chore: consolidate security documentation and fix CI coverage thresholds" || true

echo "🔧 Ensuring we are on branch 'yubikey-integration'..."
# -B forces the branch to be created/reset to current HEAD
git checkout -B yubikey-integration

echo "🚀 Pushing branch yubikey-integration..."
git push -u origin yubikey-integration

echo "twisted_rightwards_arrows Switching to main..."
git checkout main
git pull origin main || true  # Sync if remote exists

echo "twisted_rightwards_arrows Merging yubikey-integration..."
git merge yubikey-integration

echo "🚀 Pushing main..."
git push origin main

echo "🔙 Returning to feature branch..."
git checkout yubikey-integration

echo "✅ Robust update complete!"
