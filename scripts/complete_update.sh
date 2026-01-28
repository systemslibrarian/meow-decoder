#!/bin/bash
set -e

echo "📦 Staging changes..."
git add .

echo "💾 Committing changes..."
# We use || true to allow the script to continue if there's nothing to commit
git commit -m "chore: consolidate security documentation and fix CI coverage thresholds" || true

echo "🚀 Pushing branch yubikey-integration..."
git push origin yubikey-integration

echo "twisted_rightwards_arrows Merging into main..."
git checkout main
git merge yubikey-integration

echo "🚀 Pushing main..."
git push origin main

echo "✅ Update complete!"
