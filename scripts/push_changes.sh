#!/bin/bash
set -e

echo "📦 Checking status..."
git status

echo ""
echo "📦 Staging changes..."
git add -A

echo "💾 Committing..."
git commit -m "fix: add crate-level allows for dead_code, unused_imports, unexpected_cfgs" || echo "Nothing new to commit"

echo "🚀 Force pushing..."
git push -f origin main

echo "✅ Changes force pushed to GitHub!"
