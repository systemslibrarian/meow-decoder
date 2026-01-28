#!/bin/bash
set -e

echo "📦 Checking status..."
git status

echo ""
echo "📦 Staging changes..."
git add -A

echo "💾 Committing..."
git commit -m "ci: run and push ci script results" || echo "Nothing new to commit"

echo "🚀 Force pushing..."
git push -f origin main

echo "✅ Changes force pushed to GitHub!"
