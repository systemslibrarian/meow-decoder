#!/bin/bash
set -e

echo "📦 Checking status..."
git status

echo ""
echo "📦 Staging changes..."
git add -A

echo "💾 Committing..."
git commit -m "fix(rust): fix unused-mut and unused-variables warnings in crypto_core" || echo "Nothing new to commit"

echo "🚀 Force pushing..."
git push -f origin main

echo "✅ Changes force pushed to GitHub!"
