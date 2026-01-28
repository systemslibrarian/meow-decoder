#!/bin/bash
set -e

echo "📦 Checking status..."
git status

echo ""
echo "📦 Staging changes..."
git add -A

echo "💾 Committing..."
git commit -m "fix(rust): fix pyo3 signature mismatch and unused variables in meow_crypto_rs" || echo "Nothing new to commit"

echo "🚀 Force pushing..."
git push -f origin main

echo "✅ Changes force pushed to GitHub!"
