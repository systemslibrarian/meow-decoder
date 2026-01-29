#!/bin/bash
set -euo pipefail

echo "📦 Checking status..."
git status

echo ""
echo "📦 Staging changes..."
git add -A

# If no changes staged, exit cleanly
if git diff --cached --quiet; then
  echo "✅ No changes to commit."
  exit 0
fi

msg="${1:-Fixed issues and updated files}"

echo "💾 Committing..."
git commit -m "$msg"

echo "🚀 Pushing..."
# Safer than -f: only forces if remote hasn't advanced unexpectedly
git push --force-with-lease origin main

echo "✅ Pushed to GitHub!"
