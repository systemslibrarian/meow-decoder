#!/usr/bin/env bash
set -euo pipefail

echo "📦 Fetching latest..."
git fetch origin main

echo ""
echo "📦 Current status:"
git status --short

echo ""
echo "📦 Staging everything..."
git add -A || echo "⚠️ git add -A had non-zero exit (but continuing)"

# Force-add specific patterns if agent is being picky
git add tests/ *.md target/ 2>/dev/null || true

echo ""
echo "📦 After staging:"
git status --short

if git diff --cached --quiet; then
  if ! git diff --quiet; then
    echo "⚠️ Files are modified but NOTHING staged! Agent likely failed to write changes to disk."
    echo "   Try manual: git add -A && git commit -m 'Manual fix'"
    echo "   Or rebuild Codespace / switch terminal to bash"
    exit 1
  else
    echo "✅ Clean working tree – no changes to commit."
    exit 0
  fi
fi

msg="${1:-"Fixed crypto tests/backend + added test_crypto.py + docs"}"
echo "💾 Committing: $msg"
git commit -m "$msg" || { echo "❌ Commit failed"; exit 1; }

echo "🚀 Pushing (safe force-with-lease)..."
git push --force-with-lease origin main && echo "🎉 Pushed!" || {
  echo "⚠️ Push failed – remote probably ahead."
  echo "   Try: git pull --rebase && ./commit-and-push.sh '$msg'"
  exit 1
}