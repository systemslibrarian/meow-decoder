#!/bin/bash
set -e

echo "🧹 Cleaning up branches - keeping only main..."
echo ""

# Show current branches
echo "📋 Current branches:"
git branch -a
echo ""

# Switch to main
echo "🔄 Switching to main..."
git checkout main

# Delete local branches (except main)
echo ""
echo "🗑️  Deleting local branches..."
git branch -D yubikey-integration 2>/dev/null || echo "   (yubikey-integration not found locally)"
git branch -D copilot/chubby-wallaby 2>/dev/null || echo "   (copilot/chubby-wallaby not found locally)"

# Delete remote branches
echo ""
echo "🗑️  Deleting remote branches on GitHub..."
git push origin --delete yubikey-integration 2>/dev/null || echo "   (yubikey-integration not found on GitHub)"
git push origin --delete copilot/chubby-wallaby 2>/dev/null || echo "   (copilot/chubby-wallaby not found on GitHub)"

# Clean up local references to deleted remote branches
echo ""
echo "🧹 Cleaning local references..."
git remote prune origin

# Verify only main remains
echo ""
echo "✅ Remaining branches:"
git branch -a

echo ""
echo "✅ Done! Only main branch remains."
