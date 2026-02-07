#!/usr/bin/env bash
# meow-push.sh — Local-only push script (excluded from git via .gitignore)
# Usage: bash meow-push.sh "short description of what changed"
# Usage: bash meow-push.sh fix "short description"   (custom prefix)
set -euo pipefail

# --- Parse args ---
if [[ $# -eq 0 ]]; then
  echo "Usage: bash meow-push.sh \"description of changes\""
  echo "       bash meow-push.sh fix \"description\""
  echo ""
  echo "Prefixes: fix, feat, docs, chore, refactor, test"
  exit 1
fi

if [[ $# -ge 2 ]]; then
  PREFIX="$1"
  shift
  MSG="$*"
else
  PREFIX="fix"
  MSG="$*"
fi

# Slugify the description for the branch name
SLUG=$(echo "$MSG" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//' | cut -c1-40)
BRANCH="${PREFIX}/${SLUG}"
COMMIT_MSG="${PREFIX}: ${MSG}"

echo "=== meow-push ==="
echo "Branch:  $BRANCH"
echo "Commit:  $COMMIT_MSG"
echo ""

# --- Ensure we start from latest main ---
CURRENT=$(git branch --show-current)
if [[ "$CURRENT" == "main" ]]; then
  echo "→ Pulling latest main..."
  git pull --quiet
else
  echo "⚠ You're on '$CURRENT', not main. Switching to main first..."
  git stash --quiet 2>/dev/null || true
  git checkout main --quiet
  git pull --quiet
  git stash pop --quiet 2>/dev/null || true
fi

# --- Check for changes ---
if git diff --quiet && git diff --cached --quiet; then
  echo "✗ No changes to commit. Make some changes first!"
  exit 1
fi

# --- Branch, commit, push, PR ---
echo "→ Creating branch: $BRANCH"
git checkout -b "$BRANCH" --quiet

echo "→ Staging all changes..."
git add -A

echo "→ Committing: $COMMIT_MSG"
git commit -m "$COMMIT_MSG" --quiet

echo "→ Pushing to origin..."
git push -u origin HEAD --quiet

echo "→ Creating PR..."
PR_URL=$(gh pr create --fill 2>&1 | tail -1)
echo ""
echo "✓ PR created: $PR_URL"
echo ""

# --- Wait for CI ---
echo "→ Waiting for CI checks..."
sleep 5  # give GitHub a moment to register the checks

MAX_WAIT=300  # 5 minutes
WAITED=0
while true; do
  STATUS=$(gh pr checks 2>&1 || true)

  if echo "$STATUS" | grep -q "fail\|FAIL"; then
    echo ""
    echo "✗ CI FAILED:"
    echo "$STATUS"
    echo ""
    echo "Fix the issue, then: git add -A && git commit -m 'fix: ...' && git push"
    exit 1
  fi

  if echo "$STATUS" | grep -q "pending\|PENDING\|no checks"; then
    WAITED=$((WAITED + 10))
    if [[ $WAITED -ge $MAX_WAIT ]]; then
      echo ""
      echo "⚠ CI still running after ${MAX_WAIT}s. Merge manually when ready:"
      echo "  gh pr merge --squash"
      exit 0
    fi
    printf "  Still running... (%ds)\r" "$WAITED"
    sleep 10
    continue
  fi

  # All checks passed
  echo ""
  echo "✓ All CI checks passed!"
  break
done

# --- Merge ---
echo "→ Merging PR (squash)..."
gh pr merge --squash --delete-branch

echo "→ Switching back to main..."
git checkout main --quiet
git pull --quiet

echo ""
echo "✓ Done! Changes are on main."
