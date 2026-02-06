# How to Push Updates (with Branch Protection)

Since `main` is now protected, you can't push directly to it.
Every change goes through a PR. Here's the workflow:

---

## Quick Version (copy-paste)

```bash
# 1. Create a branch (name it something meaningful)
git checkout -b fix/short-description

# 2. Stage and commit your changes
git add -A
git commit -m "fix: short description of what changed"

# 3. Push the branch
git push -u origin HEAD

# 4. Create a PR
gh pr create --fill

# 5. Merge it (after CI passes)
gh pr merge --squash
```

---

## Step-by-Step Explained

### 1. Make your changes on a branch (never on `main`)

```bash
git checkout main              # start from main
git pull                       # get latest
git checkout -b fix/my-thing   # create branch
```

Branch naming conventions:
- `fix/description` — bug fixes
- `feat/description` — new features
- `docs/description` — documentation only
- `chore/description` — maintenance, CI, deps

### 2. Commit your work

```bash
git add -A                            # stage everything
git commit -m "fix: what you changed" # commit
```

### 3. Push and create PR

```bash
git push -u origin HEAD        # push branch to GitHub
gh pr create --fill            # create PR with auto title/body
```

### 4. Wait for CI, then merge

```bash
# Check CI status
gh pr checks

# When green, merge
gh pr merge --squash

# Clean up
git checkout main
git pull
```

---

## One-Liner Alias

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
alias meow-push='git checkout -b fix/$(date +%s) && git add -A && git commit -m "fix: update" && git push -u origin HEAD && gh pr create --fill'
```

Then just run `meow-push` after making changes. Merge via GitHub UI or `gh pr merge --squash`.

---

## meow-push.sh Script (Recommended — Does Everything)

There's a local-only script at the repo root called `meow-push.sh` that automates the **entire** workflow: branch → commit → push → PR → wait for CI → squash merge → back to main.

It's excluded from git via `.gitignore` so only you can see it.

### Usage:

```bash
# Basic — defaults to "fix:" prefix
bash meow-push.sh "updated crypto module"

# With a custom prefix
bash meow-push.sh feat "added steganography mode"
bash meow-push.sh docs "updated readme"
bash meow-push.sh chore "bumped dependencies"
bash meow-push.sh refactor "cleaned up fountain code"
bash meow-push.sh test "added adversarial tests"
```

### What it does:

1. Pulls latest `main`
2. Creates a branch named from your description (e.g., `fix/updated-crypto-module`)
3. Stages all changes (`git add -A`)
4. Commits with your message (e.g., `fix: updated crypto module`)
5. Pushes the branch to origin
6. Creates a PR via `gh pr create --fill`
7. Waits up to 5 minutes for CI checks to pass
8. Squash-merges the PR and deletes the branch
9. Switches back to `main` and pulls

### If CI fails:

The script stops and tells you what failed. Fix the issue, then:

```bash
git add -A && git commit -m "fix: address CI failure"
git push
# then manually merge when green:
gh pr merge --squash
```

---

## Emergency: Direct Push to Main

If you need to bypass (e.g., CI is broken and blocking itself):

1. Go to **Settings → Branches → main rule**
2. Temporarily uncheck "Do not allow bypassing the above settings"
3. Push directly
4. Re-enable the setting

---

## Common Scenarios

### "I already committed to main by accident"

```bash
# Move the commit to a branch instead
git branch fix/accidental-commit    # save current commit
git reset --hard HEAD~1             # undo on main
git checkout fix/accidental-commit  # switch to branch
git push -u origin HEAD             # push branch
gh pr create --fill                 # make PR
```

### "I want to update an open PR"

```bash
git checkout fix/my-existing-branch
# make more changes
git add -A && git commit -m "fix: additional changes"
git push   # updates the PR automatically
```

### "CI failed on my PR"

```bash
gh pr checks                # see which check failed
gh run view <RUN_ID> --log  # see the failure log
# fix the issue, commit, push — PR updates automatically
```

---

## How We Set Up Branch Protection (for reference)

These are the steps we took on 2026-02-06 to protect `main`:

1. **Go to**: GitHub repo → **Settings** → **Branches**
2. **Click**: "Add classic branch protection rule"
3. **Branch name pattern**: `main`
4. **Checked these boxes**:
   - ✅ Require a pull request before merging
     - ✅ Require approvals: **0** (solo dev — just needs CI to pass)
   - ✅ Require status checks to pass before merging
     - ✅ Require branches to be up to date before merging
     - Added required checks: `CI - Tests + Coverage`, `CodeQL`, `Security CI`
   - ✅ Do not allow bypassing the above settings *(prevents accidental direct pushes)*
5. **Click**: "Create" / "Save changes"

### To verify it's working:

```bash
# This should FAIL (can't push directly to main):
echo "test" >> test.txt && git add . && git commit -m "test" && git push

# This should WORK (go through a PR):
git checkout -b fix/test-branch
echo "test" >> test.txt && git add . && git commit -m "test"
git push -u origin HEAD
gh pr create --fill
```

### To modify later:

- **Settings → Branches → main** → Edit the rule
- To temporarily allow direct push: uncheck "Do not allow bypassing"
