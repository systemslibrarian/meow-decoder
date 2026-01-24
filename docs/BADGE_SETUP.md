# 🎖️ Setting Up GitHub Badges

This guide will help you set up all the professional GitHub badges shown in the README.

---

## ✅ Badges Included

1. **CI** - Continuous Integration status
2. **CodeQL Security Scan** - Automated security analysis
3. **Codecov** - Test coverage reporting
4. **License** - MIT License badge
5. **Python Version** - Supported Python versions
6. **Ruff** - Linter badge
7. **Mypy** - Type checker badge

---

## 🚀 Step 1: Enable GitHub Actions

### CI Badge (security-ci.yml)

**Status:** ✅ Already configured

The workflow file `.github/workflows/security-ci.yml` is already set up. Once you push to GitHub, the badge will automatically work.

**Badge URL:**
```markdown
[![CI](https://github.com/YOUR_USERNAME/meow-decoder/actions/workflows/security-ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/meow-decoder/actions/workflows/security-ci.yml)
```

**To activate:**
1. Push code to GitHub: `git push origin main`
2. Actions will run automatically
3. Badge updates automatically

---

### CodeQL Security Scan Badge

**Status:** ✅ Already configured

The workflow file `.github/workflows/codeql.yml` is already set up.

**Badge URL:**
```markdown
[![CodeQL](https://github.com/YOUR_USERNAME/meow-decoder/actions/workflows/codeql.yml/badge.svg)](https://github.com/YOUR_USERNAME/meow-decoder/actions/workflows/codeql.yml)
```

**To activate:**
1. Go to GitHub repo → Settings → Code security and analysis
2. Enable "CodeQL analysis" (should be automatic with the workflow)
3. Push code to trigger first scan
4. Badge updates automatically

---

## 📊 Step 2: Set Up Codecov

### Create Codecov Account

1. Go to [codecov.io](https://codecov.io/)
2. Sign in with your GitHub account
3. Authorize Codecov to access your repositories

### Add Repository

1. In Codecov dashboard, click "Add Repository"
2. Find `meow-decoder` and click "Setup"
3. Copy the **CODECOV_TOKEN** provided

### Add Token to GitHub

1. Go to your GitHub repo → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `CODECOV_TOKEN`
4. Value: Paste the token from Codecov
5. Click "Add secret"

### Badge URL

**Once configured, your badge will be:**
```markdown
[![codecov](https://codecov.io/gh/YOUR_USERNAME/meow-decoder/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_USERNAME/meow-decoder)
```

**To activate:**
1. Push code to GitHub
2. CI will run and upload coverage report to Codecov
3. Wait ~5 minutes for first report
4. Badge will show coverage percentage

---

## 🔧 Step 3: Static Badges

These badges don't require any setup - they're static URLs:

### License Badge

```markdown
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
```

### Python Version Badge

```markdown
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
```

### Ruff Badge

```markdown
![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
```

### Mypy Badge

```markdown
![Mypy](https://www.mypy-lang.org/static/mypy_badge.svg)
```

---

## 📝 Step 4: Update README.md

**Replace placeholders:**

In `README.md`, find and replace:
- `YOUR_USERNAME` → Your actual GitHub username
- `your-domain.com` → Your actual domain (or remove email sections)

**Example:**
```markdown
<!-- BEFORE -->
https://github.com/YOUR_USERNAME/meow-decoder

<!-- AFTER -->
https://github.com/paul-smith/meow-decoder
```

---

## ✅ Verification Checklist

After setup, verify each badge works:

- [ ] **CI Badge** - Shows "passing" (green)
- [ ] **CodeQL Badge** - Shows "passing" (green)
- [ ] **Codecov Badge** - Shows percentage (e.g., "12%")
- [ ] **License Badge** - Shows "MIT" (green)
- [ ] **Python Badge** - Shows "3.10+" (blue)
- [ ] **Ruff Badge** - Shows "Ruff" (purple)
- [ ] **Mypy Badge** - Shows "checked with mypy" (blue)

---

## 🐛 Troubleshooting

### CI Badge Not Showing

**Problem:** Badge shows "no status"

**Solution:**
1. Ensure workflow file exists: `.github/workflows/security-ci.yml`
2. Push to `main` branch (badge watches this branch)
3. Check Actions tab in GitHub for errors
4. Wait ~2 minutes for first run

### CodeQL Badge Not Showing

**Problem:** Badge shows "unknown"

**Solution:**
1. Enable CodeQL in Settings → Code security
2. Workflow file must be named exactly `codeql.yml`
3. First scan takes ~5 minutes
4. Check Actions tab for CodeQL workflow

### Codecov Badge Shows "unknown"

**Problem:** Coverage badge not updating

**Solution:**
1. Verify `CODECOV_TOKEN` is set in GitHub Secrets
2. Check CI logs for "Upload coverage to Codecov" step
3. Ensure `coverage.xml` is generated: `pytest --cov-report=xml`
4. Visit Codecov dashboard to see if reports are arriving
5. First upload takes ~5 minutes to process

### Codecov Badge Shows 404

**Problem:** Badge URL returns 404

**Solution:**
1. Verify repository name matches exactly (case-sensitive)
2. Ensure repository is public OR Codecov is authorized
3. Check branch name (default is `main`, not `master`)
4. Wait for first coverage report to be processed

---

## 📈 Expected Timeline

| Step | Time |
|------|------|
| Push code to GitHub | Immediate |
| CI workflow runs | ~2-5 minutes |
| CodeQL scan completes | ~5-10 minutes |
| Codecov processes report | ~5 minutes |
| All badges active | ~15 minutes total |

---

## 🎯 Badge Customization

### Custom Badge Colors

Change badge colors in URLs:

```markdown
<!-- Green success -->
![Status](https://img.shields.io/badge/status-passing-green.svg)

<!-- Red failure -->
![Status](https://img.shields.io/badge/status-failing-red.svg)

<!-- Yellow warning -->
![Status](https://img.shields.io/badge/status-warning-yellow.svg)

<!-- Blue info -->
![Status](https://img.shields.io/badge/version-v5.4.0-blue.svg)
```

### Shields.io Custom Badges

Create custom badges at [shields.io](https://shields.io/):

```markdown
![Custom](https://img.shields.io/badge/<LABEL>-<MESSAGE>-<COLOR>)
```

**Examples:**
```markdown
![Security](https://img.shields.io/badge/security-10%2F10-brightgreen)
![Tests](https://img.shields.io/badge/tests-40%2F42%20passing-green)
![Coverage](https://img.shields.io/badge/coverage-12%25-yellow)
```

---

## 📚 Additional Badges

### Optional Badges to Consider:

**PyPI Version:**
```markdown
![PyPI](https://img.shields.io/pypi/v/meow-decoder)
```
*(Requires publishing to PyPI)*

**GitHub Stars:**
```markdown
![Stars](https://img.shields.io/github/stars/YOUR_USERNAME/meow-decoder?style=social)
```

**GitHub Issues:**
```markdown
![Issues](https://img.shields.io/github/issues/YOUR_USERNAME/meow-decoder)
```

**Last Commit:**
```markdown
![Last Commit](https://img.shields.io/github/last-commit/YOUR_USERNAME/meow-decoder)
```

**Contributors:**
```markdown
![Contributors](https://img.shields.io/github/contributors/YOUR_USERNAME/meow-decoder)
```

---

## ✅ Final Result

Once everything is set up, your README should look like:

```markdown
[![CI](https://github.com/paul-smith/meow-decoder/actions/workflows/security-ci.yml/badge.svg)](...)
[![CodeQL](https://github.com/paul-smith/meow-decoder/actions/workflows/codeql.yml/badge.svg)](...)
[![codecov](https://codecov.io/gh/paul-smith/meow-decoder/branch/main/graph/badge.svg)](...)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](...)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](...)
[![Ruff](https://img.shields.io/endpoint?url=...)](...)
[![Mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](...)
```

All badges should be **green** or showing **valid data** within 15-20 minutes of first push.

---

## 📞 Need Help?

If badges still don't work after 24 hours:

1. Check [GitHub Actions status](https://www.githubstatus.com/)
2. Check [Codecov status](https://status.codecov.io/)
3. Review GitHub Actions logs for errors
4. Open an issue in the repo for community help

---

**Happy badging!** 🎖️
