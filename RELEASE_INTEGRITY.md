# 🔒 Release Integrity Guide

This guide explains how to sign releases and verify their integrity.

---

## 🎯 For Maintainers: Signing Releases

### Prerequisites

1. **GPG key** - Generate if you don't have one:
   ```bash
   gpg --full-generate-key
   # Choose: RSA and RSA, 4096 bits, never expires
   ```

2. **Git configured with GPG:**
   ```bash
   git config --global user.signingkey YOUR_KEY_ID
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   ```

3. **Add GPG key to GitHub:**
   - Export: `gpg --armor --export YOUR_KEY_ID`
   - GitHub → Settings → SSH and GPG keys → New GPG key
   - Paste exported key

---

### Creating a Signed Release

#### 1. Update Version

```bash
# Update version in pyproject.toml
vim pyproject.toml  # Change version = "5.4.0" → "5.5.0"

# Update __init__.py
vim meow_decoder/__init__.py  # Change __version__ = "5.4.0" → "5.5.0"

# Commit
git add pyproject.toml meow_decoder/__init__.py
git commit -S -m "Bump version to 5.5.0"
```

#### 2. Create Signed Tag

```bash
# Create annotated, signed tag
git tag -s v5.5.0 -m "Release v5.5.0

Security improvements:
- Fixed nonce generation
- Enhanced tamper detection
- Improved test coverage

Full changelog: https://github.com/YOUR_USERNAME/meow-decoder/blob/main/CHANGELOG.md"

# Verify signature
git verify-tag v5.5.0

# Push tag
git push origin v5.5.0
```

#### 3. GitHub Actions Does the Rest

The release workflow automatically:
- ✅ Builds packages
- ✅ Generates SHA256 checksums
- ✅ Creates SBOM (Software Bill of Materials)
- ✅ Runs security audit
- ✅ Creates GitHub release with all artifacts
- ✅ Publishes to PyPI (if configured)

#### 4. Verify Release

After GitHub Actions completes:

```bash
# Download release
wget https://github.com/YOUR_USERNAME/meow-decoder/releases/download/v5.5.0/SHA256SUMS.txt
wget https://github.com/YOUR_USERNAME/meow-decoder/releases/download/v5.5.0/meow_decoder-5.5.0-py3-none-any.whl

# Verify checksum
sha256sum -c SHA256SUMS.txt

# Should output:
# meow_decoder-5.5.0-py3-none-any.whl: OK
```

---

## 🔍 For Users: Verifying Releases

### Step 1: Verify Git Tag Signature

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/meow-decoder.git
cd meow-decoder

# Get maintainer's GPG key
gpg --keyserver keyserver.ubuntu.com --recv-keys MAINTAINER_KEY_ID

# Verify tag
git verify-tag v5.5.0

# Should output:
# gpg: Good signature from "Maintainer Name <email>"
```

### Step 2: Verify Package Checksum

```bash
# Download files
wget https://github.com/YOUR_USERNAME/meow-decoder/releases/download/v5.5.0/SHA256SUMS.txt
wget https://github.com/YOUR_USERNAME/meow-decoder/releases/download/v5.5.0/meow_decoder-5.5.0-py3-none-any.whl

# Verify
sha256sum -c SHA256SUMS.txt

# Should output: meow_decoder-5.5.0-py3-none-any.whl: OK
```

### Step 3: Review SBOM (Optional)

```bash
# Download SBOM
wget https://github.com/YOUR_USERNAME/meow-decoder/releases/download/v5.5.0/sbom-summary.txt

# Review dependencies
cat sbom-summary.txt
```

### Step 4: Check Security Audit

```bash
# Download audit
wget https://github.com/YOUR_USERNAME/meow-decoder/releases/download/v5.5.0/security-audit.txt

# Review
cat security-audit.txt

# Should show: No known vulnerabilities found
```

---

## 📦 Release Artifacts Explained

Each release includes:

| File | Purpose | Verification |
|------|---------|--------------|
| **\*.whl** | Python wheel package | SHA256 checksum |
| **\*.tar.gz** | Source distribution | SHA256 checksum |
| **SHA256SUMS.txt** | Checksums for all files | GPG tag signature |
| **sbom.json** | Machine-readable SBOM | Included in release |
| **sbom.xml** | XML format SBOM | Included in release |
| **sbom-summary.txt** | Human-readable dependencies | Included in release |
| **requirements-frozen.txt** | Exact dependency versions | Included in release |
| **security-audit.txt** | Vulnerability scan results | Included in release |

---

## 🛡️ Security Best Practices

### For Maintainers

1. **Never commit with unsigned tags**
   ```bash
   git config --global tag.gpgsign true
   ```

2. **Protect GPG private key**
   - Use strong passphrase
   - Back up to secure location
   - Store on hardware token if possible

3. **Review dependencies before release**
   ```bash
   pip-audit
   ```

4. **Run full test suite**
   ```bash
   pytest tests/ -v
   ```

5. **Update CHANGELOG.md**
   - List all security fixes
   - Credit contributors
   - Link to relevant issues

### For Users

1. **Always verify signatures**
   - Don't skip GPG verification
   - Check checksum matches

2. **Review SBOM**
   - Check for unexpected dependencies
   - Verify dependency versions

3. **Check security audit**
   - Look for known vulnerabilities
   - Update if issues found

4. **Pin versions in production**
   ```bash
   pip install meow-decoder==5.5.0  # Pin exact version
   ```

---

## 🔐 GPG Key Management

### Publishing Your GPG Key

```bash
# Export public key
gpg --armor --export YOUR_KEY_ID > meow-decoder-gpg-public.asc

# Upload to keyservers
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID

# Add to repository
cp meow-decoder-gpg-public.asc docs/GPG-KEY.asc
git add docs/GPG-KEY.asc
git commit -S -m "Add GPG public key"
```

### Revoking a Compromised Key

```bash
# Generate revocation certificate
gpg --gen-revoke YOUR_KEY_ID > revoke.asc

# If key compromised, import and upload
gpg --import revoke.asc
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID

# Update repository
echo "⚠️ GPG key YOUR_KEY_ID revoked on $(date)" >> docs/GPG-REVOKED.txt
git commit -S -m "Revoke compromised GPG key"
```

---

## 📊 Verification Checklist

### For Each Release

- [ ] GPG tag signature verified
- [ ] SHA256 checksums match
- [ ] SBOM reviewed (no unexpected deps)
- [ ] Security audit clean
- [ ] Tests passing (CI badge green)
- [ ] CodeQL scan passing
- [ ] Version matches across files

### Example: Complete Verification

```bash
#!/bin/bash
# verify-release.sh - Complete release verification

VERSION="5.5.0"
REPO="YOUR_USERNAME/meow-decoder"

echo "Verifying meow-decoder v$VERSION..."

# 1. Verify GPG signature
git verify-tag v$VERSION || exit 1
echo "✅ GPG signature valid"

# 2. Download artifacts
cd /tmp
wget https://github.com/$REPO/releases/download/v$VERSION/SHA256SUMS.txt
wget https://github.com/$REPO/releases/download/v$VERSION/meow_decoder-$VERSION-py3-none-any.whl
wget https://github.com/$REPO/releases/download/v$VERSION/security-audit.txt

# 3. Verify checksum
sha256sum -c SHA256SUMS.txt || exit 1
echo "✅ Checksum valid"

# 4. Check security audit
if grep -q "No known vulnerabilities" security-audit.txt; then
    echo "✅ Security audit clean"
else
    echo "⚠️ Security issues found - review security-audit.txt"
fi

echo "✅ Release v$VERSION verified!"
```

---

## 🚨 Incident Response

### If Compromised Release Detected

1. **Immediately:**
   - Delete GitHub release
   - Revoke signing key
   - Notify users via GitHub issue
   - Email security@your-domain.com subscribers

2. **Investigation:**
   - Identify compromise scope
   - Review all recent commits
   - Check CI/CD logs

3. **Remediation:**
   - Generate new GPG key
   - Re-release after fixes
   - Update security advisory

4. **Communication:**
   - Post-mortem blog post
   - CHANGELOG security notice
   - Update SECURITY.md

---

## 📚 References

- **GPG Best Practices:** https://riseup.net/en/security/message-security/openpgp/best-practices
- **CycloneDX SBOM:** https://cyclonedx.org/
- **NIST SBOM Guidelines:** https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity/software-security-supply-chains
- **Sigstore (future):** https://www.sigstore.dev/

---

## ✅ Quick Reference

**Sign a release:**
```bash
git tag -s v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

**Verify a release:**
```bash
git verify-tag v1.0.0
sha256sum -c SHA256SUMS.txt
```

**Check SBOM:**
```bash
cat sbom-summary.txt
```

**Security audit:**
```bash
cat security-audit.txt
```

---

*For questions about release integrity, email: security@your-domain.com*
