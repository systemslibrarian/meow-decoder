# 🐾 Contributing to Meow Decoder — Cat Herder's Handbook

Thank you for joining the **clowder**! Contributors to Meow Decoder are affectionately known as **Cat Herders** 🐱 — because wrangling cryptographic code is exactly like herding cats.

> *"In a world of dogs fetching sticks, we herd cats through air gaps."*

---

## 🎯 Ways to Contribute

### 🌿 Catnip Bounty Program (Security Research — High Priority)
- Find and responsibly disclose vulnerabilities — earn your **Catnip Bounty** 🌿
- Review cryptographic implementation (sniff the code for bugs)
- Audit constant-time operations (no timing-based treats!)
- Test side-channel resistance (make sure the cat leaves no paw prints)

**Security issues:** Please email security concerns privately (see [SECURITY.md](SECURITY.md)) rather than opening public issues. The cat appreciates discretion.

### 🐛 Hairball Reports (Bug Reports)
- Reproduce the hairball with minimal steps
- Include Python version, OS, and dependencies
- Provide the full fur ball (error messages and stack traces)
- Attach sample files if relevant (non-sensitive!)

### 📦 Add to the Litter Box (Feature Requests)
- Check the existing litter box (issues) first — someone may have already scooped it
- Explain the use case clearly (what new trick should the cat learn?)
- Consider security implications (cats are cautious creatures)
- Be open to alternative approaches (cats always find a different way in)

### 📝 Grooming the Docs (Documentation)
- Fix typos and clarify confusing sections (untangle the yarn)
- Add examples and use cases
- Improve architecture documentation
- Translate to other languages (multilingual meowing)

### 💻 Code Contributions (Scratching Posts)
- Bug fixes (removing hairballs)
- Performance improvements (faster pouncing)
- New features (discuss first — cats don't like surprises!)
- Test coverage improvements (more safety nets for nine lives)

---

## 🛠️ Development Setup

```bash
# Clone the repository
git clone https://github.com/systemslibrarian/meow-decoder.git
cd meow-decoder

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install in development mode with all dependencies
pip install -e ".[dev]"

# For reproducible builds, use hash-locked dependencies:
pip install --require-hashes -r requirements.lock
pip install --require-hashes -r requirements-dev.lock

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
pytest tests/
```

### 🦀 Rust Crypto Backend (Required)

The Rust crypto backend is **mandatory** for all development. CI enforces `RUST_BACKEND_REQUIRED=1`.

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build and install the Rust module
cd rust_crypto
pip install maturin
maturin develop --release
cd ..

# Verify installation
python -c "import meow_crypto_rs; print('✅ Rust backend:', meow_crypto_rs.backend_info())"

# Run Rust tests
cargo test -p crypto_core
```

**Crypto code requirements:**
- All secret-handling crypto must use `meow_crypto_rs` (Rust backend)
- Do NOT import `cryptography` in production modules (enforced by CI)
- Use `backend.constant_time_compare()` for auth tag verification
- Use `backend.secure_zero()` for zeroizing secrets

---

## 📋 Coding Standards

### Python Style
- Follow PEP 8
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use descriptive variable names

### Security-Critical Code
- **No `eval()` or `exec()`** ever
- **Constant-time comparisons** for secrets (`secrets.compare_digest`)
- **Secure random** via `secrets` module, not `random`
- **Zero sensitive memory** after use
- **Validate all inputs** before processing

### Docstrings
```python
def encrypt_data(data: bytes, password: str) -> tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM with Argon2id key derivation.

    Args:
        data: Raw bytes to encrypt
        password: User-provided password (will be stretched)

    Returns:
        Tuple of (ciphertext, nonce)

    Raises:
        ValueError: If password is empty
        RuntimeError: If encryption fails

    Security:
        - Uses Argon2id with 512 MiB memory cost
        - Nonce is randomly generated (never reused)
        - Ciphertext includes GCM authentication tag
    """
```

### Commit Messages
```
feat(crypto): add post-quantum hybrid encryption

- Implement ML-KEM-768/1024 + X25519 PQXDH hybrid key exchange
- Add graceful fallback when liboqs not installed
- Update config defaults to enable PQ by default

Closes #123
```

Format: `type(scope): description`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `security`

---

## 🧪 Testing Requirements

### Before Submitting
```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=meow_decoder --cov-report=term-missing tests/

# Run security tests specifically
pytest tests/test_security.py tests/test_adversarial.py

# Run linting
flake8 meow_decoder/
black --check meow_decoder/
mypy meow_decoder/
```

### Test Categories
| Test File | Purpose |
|-----------|---------|
| `test_crypto.py` | Core encryption/decryption (205 tests) |
| `test_crypto_backend.py` | Rust crypto backend bindings (105 tests) |
| `test_security.py` | Security properties (20+ tests) |
| `test_adversarial.py` | Attack resistance |
| `test_encode.py` | Encoding pipeline, QR generation |
| `test_decode_gif.py` | GIF decoding, frame extraction |
| `test_fountain.py` | Fountain code encoding |
| `test_ratchet.py` | Per-frame symmetric ratchet (142 tests) |
| `test_pq_hybrid.py` | Post-quantum hybrid encryption |
| `test_golden_vectors.py` | Frozen golden vector regression |
| `test_crypto_enforcement.py` | AST-enforced Python crypto ban |

### Adding Tests
- Every new feature needs tests
- Security features need adversarial tests
- Aim for >90% coverage on new code
- Include edge cases and error conditions

---

## 🔐 Security Considerations

### Code Review Checklist
- [ ] No hardcoded secrets or keys
- [ ] Constant-time comparisons for sensitive data
- [ ] Input validation on all external data
- [ ] Secure random number generation
- [ ] Memory zeroing for sensitive values
- [ ] No timing side-channels
- [ ] Error messages don't leak secrets

### Cryptographic Changes
If your PR touches cryptographic code:
1. Explain the security rationale
2. Reference relevant standards (NIST, RFC, etc.)
3. Include test vectors if available
4. Consider backward compatibility
5. Update threat model if attack surface changes

---

## 📊 Pull Request Process

### 1. Fork and Branch
```bash
git checkout -b feature/your-feature-name
# or: git checkout -b fix/issue-description
```

### 2. Make Changes
- Keep commits atomic and focused
- Write clear commit messages
- Add/update tests
- Update documentation

### 3. Self-Review
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Security checklist completed
- [ ] Documentation updated
- [ ] No debug code left behind

### 4. Submit PR
- Fill out the PR template
- Link related issues
- Explain what and why
- Note any breaking changes

### 5. Review Process
- Maintainers will review within ~1 week
- Address feedback promptly
- Security-sensitive PRs may take longer
- Be patient with crypto-related changes

---

## 🏷️ Issue Labels (Cat Collar Tags)

| Label | Description |
|-------|-------------|
| `🚨 security` | Security-related issues — the cat's top priority |
| `🐛 hairball` | Something isn't working (bug report) |
| `📦 litter-box` | New feature request (add to the litter box) |
| `📝 grooming` | Documentation improvements |
| `🐱 good-first-pounce` | Good for new Cat Herders |
| `😿 help-wanted` | Extra paws needed |
| `🔐 crypto` | Cryptography-related (sharp claws required) |
| `✨ ux` | User experience improvements (nicer purring) |

---

## 📞 Getting Help

- **Questions:** Open a GitHub Discussion (ask the clowder)
- **Hairballs:** Open a GitHub Issue (report a bug)
- **Security:** See [SECURITY.md](SECURITY.md) (the Catnip Bounty Program)

---

## 🏆 Recognition — The Cat Herder Hall of Fame

All Cat Herders are recognized in:
- 📋 Release notes ("Herded by...")
- 🐾 CONTRIBUTORS.md — the **Official Clowder Roster**
- 🌿 **Catnip Bounty Hall of Fame** (for security researchers)
- 🎖️ Special titles for repeat contributors:
  - **Kitten** — First contribution merged
  - **Tabby** — 5+ contributions
  - **Maine Coon** — 20+ contributions or major feature
  - **Apex Predator** — Core maintainer / security lead

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the [CC BY-NC-SA 4.0 License](https://creativecommons.org/licenses/by-nc-sa/4.0/).

---

<p align="center">
  <em>🐾 Thank you for herding cats with us! Every Cat Herder makes Meow Decoder more secure. 🐾</em>
  <br>
  <em>"We don't herd cats because it's easy. We herd cats because they have secrets."</em>
</p>
