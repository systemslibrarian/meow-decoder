# 🤝 Contributing to Meow Decoder

Thank you for your interest in contributing to Meow Decoder! This document provides guidelines and information for contributors.

---

## 🎯 Ways to Contribute

### 🔒 Security Research (High Priority)
- Find and responsibly disclose vulnerabilities
- Review cryptographic implementation
- Audit constant-time operations
- Test side-channel resistance

**Security issues:** Please email security concerns privately (see [SECURITY.md](SECURITY.md)) rather than opening public issues.

### 🐛 Bug Reports
- Reproduce the issue with minimal steps
- Include Python version, OS, and dependencies
- Provide error messages and stack traces
- Attach sample files if relevant (non-sensitive!)

### ✨ Feature Requests
- Check existing issues first
- Explain the use case clearly
- Consider security implications
- Be open to alternative approaches

### 📝 Documentation
- Fix typos and clarify confusing sections
- Add examples and use cases
- Improve architecture documentation
- Translate to other languages

### 💻 Code Contributions
- Bug fixes
- Performance improvements
- New features (discuss first!)
- Test coverage improvements

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

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
pytest tests/
```

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
        - Uses Argon2id with 256 MiB memory cost
        - Nonce is randomly generated (never reused)
        - Ciphertext includes GCM authentication tag
    """
```

### Commit Messages
```
feat(crypto): add post-quantum hybrid encryption

- Implement ML-KEM-768 + X25519 hybrid key exchange
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
| `test_crypto.py` | Core encryption/decryption |
| `test_security.py` | Security properties (125+ tests) |
| `test_adversarial.py` | Attack resistance |
| `test_e2e.py` | End-to-end roundtrip |
| `test_fountain.py` | Fountain code encoding |

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

## 🏷️ Issue Labels

| Label | Description |
|-------|-------------|
| `security` | Security-related issues (high priority) |
| `bug` | Something isn't working |
| `enhancement` | New feature request |
| `documentation` | Documentation improvements |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `crypto` | Cryptography-related |
| `ux` | User experience improvements |

---

## 📞 Getting Help

- **Questions:** Open a GitHub Discussion
- **Bugs:** Open a GitHub Issue
- **Security:** See [SECURITY.md](SECURITY.md)
- **Chat:** (Coming soon)

---

## 🙏 Recognition

Contributors are recognized in:
- Release notes
- CONTRIBUTORS.md (coming soon)
- Security Hall of Fame (for vulnerability reporters)

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

<p align="center">
  <em>🐱 Thank you for helping make Meow Decoder more secure and useful! 🐱</em>
</p>
