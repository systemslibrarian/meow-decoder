# 🐱 Meow Decoder - Makefile

.PHONY: help install dev test lint format clean build publish \
	formal-proverif formal-proverif-html formal-tla formal-tla-fountain formal-tamarin formal-tamarin-duress \
	formal-verus formal-lean formal-all verify

help:
	@echo "🐱 Meow Decoder - Available Commands:"
	@echo ""
	@echo "  make install     - Install dependencies"
	@echo "  make dev         - Install dev dependencies"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Lint code"
	@echo "  make format      - Format code"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make build       - Build package"
	@echo "  make publish     - Publish to PyPI"
	@echo ""
	@echo "📦 Build Targets:"
	@echo "  make build             - Build Python package"
	@echo "  make build-rust        - Build Rust crypto_core"
	@echo "  make build-wasm        - Build WASM bindings"
	@echo "  make build-wasm-release - Build optimized WASM for production"
	@echo "  make wasm-demo         - Build WASM + start browser demo server"
	@echo "  make prepare-deploy    - Prepare WASM demo for hosting"
	@echo ""
	@echo "🔒 Security:"
	@echo "  make security-test       - Run security test suite"
	@echo "  make sidechannel-test    - Run side-channel tests"
	@echo "  make supply-chain-audit  - Run supply-chain audit"
	@echo "  make stealth-build       - Build stealth distribution"
	@echo ""
	@echo "�🔬 Formal Verification:"
	@echo "  make formal-proverif       - Run ProVerif symbolic model"
	@echo "  make formal-proverif-html  - ProVerif HTML report"
	@echo "  make formal-tla            - Run TLA+ main model (MeowEncode)"
	@echo "  make formal-tla-fountain   - Run TLA+ fountain model (MeowFountain)"
	@echo "  make formal-tamarin        - Run Tamarin basic equivalence"
	@echo "  make formal-tamarin-duress - Run Tamarin duress OE (diff mode)"
	@echo "  make formal-verus          - Run Verus proofs"
	@echo "  make formal-lean           - Build Lean 4 proofs"
	@echo "  make formal-all            - Run all formal checks"
	@echo "  make verify                - Run full verification suite"
	@echo ""
	@echo "🐾 Strong cat passwords only! 😺"

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

test:
	pytest tests/ -v --cov=meow_decoder

test-security:
	@echo "🐾 Running security coverage gate (TIER 1 modules, ≥85% required)..."
	MEOW_TEST_MODE=1 pytest tests/ -v -m "security or crypto or adversarial" \
		--cov --cov-config=.coveragerc-security --cov-fail-under=85 \
		--cov-report=term-missing --cov-report=xml:coverage-security.xml

lint:
	flake8 meow_decoder/
	black --check meow_decoder/
	mypy meow_decoder/
	bandit -r meow_decoder/ -ll

format:
	black meow_decoder/ tests/

clean:
	rm -f tests/test_e2e.py
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

build: clean
	python -m build

publish: build
	twine check dist/*
	twine upload dist/*

formal-proverif:
	@echo "🔵 Running ProVerif symbolic analysis..."
	cd formal/proverif && eval $(opam env) && proverif meow_encode.pv

formal-proverif-html:
	@echo "🔵 Generating ProVerif HTML report..."
	cd formal/proverif && eval $(opam env) && proverif -html output meow_encode.pv

formal-tla:
	@echo "📐 Running TLA+ main model (MeowEncode.tla)..."
	cd formal/tla && java -jar tla2tools.jar -config MeowEncode.cfg MeowEncode.tla

formal-tla-fountain:
	@echo "📐 Running TLA+ fountain model (MeowFountain.tla)..."
	cd formal/tla && java -jar tla2tools.jar -config MeowFountain.cfg MeowFountain.tla

formal-tamarin:
	@echo "🟣 Running Tamarin basic equivalence..."
	cd formal/tamarin && bash ./run.sh

formal-tamarin-duress:
	@echo "🟣 Running Tamarin duress observational equivalence (diff mode)..."
	cd formal/tamarin && tamarin-prover --diff MeowDuressEquiv.spthy --prove

formal-verus:
	@echo "🟢 Running Verus implementation proofs..."
	cd crypto_core && verus src/lib.rs

formal-lean:
	@echo "🔷 Building Lean 4 fountain code proofs..."
	cd formal/lean && lake build

formal-all: formal-proverif formal-tla formal-tla-fountain formal-tamarin-duress formal-verus formal-lean
	@echo ""
	@echo "✅ All formal verification complete!"
	@echo "📊 See docs/formal_coverage.md for coverage matrix"

verify:
	bash ./scripts/verify_all.sh

# 🥷 Stealth build for deniability
stealth-build:
	@echo "🥷 Building stealth distribution..."
	python scripts/stealth_build.py
	@echo "✅ Stealth build created in dist/stealth/"

# 🔬 Side-channel tests
sidechannel-test:
	@echo "🔬 Running side-channel tests..."
	pytest tests/test_sidechannel.py -v --tb=short
	@echo "✅ Side-channel tests complete"

# 🔐 Security-focused tests
security-test:
	@echo "🔐 Running security test suite..."
	pytest tests/test_security.py tests/test_adversarial.py tests/test_sidechannel.py -v --tb=short
	@echo "✅ Security tests complete"

# 📦 Supply-chain audit
supply-chain-audit:
	@echo "📦 Running supply-chain audit..."
	pip-audit
	cd crypto_core && cargo audit
	cd crypto_core && cargo deny check
	@echo "✅ Supply-chain audit complete"

# 🦀 Rust crypto_core build
build-rust:
	@echo "🦀 Building Rust crypto_core..."
	cd crypto_core && cargo build --release --features full-software
	@echo "✅ Rust build complete"

# 🌐 WASM build (development)
build-wasm:
	@echo "🌐 Building WASM bindings (development)..."
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Installing wasm-pack..."; cargo install wasm-pack; }
	cd crypto_core && wasm-pack build --target web --dev --features wasm
	@echo "✅ WASM development build complete in crypto_core/pkg/"

# 🌐 WASM build (production - optimized)
build-wasm-release:
	@echo "🌐 Building WASM bindings (production - optimized)..."
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Installing wasm-pack..."; cargo install wasm-pack; }
	cd crypto_core && wasm-pack build --target web --release --features wasm
	@echo "✅ WASM production build complete in crypto_core/pkg/"
	@echo "📊 Package size: $$(du -h crypto_core/pkg/*.wasm | cut -f1)"

# 🌐 WASM Node.js build (for server-side use)
build-wasm-node:
	@echo "🌐 Building WASM bindings for Node.js..."
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Installing wasm-pack..."; cargo install wasm-pack; }
	cd crypto_core && wasm-pack build --target nodejs --release --features wasm
	@echo "✅ WASM Node.js build complete in crypto_core/pkg/"

# 🌐 WASM demo - Build and start HTTP server
wasm-demo: build-wasm
	@echo ""
	@echo "🐱 Starting WASM Demo Server..."
	@echo ""
	@echo "📍 Open in browser: http://localhost:8080/examples/wasm_browser_example.html"
	@echo ""
	@echo "💡 In Codespaces: Forward port 8080 in the Ports tab, then open the URL"
	@echo ""
	@echo "Press Ctrl+C to stop the server"
	@echo ""
	python3 -m http.server 8080

# 📦 Prepare WASM demo for deployment (PythonAnywhere, etc.)
prepare-deploy:
	@echo "📦 Preparing WASM demo for deployment..."
	@./scripts/prepare_pythonanywhere.sh
	@echo "📖 See examples/PYTHONANYWHERE_HOSTING.md for hosting instructions"

.DEFAULT_GOAL := help
