# 🐱 Meow Decoder - Makefile

.PHONY: help install dev test lint format clean build publish \
	formal-proverif formal-proverif-html formal-tla formal-tla-fountain formal-tla-streaming \
	formal-tamarin formal-tamarin-duress formal-tamarin-pq formal-tamarin-docker \
	formal-verus formal-verus-docker formal-lean formal-lean-sorry formal-all formal-ci \
	formal-negative-tla formal-negative-proverif formal-negative-tamarin formal-negative \
	verify check-wasm-deps build-wasm build-wasm-release build-wasm-pq build-wasm-node meow-build

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
	@echo "  make build-wasm        - Build WASM bindings (dev)"
	@echo "  make build-wasm-release - Build optimized WASM"
	@echo "  make build-wasm-pq     - Build WASM with Post-Quantum ML-KEM-1024"
	@echo "  make meow-build        - Build WASM + start browser demo server"
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
	@echo "  make formal-tla-streaming  - Run TLA+ streaming model (MeowStreaming)"
	@echo "  make formal-tamarin        - Run Tamarin basic equivalence"
	@echo "  make formal-tamarin-duress - Run Tamarin duress OE (diff mode)"
	@echo "  make formal-tamarin-pq     - Run Tamarin MEOW4 PQ duress OE"
	@echo "  make formal-tamarin-docker - Run Tamarin via Docker (no native Maude)"
	@echo "  make formal-negative-tamarin-pq     - Run Tamarin PQ negative tests (should FAIL)"
	@echo "  make formal-negative-tamarin-docker - Run Tamarin PQ negative tests via Docker"
	@echo "  make formal-verus          - Run Verus proofs"
	@echo "  make formal-verus-docker   - Run Verus via Docker (nightly toolchain)"
	@echo "  make formal-lean           - Build Lean 4 proofs"
	@echo "  make formal-lean-sorry     - Check for unapproved sorry"
	@echo "  make formal-all            - Run all formal checks"
	@echo "  make formal-ci             - CI gate (skips unavailable tools)"
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
	cd formal/tla && tlc -config MeowEncode.cfg MeowEncode.tla

formal-tla-fountain:
	@echo "📐 Running TLA+ fountain model (MeowFountain.tla)..."
	cd formal/tla && tlc -config MeowFountain.cfg MeowFountain.tla

formal-tla-streaming:
	@echo "📐 Running TLA+ streaming model (MeowStreaming.tla)..."
	cd formal/tla && tlc -config MeowStreaming.cfg MeowStreaming.tla

formal-tamarin:
	@echo "🟣 Running Tamarin basic equivalence..."
	cd formal/tamarin && bash ./run.sh

formal-tamarin-duress:
	@echo "🟣 Running Tamarin duress observational equivalence (diff mode)..."
	cd formal/tamarin && tamarin-prover --diff MeowDuressEquiv.spthy --prove

formal-tamarin-pq:
	@echo "🟣 Running Tamarin MEOW4 PQ duress OE (diff mode)..."
	cd formal/tamarin && tamarin-prover --diff MeowDuressEquivPQ.spthy --prove

formal-tamarin-docker:
	@echo "🟣 Running Tamarin duress OE via Docker (MEOW3 + MEOW4)..."
	docker build -f formal/Dockerfile.tamarin -t meow-tamarin . \
		&& docker run --rm meow-tamarin

formal-verus:
	@echo "🟢 Running Verus implementation proofs..."
	cd crypto_core && verus src/lib.rs

formal-verus-docker:
	@echo "🟢 Running Verus proofs via Docker (nightly)..."
	docker build -f formal/Dockerfile.verus -t meow-verus . \
		&& docker run --rm meow-verus

formal-lean:
	@echo "🔷 Building Lean 4 fountain code proofs..."
	cd formal/lean && lake build

formal-lean-sorry:
	@echo "🔷 Checking for unapproved sorry in Lean files..."
	@SORRY_COUNT=$$(grep -rn 'sorry' formal/lean/ --include='*.lean' \
		--exclude-dir='.lake' --exclude-dir='lake-packages' \
		| grep -v -e 'AXIOM:' -e 'APPROVED:' | wc -l); \
	if [ "$$SORRY_COUNT" -gt 0 ]; then \
		echo "❌ Found $$SORRY_COUNT unapproved sorry statement(s):"; \
		grep -rn 'sorry' formal/lean/ --include='*.lean' \
			--exclude-dir='.lake' --exclude-dir='lake-packages' \
			| grep -v -e 'AXIOM:' -e 'APPROVED:'; \
		exit 1; \
	else \
		echo "✅ No unapproved sorry statements found."; \
	fi

# Negative tests: variants that should FAIL (verify positive models are correct)
formal-negative-tamarin-pq:
	@echo "🔴 Running Tamarin PQ NEGATIVE tests (should FAIL)..."
	@echo "Test 1: KEM ct not bound to HMAC → diffEquivLemma should FAIL"
	@cd formal/tamarin && tamarin-prover --diff MeowDuressEquivPQ_NEGATIVE_NoKEMBinding.spthy --prove || echo "✅ Test 1 failed as expected"
	@echo "Test 2: Non-uniform failure observables → PQ_Failure_Uniform_Observable should FAIL"
	@cd formal/tamarin && tamarin-prover --diff MeowDuressEquivPQ_NEGATIVE_LeaksFailureReason.spthy --prove || echo "✅ Test 2 failed as expected"

formal-negative-tamarin-docker:
	@echo "🔴 Running Tamarin PQ NEGATIVE tests via Docker..."
	docker run --rm meow-tamarin bash -c "\
		tamarin-prover --diff /formal/tamarin/MeowDuressEquivPQ_NEGATIVE_NoKEMBinding.spthy --prove || echo '✅ Test 1 failed as expected'; \
		tamarin-prover --diff /formal/tamarin/MeowDuressEquivPQ_NEGATIVE_LeaksFailureReason.spthy --prove || echo '✅ Test 2 failed as expected'"

formal-all: formal-proverif formal-tla formal-tla-fountain formal-tla-streaming formal-tamarin-duress formal-verus formal-lean
	@echo ""
	@echo "✅ All formal verification complete!"
	@echo "📊 See docs/formal_coverage.md for coverage matrix"

\# CI-friendly target: runs available tools, skips missing ones, fails on errors
formal-ci:
	@echo "🔬 Running CI formal verification gates..."
	@FAIL=0; \
	if command -v proverif >/dev/null 2>&1; then \
		echo "── ProVerif ──"; \
		$(MAKE) formal-proverif || FAIL=1; \
	else echo "⏭️  ProVerif not available, skipping"; fi; \
	if command -v tlc >/dev/null 2>&1 || (command -v java >/dev/null 2>&1 && [ -f ~/tla/tla2tools.jar ]); then \
		echo "── TLA+ (MeowEncode) ──"; \
		$(MAKE) formal-tla || FAIL=1; \
		echo "── TLA+ (MeowFountain) ──"; \
		$(MAKE) formal-tla-fountain || FAIL=1; \
		echo "── TLA+ (MeowStreaming) ──"; \
		$(MAKE) formal-tla-streaming || FAIL=1; \
	else echo "⏭️  TLA+ (java) not available, skipping"; fi; \
	if command -v tamarin-prover >/dev/null 2>&1; then \
		echo "── Tamarin (native) ──"; \
		$(MAKE) formal-tamarin-duress || FAIL=1; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "── Tamarin (Docker) ──"; \
		$(MAKE) formal-tamarin-docker || FAIL=1; \
	else echo "⏭️  Tamarin not available (no native or Docker), skipping"; fi; \
	if command -v verus >/dev/null 2>&1; then \
		echo "── Verus (native) ──"; \
		$(MAKE) formal-verus || FAIL=1; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "── Verus (Docker, nightly) ──"; \
		$(MAKE) formal-verus-docker || FAIL=1; \
	else echo "⏭️  Verus not available (no native or Docker), skipping"; fi; \
	if command -v lake >/dev/null 2>&1; then \
		echo "── Lean 4 ──"; \
		$(MAKE) formal-lean || FAIL=1; \
		echo "── Lean sorry gate ──"; \
		$(MAKE) formal-lean-sorry || FAIL=1; \
	else echo "⏭️  Lean not available, skipping"; fi; \
	if [ "$$FAIL" -ne 0 ]; then \
		echo "❌ Formal verification FAILED"; exit 1; \
	else \
		echo "✅ All available formal checks passed!"; \
	fi

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
build-wasm: check-wasm-deps
	@echo "🌐 Building WASM bindings (development)..."
	cd crypto_core && wasm-pack build --target web --dev --features wasm
	@echo "✅ WASM development build complete in crypto_core/pkg/"

# 🔧 Check and install WASM dependencies
check-wasm-deps:
	@echo "🔍 Checking WASM build dependencies..."
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "📦 Rust/Cargo not found. Installing..."; \
		if command -v apk >/dev/null 2>&1; then \
			echo "   Detected Alpine Linux - using apk"; \
			sudo apk add --no-cache rust cargo wasm-pack 2>/dev/null || apk add --no-cache rust cargo wasm-pack; \
		elif command -v apt-get >/dev/null 2>&1; then \
			echo "   Detected Debian/Ubuntu - using apt"; \
			sudo apt-get update && sudo apt-get install -y rustc cargo; \
			cargo install wasm-pack; \
		elif command -v brew >/dev/null 2>&1; then \
			echo "   Detected macOS - using Homebrew"; \
			brew install rust wasm-pack; \
		else \
			echo "❌ Could not detect package manager. Please install Rust manually:"; \
			echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
			echo "   cargo install wasm-pack"; \
			exit 1; \
		fi; \
	fi
	@if ! command -v wasm-pack >/dev/null 2>&1; then \
		echo "📦 wasm-pack not found. Installing..."; \
		if command -v apk >/dev/null 2>&1; then \
			sudo apk add --no-cache wasm-pack 2>/dev/null || apk add --no-cache wasm-pack; \
		else \
			cargo install wasm-pack; \
		fi; \
	fi
	@echo "✅ Dependencies ready"

# 🌐 WASM build (production - optimized)
build-wasm-release: check-wasm-deps
	@echo "🌐 Building WASM bindings (production - optimized)..."
	cd crypto_core && wasm-pack build --target web --release --features wasm
	@echo "🔧 Running wasm-opt for additional optimization..."
	@if command -v wasm-opt >/dev/null 2>&1; then \
		wasm-opt -O3 --strip-debug crypto_core/pkg/crypto_core_bg.wasm -o crypto_core/pkg/crypto_core_bg.wasm; \
		echo "✅ wasm-opt optimization complete"; \
	else \
		echo "⚠️  wasm-opt not found (optional). Install with: cargo install wasm-opt"; \
		echo "   Skipping additional optimization..."; \
	fi
	@echo "✅ WASM production build complete in crypto_core/pkg/"
	@echo "📊 Package size: $$(du -h crypto_core/pkg/*.wasm | cut -f1)"

# 🔮 WASM build with Post-Quantum ML-KEM-1024 support
build-wasm-pq: check-wasm-deps
	@echo "🔮 Building WASM with Post-Quantum ML-KEM-1024 support..."
	cd crypto_core && wasm-pack build --target web --release --features wasm-pq
	@echo "🔧 Running wasm-opt for additional optimization..."
	@if command -v wasm-opt >/dev/null 2>&1; then \
		wasm-opt -O3 --strip-debug crypto_core/pkg/crypto_core_bg.wasm -o crypto_core/pkg/crypto_core_bg.wasm; \
		echo "✅ wasm-opt optimization complete"; \
	else \
		echo "⚠️  wasm-opt not found (optional). Install with: cargo install wasm-opt"; \
		echo "   Skipping additional optimization..."; \
	fi
	@echo "✅ WASM Post-Quantum build complete in crypto_core/pkg/"
	@echo "📊 Package size: $$(du -h crypto_core/pkg/*.wasm | cut -f1)"
	@echo ""
	@echo "🔮 Post-Quantum features enabled:"
	@echo "   - ML-KEM-1024 (Kyber) quantum-resistant key exchange"
	@echo "   - Hybrid X25519 + ML-KEM mode"
	@echo "   - NIST Level 5 security"

# 🌐 WASM Node.js build (for server-side use)
build-wasm-node: check-wasm-deps
	@echo "🌐 Building WASM bindings for Node.js..."
	cd crypto_core && wasm-pack build --target nodejs --release --features wasm
	@echo "✅ WASM Node.js build complete in crypto_core/pkg/"

# 🐱 meow-build - Build WASM + start HTTP server
meow-build: build-wasm
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "🐱 Meow Decoder Demo Server"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@echo "📍 Local URL: http://localhost:8080/examples/wasm_browser_example.html"
	@echo ""
	@echo "💡 In Codespaces/Dev Containers:"
	@echo "   1. Open the 'Ports' tab in the bottom panel"
	@echo "   2. Forward port 8080 (right-click → Forward Port)"
	@echo "   3. Click the forwarded URL + append /examples/wasm_browser_example.html"
	@echo ""
	@echo "⚠️  Port 8080 is NOT auto-forwarded by default (for privacy)."
	@echo "    You must manually forward it to access the demo."
	@echo ""
	@echo "Press Ctrl+C to stop the server"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	python3 -m http.server 8080

# 📦 Prepare WASM demo for deployment (PythonAnywhere, etc.)
prepare-deploy:
	@echo "📦 Preparing WASM demo for deployment..."
	@./scripts/prepare_pythonanywhere.sh
	@echo "📖 See examples/PYTHONANYWHERE_HOSTING.md for hosting instructions"

.DEFAULT_GOAL := help
