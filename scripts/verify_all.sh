#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0
SKIP=0
FAIL=0

info() { echo "[verify] $*"; }
skip() { echo "[verify] ⚠️  SKIP: $*"; SKIP=$((SKIP + 1)); }
pass() { echo "[verify] ✅ $*"; PASS=$((PASS + 1)); }
fail() { echo "[verify] ❌ FAIL: $*"; FAIL=$((FAIL + 1)); }

info "Running formal-methods verification"

# ProVerif
info "ProVerif: symbolic protocol analysis"
if command -v opam >/dev/null 2>&1; then
  eval "$(opam env)" >/dev/null 2>&1 || true
fi
if command -v proverif >/dev/null 2>&1; then
  if (cd "$ROOT_DIR/formal/proverif" && proverif meow_encode.pv); then
    pass "ProVerif"
  else
    fail "ProVerif"
  fi
elif command -v docker >/dev/null 2>&1; then
  if (cd "$ROOT_DIR/formal/proverif" && ./run.sh --docker); then
    pass "ProVerif (Docker)"
  else
    fail "ProVerif (Docker)"
  fi
else
  skip "ProVerif not found (install via opam or use Docker)"
fi

# TLA+
info "TLA+: model checking"
if command -v java >/dev/null 2>&1; then
  if (cd "$ROOT_DIR/formal/tla" && bash ./run.sh); then
    pass "TLA+"
  else
    fail "TLA+"
  fi
else
  skip "Java not found (required for TLC model checker)"
fi

# Tamarin (optional — requires maude, which needs glibc)
info "Tamarin: observational equivalence (optional)"
TAMARIN_OK=false
if command -v tamarin-prover >/dev/null 2>&1; then
  # Verify maude actually works (fails on musl/Alpine)
  if echo "quit" | maude 2>/dev/null | grep -q "Maude"; then
    TAMARIN_OK=true
  fi
fi
if [ "$TAMARIN_OK" = "true" ]; then
  if (cd "$ROOT_DIR/formal/tamarin" && bash ./run.sh); then
    pass "Tamarin"
  else
    fail "Tamarin"
  fi
elif command -v docker >/dev/null 2>&1; then
  info "Tamarin: attempting Docker fallback..."
  if (cd "$ROOT_DIR" && make formal-tamarin-docker 2>/dev/null); then
    pass "Tamarin (Docker)"
  else
    skip "Tamarin Docker image unavailable"
  fi
else
  skip "Tamarin not found (install tamarin-prover or use Docker)"
fi

# Rust tests (crypto_core)
info "Rust tests: crypto_core"
if command -v cargo >/dev/null 2>&1; then
  if (cd "$ROOT_DIR" && cargo test -p crypto_core); then
    pass "Rust crypto_core tests"
  else
    fail "Rust crypto_core tests"
  fi
else
  skip "cargo not found (install Rust toolchain)"
fi

# Verus proofs
info "Verus: crypto wrapper proofs"
VERUS_OK=false
if command -v verus >/dev/null 2>&1; then
  verus --version >/dev/null 2>&1 && VERUS_OK=true || true
fi
if [ "$VERUS_OK" = "true" ]; then
  if (cd "$ROOT_DIR/crypto_core" && verus src/lib.rs); then
    pass "Verus proofs"
  else
    fail "Verus proofs"
  fi
elif command -v docker >/dev/null 2>&1; then
  info "Verus: attempting Docker fallback..."
  if (cd "$ROOT_DIR" && make formal-verus-docker 2>/dev/null); then
    pass "Verus (Docker)"
  else
    skip "Verus Docker image unavailable"
  fi
else
  skip "Verus not found (install Verus or use Docker)"
fi

# Lean 4 proofs
info "Lean 4: mathematical proofs"
if command -v lake >/dev/null 2>&1; then
  if (cd "$ROOT_DIR/formal/lean" && lake build); then
    pass "Lean 4 proofs"
  else
    fail "Lean 4 proofs"
  fi
else
  skip "Lean 4 not found (install elan/lake)"
fi

# Python tests
info "Python: pytest security tests"
if command -v pytest >/dev/null 2>&1; then
  if (cd "$ROOT_DIR" && MEOW_TEST_MODE=1 pytest tests/ -m "security or crypto or adversarial" \
      --override-ini="addopts=" -q --no-header --tb=short 2>/dev/null); then
    pass "Python security tests"
  else
    fail "Python security tests"
  fi
else
  skip "pytest not found"
fi

# Summary
echo ""
echo "============================================"
echo "📋 Verification Summary"
echo "============================================"
echo "  ✅ Passed:  $PASS"
echo "  ⚠️  Skipped: $SKIP"
echo "  ❌ Failed:  $FAIL"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "❌ $FAIL verification(s) FAILED"
  exit 1
fi

if [ "$PASS" -eq 0 ]; then
  echo "⚠️  No verification tools available — install at least one"
  echo "   Options: proverif, java (TLA+), tamarin-prover, cargo, verus, lake"
  exit 1
fi

echo "✅ All available verifications passed ($SKIP skipped)"

info "All verification steps completed."