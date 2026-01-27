#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

info() { echo "[verify] $*"; }

info "Running formal-methods verification"

# ProVerif
info "ProVerif: symbolic protocol analysis"
if command -v opam >/dev/null 2>&1; then
  eval "$(opam env)" >/dev/null 2>&1 || true
fi
if command -v proverif >/dev/null 2>&1; then
  (cd "$ROOT_DIR/formal/proverif" && proverif meow_encode.pv)
elif command -v docker >/dev/null 2>&1; then
  (cd "$ROOT_DIR/formal/proverif" && ./run.sh --docker)
else
  echo "ProVerif not found. Install via opam (preferred) or use Docker." >&2
  exit 1
fi

# TLA+
info "TLA+: model checking"
if command -v java >/dev/null 2>&1; then
  (cd "$ROOT_DIR/formal/tla" && bash ./run.sh)
else
  echo "Java not found. Required for TLC." >&2
  exit 1
fi

# Tamarin (optional)
info "Tamarin: observational equivalence (optional)"
if command -v tamarin-prover >/dev/null 2>&1; then
  (cd "$ROOT_DIR/formal/tamarin" && bash ./run.sh)
else
  if [ "${CI:-}" = "true" ]; then
    echo "Tamarin not installed in CI; skipping equivalence check." >&2
  else
    echo "Tamarin not found. Install tamarin-prover to run equivalence check." >&2
    exit 1
  fi
fi

# Rust tests (crypto_core)
info "Rust tests: crypto_core"
if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT_DIR" && cargo test -p crypto_core)
else
  echo "cargo not found. Install Rust toolchain." >&2
  exit 1
fi

# Verus proofs
info "Verus: crypto wrapper proofs"
if command -v verus >/dev/null 2>&1; then
  (cd "$ROOT_DIR/crypto_core" && verus src/lib.rs)
else
  if [ "${CI:-}" = "true" ]; then
    echo "Verus not installed in CI; skipping proofs. Run locally with verus in PATH." >&2
  else
    echo "Verus not found. Install Verus to run proofs." >&2
    exit 1
  fi
fi

info "All verification steps completed."