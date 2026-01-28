#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# CI entrypoint: "run what CI runs" (local + GitHub Actions)
# ------------------------------------------------------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log()  { printf "\n==> %s\n" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" >&2; }
die()  { printf "\n[error] %s\n" "$*" >&2; exit 1; }

is_ci="${CI:-false}"

log "Repo: $ROOT_DIR"
log "CI: ${is_ci}"

# Helpful context
if command -v git >/dev/null 2>&1; then
  log "Git: $(git rev-parse --short HEAD 2>/dev/null || true)"
fi

# -------------------------
# Helpers: Python
# -------------------------
run_python_ci() {
  log "Python detected"

  # Prefer uv if present, else python -m venv + pip
  if command -v uv >/dev/null 2>&1 && [[ -f "pyproject.toml" ]]; then
    log "Using uv (pyproject.toml)"
    uv sync --dev
    log "Running: ruff (if configured)"
    uv run ruff check . || warn "ruff not configured or failed"
    log "Running: pytest"
    uv run pytest -q
    return 0
  fi

  # Fallback: plain python
  if ! command -v python >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    alias python=python3
  fi
  command -v python >/dev/null 2>&1 || die "Python not found"

  # Create venv locally (ignored by git)
  local venv=".venv"
  if [[ ! -d "$venv" ]]; then
    log "Creating venv: $venv"
    python -m venv "$venv"
  fi

  # shellcheck disable=SC1091
  source "$venv/bin/activate" 2>/dev/null || source "$venv/Scripts/activate"

  log "Python: $(python --version)"

  python -m pip install --upgrade pip wheel setuptools >/dev/null

  if [[ -f "requirements-dev.txt" ]]; then
    log "Installing requirements-dev.txt"
    python -m pip install -r requirements-dev.txt
  elif [[ -f "requirements.txt" ]]; then
    log "Installing requirements.txt"
    python -m pip install -r requirements.txt
  elif [[ -f "pyproject.toml" ]]; then
    warn "pyproject.toml found but uv/poetry not configured here. Consider adding uv/poetry install steps."
  else
    warn "No Python dependency file found; continuing."
  fi

  # Run formatting/lint if present
  if command -v ruff >/dev/null 2>&1; then
    log "Running: ruff check ."
    ruff check .
  elif command -v flake8 >/dev/null 2>&1; then
    log "Running: flake8"
    flake8
  else
    warn "No Python linter found (ruff/flake8)."
  fi

  # Run tests
  if command -v pytest >/dev/null 2>&1; then
    log "Running: pytest"
    pytest -q
  elif [[ -d "tests" ]]; then
    log "Running: python -m unittest"
    python -m unittest -q
  else
    warn "No tests detected for Python."
  fi
}

# -------------------------
# Helpers: Node
# -------------------------
run_node_ci() {
  log "Node detected"

  command -v node >/dev/null 2>&1 || die "node not found"
  command -v npm >/dev/null 2>&1 || die "npm not found"

  log "Node: $(node --version)"
  log "npm:  $(npm --version)"

  if [[ -f "package-lock.json" ]]; then
    log "Installing: npm ci"
    npm ci
  else
    log "Installing: npm install"
    npm install
  fi

  # Lint
  if npm run -s lint >/dev/null 2>&1; then
    log "Running: npm run lint"
    npm run lint
  else
    warn "No npm lint script found."
  fi

  # Tests
  if npm run -s test >/dev/null 2>&1; then
    log "Running: npm test"
    npm test
  else
    warn "No npm test script found."
  fi

  # Build (optional)
  if npm run -s build >/dev/null 2>&1; then
    log "Running: npm run build"
    npm run build
  else
    warn "No npm build script found."
  fi
}

# -------------------------
# Helpers: Rust
# -------------------------
run_rust_ci() {
  log "Rust detected"

  command -v cargo >/dev/null 2>&1 || die "cargo not found"
  log "Rust: $(rustc --version 2>/dev/null || echo 'rustc missing')"
  log "Cargo: $(cargo --version)"

  log "Running: cargo fmt (check)"
  cargo fmt --all -- --check

  log "Running: cargo clippy"
  cargo clippy --all-targets --all-features -- -D warnings

  log "Running: cargo test"
  cargo test --all-features
}

# -------------------------
# Decide what to run
# -------------------------
ran_any=false

if [[ -f "pyproject.toml" || -f "requirements.txt" || -f "requirements-dev.txt" ]]; then
  run_python_ci
  ran_any=true
fi

if [[ -f "package.json" ]]; then
  run_node_ci
  ran_any=true
fi

if [[ -f "Cargo.toml" ]]; then
  run_rust_ci
  ran_any=true
fi

if [[ "$ran_any" == "false" ]]; then
  warn "No recognized project type (Python/Node/Rust). Nothing to run."
  warn "Tip: extend scripts/ci.sh with your repo-specific commands."
fi

log "CI script complete ✅"