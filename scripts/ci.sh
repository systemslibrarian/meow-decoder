#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log()  { printf "\n==> %s\n" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" >&2; }
die()  { printf "\n[error] %s\n" "$*" >&2; exit 1; }

log "Repo: $ROOT_DIR"
log "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

PY="${PYTHON:-python}"
if ! command -v "$PY" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PY=python3
  else
    die "Python not found"
  fi
fi

log "Python: $($PY --version)"

VENV="${VENV_PATH:-.venv}"
if [[ ! -d "$VENV" ]]; then
  log "Creating venv: $VENV"
  "$PY" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate" 2>/dev/null || source "$VENV/Scripts/activate"

python -m pip install --upgrade pip wheel setuptools >/dev/null

# Install deps
if [[ -f "requirements.txt" ]]; then
  log "Installing runtime deps: requirements.txt"
  pip install -r requirements.txt
else
  warn "requirements.txt not found; skipping"
fi

if [[ -f "requirements-dev.txt" ]]; then
  log "Installing dev deps: requirements-dev.txt"
  pip install -r requirements-dev.txt
else
  warn "requirements-dev.txt not found; skipping"
fi

# Install package if it looks installable
if [[ -f "pyproject.toml" || -f "setup.py" ]]; then
  log "Installing project (editable)"
  pip install -e .
else
  warn "No pyproject.toml/setup.py found; skipping pip install -e ."
fi

# ---- Format / Lint ----
if command -v black >/dev/null 2>&1; then
  log "black --check"
  black --check .
else
  warn "black not installed; skipping"
fi

if command -v flake8 >/dev/null 2>&1; then
  log "flake8"
  flake8 .
else
  warn "flake8 not installed; skipping"
fi

# mypy is optional unless you enforce it
if command -v mypy >/dev/null 2>&1; then
  if [[ "${STRICT_MYPY:-0}" == "1" ]]; then
    log "mypy (STRICT)"
    mypy .
  else
    log "mypy (non-fatal; set STRICT_MYPY=1 to enforce)"
    mypy . || warn "mypy issues (non-fatal)"
  fi
else
  warn "mypy not installed; skipping"
fi

# ---- Tests ----
if command -v pytest >/dev/null 2>&1; then
  log "Invariant tests (MUST NOT FAIL)"
  MEOW_TEST_MODE=1 pytest tests/test_invariants.py -v

  log "Full test suite with coverage"
  pytest --cov=meow_decoder --cov-report=xml --cov-report=term-missing
else
  die "pytest not installed"
fi

log "CI script complete ✅"
