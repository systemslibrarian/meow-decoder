#!/usr/bin/env bash
set -euo pipefail

log() { printf "\n==> %s\n" "$*"; }

log "Python: $(python --version)"

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

log "Invariant tests (MUST NOT FAIL)"
MEOW_TEST_MODE=1 pytest tests/test_invariants.py -v

log "Full test suite with coverage"
pytest \
  --cov=meow_decoder \
  --cov-report=xml:coverage.xml \
  --cov-report=term-missing

log "CI complete ✅"
