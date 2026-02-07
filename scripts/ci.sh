#!/usr/bin/env bash
set -euo pipefail

log() { printf "\n==> %s\n" "$*"; }

log "Python: $(python --version)"

python -m pip install --upgrade pip
# Use lock files with hashes for supply chain security (OpenSSF Scorecard)
pip install --require-hashes -r requirements.lock
pip install --require-hashes -r requirements-dev.lock
pip install -e .

log "Invariant tests (MUST NOT FAIL)"
MEOW_TEST_MODE=1 pytest tests/test_invariants.py -v

log "Full test suite with coverage"
pytest \
  --cov=meow_decoder \
  --cov-report=xml:coverage.xml \
  --cov-report=term-missing

log "CI complete ✅"
