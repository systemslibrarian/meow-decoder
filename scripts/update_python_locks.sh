#!/usr/bin/env bash
# Resolve CI pins first, then keep development and runtime pins compatible.
set -euo pipefail
cd "$(dirname "$0")/.."
uv pip compile --generate-hashes requirements-ci.in -o requirements-ci.lock
uv pip compile --generate-hashes requirements-dev.txt -c requirements-ci.lock -o requirements-dev.lock
uv pip compile --generate-hashes requirements.txt -c requirements-ci.lock -c requirements-dev.lock -o requirements.lock
