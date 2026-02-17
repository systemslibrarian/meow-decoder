#!/bin/bash
set -e
cd "$(dirname "$0")"

tamarin-prover --diff MeowDuressEquiv.spthy --prove
