#!/bin/bash
set -e
cd "$(dirname "$0")"

tamarin-prover --prove meow_encode_equiv.spthy
