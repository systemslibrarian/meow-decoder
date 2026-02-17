"""
legacy_py — Quarantined Legacy Modules

These modules are NOT part of the production crypto pipeline.
They are preserved for:
  - Audit traceability (pq_crypto_real.py — OPUS-AUDIT D1)
  - Legacy format support (x25519_pem_legacy.py — PEM key parsing)

WARNING: Modules in this directory may import the Python `cryptography`
         library. They are excluded from the production import ban enforced
         by tests/test_crypto_enforcement.py.

DO NOT import these modules from production code under meow_decoder/.
"""
