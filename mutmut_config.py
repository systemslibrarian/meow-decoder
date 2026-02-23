"""
mutmut configuration for Meow Decoder mutation testing.

Focuses mutation testing on security-critical modules where
surviving mutants would indicate insufficient test coverage.

Usage:
    pip install mutmut
    mutmut run
    mutmut results
    mutmut html  # Generate HTML report
"""


def pre_mutation(context):
    """Skip mutations in non-security-critical code."""
    # Skip test files, examples, and archive code
    skip_prefixes = (
        "tests/",
        "examples/",
        "fuzz/",
        "scripts/",
        "meow_decoder/_archive",
        "meow_decoder/progress",
        "meow_decoder/webcam",
        "meow_decoder/profiling",
    )
    if context.filename.startswith(skip_prefixes):
        context.skip = True
        return

    # Focus on security-critical modules
    security_critical = (
        "meow_decoder/crypto.py",
        "meow_decoder/crypto_enhanced.py",
        "meow_decoder/crypto_backend.py",
        "meow_decoder/ratchet.py",
        "meow_decoder/fountain.py",
        "meow_decoder/pq_hybrid.py",
        "meow_decoder/forward_secrecy.py",
        "meow_decoder/x25519_forward_secrecy.py",
        "meow_decoder/schrodinger_encode.py",
        "meow_decoder/quantum_mixer.py",
        "meow_decoder/constant_time.py",
        "meow_decoder/encode.py",
        "meow_decoder/decode_gif.py",
        "meow_decoder/config.py",
    )
    if context.filename not in security_critical:
        context.skip = True
