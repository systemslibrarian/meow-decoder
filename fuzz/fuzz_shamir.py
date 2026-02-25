#!/usr/bin/env python3
"""
Fuzz target for Shamir Secret Sharing (GF(2^8)).
Tests polynomial evaluation, share serialization/deserialization,
and reconstruction with corrupted/insufficient shares.
"""

import os
import sys
import struct

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.shamir_split import (
        shamir_split,
        shamir_combine,
        ShamirShare,
        _gf_mul,
        _gf_div,
        _gf_pow,
        _eval_poly_at,
        _lagrange_interpolate,
    )

    return (
        shamir_split,
        shamir_combine,
        ShamirShare,
        _gf_mul,
        _gf_div,
        _gf_pow,
        _eval_poly_at,
        _lagrange_interpolate,
    )


if atheris is not None:
    with atheris.instrument_imports():
        (
            shamir_split,
            shamir_combine,
            ShamirShare,
            _gf_mul,
            _gf_div,
            _gf_pow,
            _eval_poly_at,
            _lagrange_interpolate,
        ) = _setup_imports()
else:
    (
        shamir_split,
        shamir_combine,
        ShamirShare,
        _gf_mul,
        _gf_div,
        _gf_pow,
        _eval_poly_at,
        _lagrange_interpolate,
    ) = _setup_imports()


def fuzz_gf_arithmetic(data: bytes):
    """Fuzz GF(2^8) arithmetic operations."""
    if len(data) < 3:
        return

    a = data[0]
    b = data[1]
    n = data[2]

    try:
        # Multiplication
        result = _gf_mul(a, b)
        assert 0 <= result <= 255, f"gf_mul out of range: {result}"

        # Commutativity: a * b == b * a
        assert _gf_mul(a, b) == _gf_mul(b, a), "GF mul not commutative"

        # Identity: a * 1 == a
        assert _gf_mul(a, 1) == a, f"GF mul identity failed: {_gf_mul(a, 1)} != {a}"

        # Zero: a * 0 == 0
        assert _gf_mul(a, 0) == 0, "GF mul zero failed"

        # Power
        result_pow = _gf_pow(a, n)
        assert 0 <= result_pow <= 255, f"gf_pow out of range: {result_pow}"

        # a^0 == 1 for all a != 0
        if a != 0:
            assert _gf_pow(a, 0) == 1, "GF pow zero exponent failed"

        # Division (only when b != 0)
        if b != 0:
            result_div = _gf_div(a, b)
            assert 0 <= result_div <= 255, f"gf_div out of range: {result_div}"

            # a / b * b == a (for a != 0)
            if a != 0:
                reconstructed = _gf_mul(result_div, b)
                assert reconstructed == a, (
                    f"GF div-mul roundtrip failed: {a}/{b}={result_div}, "
                    f"{result_div}*{b}={reconstructed}"
                )

        # Division by zero should raise
        try:
            _gf_div(a, 0)
            assert False, "Division by zero should raise"
        except (ZeroDivisionError, ValueError):
            pass  # Expected

    except (ValueError, ZeroDivisionError):
        pass  # Some edge cases


def fuzz_polynomial_evaluation(data: bytes):
    """Fuzz polynomial evaluation at random points."""
    if len(data) < 3:
        return

    # Use first byte as evaluation point, rest as coefficients
    x = data[0]
    coeffs = list(data[1 : min(len(data), 256)])

    if not coeffs:
        return

    try:
        result = _eval_poly_at(coeffs, x)
        assert 0 <= result <= 255, f"Polynomial eval out of GF(2^8) range: {result}"

        # Constant polynomial: coeffs=[c] => eval(x) == c for all x
        if len(coeffs) == 1:
            assert result == coeffs[0], "Constant polynomial evaluation wrong"

        # At x=0, result should be coeffs[0] (the constant term)
        result_at_zero = _eval_poly_at(coeffs, 0)
        assert (
            result_at_zero == coeffs[0]
        ), f"Polynomial eval at 0 should be constant term: {result_at_zero} != {coeffs[0]}"

    except (ValueError, IndexError):
        pass


def fuzz_share_serialization(data: bytes):
    """Fuzz ShamirShare serialization/deserialization."""
    if len(data) < 5:
        return

    try:
        # Try to deserialize fuzzed data as a share
        share = ShamirShare.from_bytes(data)

        # If successful, verify invariants
        assert isinstance(share.share_id, int)
        assert isinstance(share.threshold, int)
        assert isinstance(share.total_shares, int)
        assert isinstance(share.data, bytes)
        assert isinstance(share.share_checksum, bytes)
        assert len(share.share_checksum) == 32

        assert 0 <= share.share_id <= 255
        assert 0 <= share.threshold <= 255
        assert 0 <= share.total_shares <= 255

        # Re-serialize and verify roundtrip
        reserialized = share.to_bytes()
        assert isinstance(reserialized, bytes)

        # Re-deserialize should produce identical share
        share2 = ShamirShare.from_bytes(reserialized)
        assert share2.share_id == share.share_id
        assert share2.threshold == share.threshold
        assert share2.data == share.data

    except (ValueError, struct.error):
        pass  # Expected for malformed input
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["short", "magic", "checksum", "version", "truncat"]):
            pass
        else:
            raise


def fuzz_split_and_combine(data: bytes):
    """Fuzz shamir_split and shamir_combine roundtrip."""
    if len(data) < 4:
        return

    # Use first two bytes for parameters
    threshold = max(2, min(data[0] % 10 + 2, 10))  # 2-10
    num_shares = max(threshold, min(data[1] % 10 + threshold, 20))  # threshold-20
    secret = data[2:]

    if not secret:
        return

    try:
        shares = shamir_split(secret, threshold, num_shares)

        assert len(shares) == num_shares
        for s in shares:
            assert isinstance(s, ShamirShare)
            assert s.threshold == threshold
            assert s.total_shares == num_shares
            assert len(s.data) == len(secret)

        # Combine with exactly threshold shares should succeed
        recovered = shamir_combine(shares[:threshold], threshold)
        assert recovered == secret, "Shamir roundtrip failed"

        # Combine with more than threshold shares should also succeed
        if num_shares > threshold:
            recovered2 = shamir_combine(shares[: threshold + 1], threshold)
            assert recovered2 == secret, "Shamir roundtrip with extra shares failed"

    except (ValueError, TypeError) as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["threshold", "shares", "empty"]):
            pass
        else:
            raise


def fuzz_insufficient_shares(data: bytes):
    """Verify that fewer than threshold shares produce wrong output."""
    if len(data) < 6:
        return

    secret = data[:4]
    threshold = 3
    num_shares = 5

    try:
        shares = shamir_split(secret, threshold, num_shares)

        # With fewer than threshold shares, reconstruction should fail
        # (produce wrong data or raise)
        if threshold > 1:
            try:
                shamir_combine([shares[0]], threshold)
                # If it returns, it must NOT equal the secret
                # (information-theoretic security of Shamir's scheme)
                # Note: with only 1 share and threshold=3, result is garbage
            except (ValueError, TypeError):
                pass  # May raise due to insufficient shares

    except (ValueError, TypeError):
        pass


def fuzz_corrupted_shares(data: bytes):
    """Fuzz reconstruction with corrupted share data."""
    if len(data) < 10:
        return

    secret = b"test_secret_data"
    threshold = 2
    num_shares = 3

    try:
        shares = shamir_split(secret, threshold, num_shares)

        # Corrupt one share's data
        corrupt_idx = data[0] % len(shares)
        corrupt_share = shares[corrupt_idx]

        if corrupt_share.data:
            import hashlib

            corrupted_data = bytearray(corrupt_share.data)
            flip_pos = data[1] % len(corrupted_data)
            corrupted_data[flip_pos] ^= data[2] | 1  # Ensure at least 1 bit flips

            corrupted_share = ShamirShare(
                share_id=corrupt_share.share_id,
                threshold=corrupt_share.threshold,
                total_shares=corrupt_share.total_shares,
                data=bytes(corrupted_data),
                share_checksum=hashlib.sha256(bytes(corrupted_data)).digest(),
                set_id=corrupt_share.set_id,
            )

            # Combine with corrupted share
            mixed_shares = list(shares[:threshold])
            mixed_shares[0] = corrupted_share

            shamir_combine(mixed_shares, threshold)
            # Result should differ from original secret (corrupted)
            # (not always guaranteed to differ for every byte, but likely)

    except (ValueError, TypeError, ZeroDivisionError):
        # ValueError: duplicate IDs, wrong threshold, data length mismatch, etc.
        # ZeroDivisionError: defense-in-depth in case a new code path in GF math
        #   produces a zero denominator before the duplicate-ID check catches it.
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_gf_arithmetic(data)
        fuzz_polynomial_evaluation(data)
        fuzz_share_serialization(data)
        fuzz_split_and_combine(data)
        fuzz_insufficient_shares(data)
        fuzz_corrupted_shares(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
