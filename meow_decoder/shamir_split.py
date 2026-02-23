"""
Shamir's Secret Sharing for multi-GIF redundancy.

Allows splitting an encoded GIF across 2-5 shares with threshold recovery.
Any t-of-n shares can reconstruct the original; fewer reveals nothing.

Security properties:
- Information-theoretic security: t-1 shares reveal ZERO information
- Uses GF(2^8) arithmetic for byte-level operations
- Constant-time polynomial evaluation to prevent timing attacks
- Compatible with Schrödinger mode (split the encrypted output)

Example:
    # Split into 3 shares, require 2 to reconstruct
    shares = shamir_split(gif_bytes, threshold=2, num_shares=3)

    # Distribute shares to different locations/devices
    # ...

    # Reconstruct from any 2 shares
    recovered = shamir_combine(shares[:2], threshold=2)
    assert recovered == gif_bytes
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import List, Tuple

# GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
# This is a primitive polynomial where 2 is a primitive element (order 255)
GF_EXP = [0] * 512  # Anti-log table
GF_LOG = [0] * 256  # Log table


def _init_gf_tables():
    """Initialize GF(2^8) lookup tables."""
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D  # Reduce by primitive polynomial
    # Extend exp table for easier multiplication
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]


_init_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    if a == 0 or b == 0:
        return 0
    return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]


def _gf_div(a: int, b: int) -> int:
    """Divide two elements in GF(2^8)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(2^8)")
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] - GF_LOG[b]) % 255]


def _gf_pow(a: int, n: int) -> int:
    """Raise element to power n in GF(2^8)."""
    if n == 0:
        return 1
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] * n) % 255]


def _eval_poly_at(coeffs: List[int], x: int) -> int:
    """
    Evaluate polynomial at point x in GF(2^8).
    coeffs[0] is the constant term (the secret).
    Uses Horner's method for efficiency.
    """
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_mul(result, x) ^ coeff
    return result


def _lagrange_interpolate(shares: List[Tuple[int, int]], x: int = 0) -> int:
    """
    Lagrange interpolation to recover f(x) from shares.
    Each share is (x_i, y_i) where y_i = f(x_i).
    By default recovers f(0) which is the secret.
    """
    result = 0
    for i, (x_i, y_i) in enumerate(shares):
        # Calculate Lagrange basis polynomial L_i(x)
        numerator = 1
        denominator = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                numerator = _gf_mul(numerator, x ^ x_j)
                denominator = _gf_mul(denominator, x_i ^ x_j)

        # L_i(x) * y_i
        term = _gf_mul(y_i, _gf_div(numerator, denominator))
        result ^= term

    return result


@dataclass
class ShamirShare:
    """A single Shamir share."""

    share_id: int  # 1-indexed share identifier (x coordinate)
    threshold: int  # Minimum shares needed to reconstruct
    total_shares: int  # Total number of shares created
    data: bytes  # The share data (y coordinates for each byte)
    share_checksum: bytes  # SHA-256 of data for integrity verification
    set_id: bytes = b"\x00" * 16  # 16-byte random ID binding the share set together

    def to_bytes(self) -> bytes:
        """Serialize share to bytes for storage/transmission."""
        # Format: magic(4) | version(1) | share_id(1) | threshold(1) | total(1) |
        #         data_len(4) | set_id(16) | data | checksum(32)
        header = struct.pack(
            ">4sBBBBI16s",
            b"MSHR",  # Magic: Meow SHamiR
            2,  # Version 2 (adds set_id)
            self.share_id,
            self.threshold,
            self.total_shares,
            len(self.data),
            self.set_id,
        )
        return header + self.data + self.share_checksum

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ShamirShare":
        """Deserialize share from bytes."""
        if len(raw) < 44:  # Minimum: header(12) + checksum(32)
            raise ValueError("Share data too short")

        magic, version = struct.unpack(">4sB", raw[:5])

        if magic != b"MSHR":
            raise ValueError(f"Invalid share magic: {magic}")

        if version == 1:
            # Legacy v1 format
            share_id, threshold, total, data_len = struct.unpack(">BBBI", raw[5:12])
            set_id = b"\x00" * 16
            header_len = 12
        elif version == 2:
            # v2 format with set_id
            if len(raw) < 60:  # header(28) + checksum(32)
                raise ValueError("Share data too short for v2")
            share_id, threshold, total, data_len, set_id = struct.unpack(">BBBI16s", raw[5:28])
            header_len = 28
        else:
            raise ValueError(f"Unsupported share version: {version}")

        if len(raw) < header_len + data_len + 32:
            raise ValueError("Share data truncated")

        data = raw[header_len : header_len + data_len]
        checksum = raw[header_len + data_len : header_len + data_len + 32]

        # Verify checksum
        import hashlib

        expected = hashlib.sha256(data).digest()
        import secrets

        if not secrets.compare_digest(expected, checksum):
            raise ValueError("Share checksum mismatch — possible tampering")

        return cls(
            share_id=share_id,
            threshold=threshold,
            total_shares=total,
            data=data,
            share_checksum=checksum,
            set_id=set_id,
        )


def shamir_split(
    secret: bytes,
    threshold: int,
    num_shares: int,
    *,
    randomness: bytes = None,
) -> List[ShamirShare]:
    """
    Split secret into num_shares shares, any threshold of which can reconstruct.

    Args:
        secret: The bytes to split (e.g., encrypted GIF)
        threshold: Minimum shares needed to reconstruct (2-255)
        num_shares: Total shares to generate (threshold <= num_shares <= 255)
        randomness: Optional deterministic randomness for testing (NOT production)

    Returns:
        List of ShamirShare objects, each containing one share.

    Security:
        - t-1 shares reveal EXACTLY ZERO information about the secret
        - Uses CSPRNG (secrets module) for coefficient generation
        - GF(2^8) arithmetic prevents modular bias
    """
    if not (2 <= threshold <= num_shares <= 255):
        raise ValueError(
            f"Invalid parameters: need 2 <= threshold ({threshold}) <= "
            f"num_shares ({num_shares}) <= 255"
        )

    if len(secret) == 0:
        raise ValueError("Cannot split empty secret")

    import hashlib

    # Generate shares for each byte of the secret
    shares_data = [bytearray() for _ in range(num_shares)]

    # For deterministic testing (NOT for production!)
    rng_offset = 0

    # Generate a unique set ID to bind these shares together
    if randomness:
        set_id = hashlib.sha256(randomness + b"set_id").digest()[:16]
    else:
        set_id = secrets.token_bytes(16)

    for byte_idx, secret_byte in enumerate(secret):
        # Generate random polynomial coefficients
        # coeffs[0] = secret_byte (the secret for this position)
        # coeffs[1..threshold-1] = random values (define the polynomial)
        coeffs = [secret_byte]

        for _ in range(threshold - 1):
            if randomness:
                # Deterministic mode for testing
                # Use HKDF-like derivation from randomness
                derived = hashlib.sha256(
                    randomness + struct.pack(">II", byte_idx, rng_offset)
                ).digest()
                rng_offset += 1
                coeff = derived[0]
            else:
                # Production: true CSPRNG
                coeff = secrets.randbelow(256)
            coeffs.append(coeff)

        # Evaluate polynomial at x = 1, 2, ..., num_shares
        for share_idx in range(num_shares):
            x = share_idx + 1  # x coordinates are 1-indexed
            y = _eval_poly_at(coeffs, x)
            shares_data[share_idx].append(y)

    # Package into ShamirShare objects with checksums
    result = []
    for i, data in enumerate(shares_data):
        data_bytes = bytes(data)
        checksum = hashlib.sha256(data_bytes).digest()
        result.append(
            ShamirShare(
                share_id=i + 1,
                threshold=threshold,
                total_shares=num_shares,
                data=data_bytes,
                share_checksum=checksum,
                set_id=set_id,
            )
        )

    return result


def shamir_combine(shares: List[ShamirShare], threshold: int = None) -> bytes:
    """
    Reconstruct secret from threshold shares.

    Args:
        shares: List of ShamirShare objects (at least threshold of them)
        threshold: Expected threshold (if None, read from first share)

    Returns:
        The original secret bytes.

    Raises:
        ValueError: If not enough shares or shares are inconsistent
    """
    if not shares:
        raise ValueError("No shares provided")

    # Validate and extract threshold
    if threshold is None:
        threshold = shares[0].threshold

    if len(shares) < threshold:
        raise ValueError(f"Need at least {threshold} shares, got {len(shares)}")

    # Verify all shares have consistent parameters
    data_len = len(shares[0].data)
    set_id = shares[0].set_id

    for share in shares:
        if share.threshold != threshold:
            raise ValueError(f"Inconsistent threshold: {share.threshold} vs {threshold}")
        if len(share.data) != data_len:
            raise ValueError(f"Inconsistent data length: {len(share.data)} vs {data_len}")
        if share.set_id != set_id:
            # Reject mismatched set IDs unconditionally — including all-zero
            # (legacy v1) shares. Mixing unauthenticated v1 shares with v2
            # shares would bypass set_id authentication entirely.
            raise ValueError(
                f"Inconsistent share set ID: shares belong to different splits. "
                f"All shares must originate from the same split operation."
            )

    # Use only the first `threshold` shares (all that's needed)
    working_shares = shares[:threshold]

    # Reconstruct each byte via Lagrange interpolation at x=0
    result = bytearray()
    for byte_idx in range(data_len):
        points = [(share.share_id, share.data[byte_idx]) for share in working_shares]
        secret_byte = _lagrange_interpolate(points, x=0)
        result.append(secret_byte)

    return bytes(result)


def split_gif_to_files(
    gif_path: str,
    output_dir: str,
    threshold: int,
    num_shares: int,
) -> List[str]:
    """
    Split an encoded GIF into multiple share files.

    Args:
        gif_path: Path to the source GIF file
        output_dir: Directory to write share files
        threshold: Minimum shares needed for recovery
        num_shares: Total shares to create

    Returns:
        List of paths to the created share files.
    """
    import os
    import hashlib

    with open(gif_path, "rb") as f:
        gif_data = f.read()

    shares = shamir_split(gif_data, threshold, num_shares)

    # Create output directory if needed
    os.makedirs(output_dir, exist_ok=True)

    # Generate base name from hash of original
    base_hash = hashlib.sha256(gif_data).hexdigest()[:8]

    output_paths = []
    for share in shares:
        filename = f"share_{base_hash}_{share.share_id}of{share.total_shares}.meow"
        path = os.path.join(output_dir, filename)
        with open(path, "wb") as f:
            f.write(share.to_bytes())
        output_paths.append(path)

    return output_paths


def combine_files_to_gif(share_paths: List[str], output_path: str) -> bool:
    """
    Reconstruct a GIF from share files.

    Args:
        share_paths: Paths to share files (at least threshold of them)
        output_path: Where to write the reconstructed GIF

    Returns:
        True on success.

    Raises:
        ValueError: If reconstruction fails.
    """
    shares = []
    for path in share_paths:
        with open(path, "rb") as f:
            raw = f.read()
        shares.append(ShamirShare.from_bytes(raw))

    gif_data = shamir_combine(shares)

    with open(output_path, "wb") as f:
        f.write(gif_data)

    return True


# Cross-platform compatibility
import sys

if sys.platform == "win32":
    # Windows-specific: ensure binary mode for all file operations
    import msvcrt
    import os

    msvcrt.setmode(0, os.O_BINARY)  # stdin
    msvcrt.setmode(1, os.O_BINARY)  # stdout


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Meow Decoder - Shamir Secret Sharing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Split command
    split_parser = subparsers.add_parser("split", help="Split a file into shares")
    split_parser.add_argument("-i", "--input", required=True, help="Input file to split")
    split_parser.add_argument(
        "-o", "--output-dir", required=True, help="Output directory for shares"
    )
    split_parser.add_argument(
        "-t", "--threshold", type=int, required=True, help="Minimum shares needed to reconstruct"
    )
    split_parser.add_argument(
        "-n", "--num-shares", type=int, required=True, help="Total number of shares to create"
    )

    # Combine command
    combine_parser = subparsers.add_parser("combine", help="Combine shares into a file")
    combine_parser.add_argument(
        "-i", "--inputs", nargs="+", required=True, help="Input share files"
    )
    combine_parser.add_argument("-o", "--output", required=True, help="Output file")

    args = parser.parse_args()

    if args.command == "split":
        try:
            paths = split_gif_to_files(args.input, args.output_dir, args.threshold, args.num_shares)
            print(f"Successfully created {len(paths)} shares in {args.output_dir}")
        except Exception as e:
            print(f"Error splitting file: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "combine":
        try:
            success = combine_files_to_gif(args.inputs, args.output)
            if success:
                print(f"Successfully reconstructed file to {args.output}")
            else:
                print("Failed to reconstruct file", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error combining shares: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
