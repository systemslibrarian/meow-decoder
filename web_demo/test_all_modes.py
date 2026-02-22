#!/usr/bin/env python3
"""
Comprehensive Web Demo Test Suite

Tests all encoding modes with 5 runs each:
1. Normal Mode - Standard QR encoding
2. Cat Mode - Steganographic encoding with cat carrier (stego_level=2)
3. Cat Mode Server API - Binary encrypt/decrypt for eye-blink transmission
4. Duress Mode - Panic password that reveals decoy data
5. Forward Secrecy Mode - X25519 ephemeral key exchange (MEOW3)
6. Schrödinger Mode - Dual-secret quantum plausible deniability

Experimental modes (not tested - encode-only, no decoder integration yet):
- Logo Eyes Mode (logo_eyes=True) - QR in cat eye regions
- Cat Eyes Blink Mode (cat_eyes_blink=True) - Green pixel blinking

Usage:
    python web_demo/test_all_modes.py
    python web_demo/test_all_modes.py --verbose
"""

import os
import sys
import struct
import tempfile
import secrets
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set test mode for faster Argon2id
os.environ["MEOW_TEST_MODE"] = "1"

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.config import EncodingConfig, DecodingConfig
from meow_decoder.crypto import encrypt_file_bytes_production, decrypt_to_raw_production
from meow_decoder.crypto_backend import get_handle_backend


@dataclass
class TestResult:
    """Result of a single test run."""

    mode: str
    run_number: int
    success: bool
    encode_time: float
    decode_time: float
    file_size: int
    error: Optional[str] = None


def test_normal_mode(run_number: int, verbose: bool = False) -> TestResult:
    """Test normal mode encoding/decoding."""
    start_time = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file with unique content
        test_content = f"Normal Mode Test #{run_number} - {secrets.token_hex(16)}"
        input_file = tmpdir / "test.txt"
        input_file.write_text(test_content)

        output_gif = tmpdir / "output.gif"
        recovered_file = tmpdir / "recovered.txt"
        password = f"normal_test_{run_number}"

        try:
            # Encode
            encode_start = time.time()
            config = EncodingConfig()
            config.redundancy = 1.5
            stats = encode_file(
                input_path=input_file,
                output_path=output_gif,
                password=password,
                config=config,
                verbose=verbose,
            )
            encode_time = time.time() - encode_start
            file_size = output_gif.stat().st_size

            # Decode
            decode_start = time.time()
            decode_config = DecodingConfig()
            decode_gif(
                input_path=output_gif,
                output_path=recovered_file,
                password=password,
                config=decode_config,
                verbose=verbose,
            )
            decode_time = time.time() - decode_start

            # Verify
            recovered_content = recovered_file.read_text()
            if recovered_content == test_content:
                return TestResult(
                    mode="normal",
                    run_number=run_number,
                    success=True,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                )
            else:
                return TestResult(
                    mode="normal",
                    run_number=run_number,
                    success=False,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                    error=f"Content mismatch: expected '{test_content}', got '{recovered_content}'",
                )

        except Exception as e:
            return TestResult(
                mode="normal",
                run_number=run_number,
                success=False,
                encode_time=time.time() - start_time,
                decode_time=0,
                file_size=0,
                error=str(e),
            )


def test_cat_mode(run_number: int, verbose: bool = False) -> TestResult:
    """Test cat mode encoding/decoding with steganography."""
    start_time = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file with unique content
        test_content = f"Cat Mode Test #{run_number} - 😺 {secrets.token_hex(16)}"
        input_file = tmpdir / "test.txt"
        input_file.write_text(test_content)

        output_gif = tmpdir / "cat_output.png"  # APNG for lossless stego
        recovered_file = tmpdir / "recovered.txt"
        password = f"cat_test_{run_number}!"  # 8+ chars

        # Cat carrier image
        cat_carrier = Path(__file__).parent.parent / "assets" / "demo_logo_eyes.gif"
        if not cat_carrier.exists():
            return TestResult(
                mode="cat",
                run_number=run_number,
                success=False,
                encode_time=0,
                decode_time=0,
                file_size=0,
                error=f"Cat carrier not found: {cat_carrier}",
            )

        try:
            # Encode with Cat Mode (stego_level=2)
            encode_start = time.time()
            config = EncodingConfig()
            config.redundancy = 2.5  # Higher redundancy for lossy stego channel
            stats = encode_file(
                input_path=input_file,
                output_path=output_gif,
                password=password,
                config=config,
                stego_level=2,
                carrier_images=[cat_carrier],
                verbose=verbose,
            )
            encode_time = time.time() - encode_start
            file_size = output_gif.stat().st_size

            # Decode
            decode_start = time.time()
            decode_config = DecodingConfig()
            decode_gif(
                input_path=output_gif,
                output_path=recovered_file,
                password=password,
                config=decode_config,
                verbose=verbose,
            )
            decode_time = time.time() - decode_start

            # Verify
            recovered_content = recovered_file.read_text()
            if recovered_content == test_content:
                return TestResult(
                    mode="cat",
                    run_number=run_number,
                    success=True,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                )
            else:
                return TestResult(
                    mode="cat",
                    run_number=run_number,
                    success=False,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                    error=f"Content mismatch",
                )

        except Exception as e:
            import traceback

            return TestResult(
                mode="cat",
                run_number=run_number,
                success=False,
                encode_time=time.time() - start_time,
                decode_time=0,
                file_size=0,
                error=f"{str(e)}\n{traceback.format_exc()}",
            )


def test_duress_mode(run_number: int, verbose: bool = False) -> TestResult:
    """Test duress mode encoding/decoding."""
    start_time = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file with unique content
        test_content = f"Duress Mode Real Secret #{run_number} - {secrets.token_hex(16)}"
        input_file = tmpdir / "test.txt"
        input_file.write_text(test_content)

        output_gif = tmpdir / "duress_output.gif"
        recovered_file = tmpdir / "recovered.txt"

        real_password = f"real_pass_{run_number}"
        duress_password = f"duress_pass_{run_number}"

        try:
            # Duress mode requires a distinct manifest format to avoid size
            # collisions.  Use X25519 forward secrecy (MEOW3 + duress = 180
            # bytes), which is unambiguous.
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization

            private_key = X25519PrivateKey.generate()
            receiver_public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            receiver_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Encode with duress mode + forward secrecy
            encode_start = time.time()
            config = EncodingConfig()
            config.redundancy = 1.5
            stats = encode_file(
                input_path=input_file,
                output_path=output_gif,
                password=real_password,
                duress_password=duress_password,
                config=config,
                receiver_public_key=receiver_public_key,
                verbose=verbose,
            )
            encode_time = time.time() - encode_start
            file_size = output_gif.stat().st_size

            # Decode with real password + private key (should succeed)
            decode_start = time.time()
            decode_config = DecodingConfig()
            decode_gif(
                input_path=output_gif,
                output_path=recovered_file,
                password=real_password,
                receiver_private_key=receiver_private_key,
                config=decode_config,
                verbose=verbose,
            )
            decode_time = time.time() - decode_start

            # Verify real content
            recovered_content = recovered_file.read_text()
            if recovered_content == test_content:
                return TestResult(
                    mode="duress",
                    run_number=run_number,
                    success=True,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                )
            else:
                return TestResult(
                    mode="duress",
                    run_number=run_number,
                    success=False,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                    error=f"Content mismatch with real password",
                )

        except Exception as e:
            import traceback

            return TestResult(
                mode="duress",
                run_number=run_number,
                success=False,
                encode_time=time.time() - start_time,
                decode_time=0,
                file_size=0,
                error=f"{str(e)}\n{traceback.format_exc()}",
            )


def test_cat_mode_server_encryption(run_number: int, verbose: bool = False) -> TestResult:
    """
    Test Cat Mode server-side encryption API (simulates /cat-mode-encrypt-server).

    This tests the binary encrypt/decrypt flow used by Cat Mode eye blinking:
    1. encrypt_file_bytes_production() → binary payload
    2. Binary → hex → (simulated transmission) → hex → binary
    3. decrypt_to_raw_production() → original message
    """
    start_time = time.time()

    # Test message
    message = f"Cat Mode Server Test #{run_number} - 🐱 {secrets.token_hex(8)}"
    message_bytes = message.encode("utf-8")
    password = f"cat_server_{run_number}!"  # 8+ chars

    try:
        # Encrypt (simulating /cat-mode-encrypt-server endpoint)
        encode_start = time.time()
        compressed, sha256_hash, salt, nonce, ciphertext, ephemeral_key, key_handle = (
            encrypt_file_bytes_production(
                raw=message_bytes,
                password=password,
                keyfile=None,
                receiver_public_key=None,
                use_length_padding=False,  # Cat Mode disables padding for faster transmission
            )
        )
        # Drop the key handle — not needed after encryption
        try:
            get_handle_backend().drop(key_handle)
        except Exception:
            pass

        # Pack binary payload (same as app.py)
        orig_len = len(message_bytes)
        comp_len = len(compressed)
        header = struct.pack(">II", orig_len, comp_len) + sha256_hash + salt + nonce
        binary_payload = header + ciphertext

        encode_time = time.time() - encode_start

        # Simulate transmission: binary → hex → (eye blinks) → hex → binary
        payload_hex = binary_payload.hex()
        received_bytes = bytes.fromhex(payload_hex)

        # Decrypt (simulating /decode-cat-binary endpoint)
        decode_start = time.time()

        # Unpack payload
        recv_orig_len, recv_comp_len = struct.unpack(">II", received_bytes[:8])
        recv_sha256 = received_bytes[8:40]
        recv_salt = received_bytes[40:56]
        recv_nonce = received_bytes[56:68]
        recv_ciphertext = received_bytes[68:]

        decrypted_bytes = decrypt_to_raw_production(
            cipher=recv_ciphertext,
            password=password,
            salt=recv_salt,
            nonce=recv_nonce,
            keyfile=None,
            orig_len=recv_orig_len,
            comp_len=recv_comp_len,
            sha256=recv_sha256,
        )

        decode_time = time.time() - decode_start

        # Verify
        decrypted_message = decrypted_bytes.decode("utf-8")
        if decrypted_message == message:
            return TestResult(
                mode="cat_server",
                run_number=run_number,
                success=True,
                encode_time=encode_time,
                decode_time=decode_time,
                file_size=len(binary_payload),
            )
        else:
            return TestResult(
                mode="cat_server",
                run_number=run_number,
                success=False,
                encode_time=encode_time,
                decode_time=decode_time,
                file_size=len(binary_payload),
                error=f"Content mismatch: expected '{message}', got '{decrypted_message}'",
            )

    except Exception as e:
        import traceback

        return TestResult(
            mode="cat_server",
            run_number=run_number,
            success=False,
            encode_time=time.time() - start_time,
            decode_time=0,
            file_size=0,
            error=f"{str(e)}\n{traceback.format_exc()}",
        )


def test_forward_secrecy_mode(run_number: int, verbose: bool = False) -> TestResult:
    """
    Test Forward Secrecy (MEOW3) encoding/decoding.

    Uses X25519 ephemeral key exchange for per-session forward secrecy.
    Even if the password is later compromised, past sessions remain secure.
    """
    start_time = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test file with unique content
        test_content = f"Forward Secrecy Test #{run_number} - 🔐 {secrets.token_hex(16)}"
        input_file = tmpdir / "test.txt"
        input_file.write_text(test_content)

        output_gif = tmpdir / "fs_output.gif"
        recovered_file = tmpdir / "recovered.txt"
        password = f"fs_test_{run_number}!"  # 8+ chars

        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization

            # Generate X25519 receiver keypair
            private_key = X25519PrivateKey.generate()
            receiver_public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            receiver_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Encode with forward secrecy (MEOW3)
            encode_start = time.time()
            stats = encode_file(
                input_path=input_file,
                output_path=output_gif,
                password=password,
                config=EncodingConfig(),
                forward_secrecy=True,
                receiver_public_key=receiver_public_key,
            )
            encode_time = time.time() - encode_start
            file_size = output_gif.stat().st_size

            # Decode with receiver private key
            decode_start = time.time()
            result = decode_gif(
                input_path=output_gif,
                output_path=recovered_file,
                password=password,
                receiver_private_key=receiver_private_key,
                config=DecodingConfig(),
            )
            decode_time = time.time() - decode_start

            # Verify content
            recovered = recovered_file.read_text()
            if recovered == test_content:
                return TestResult(
                    mode="forward_secrecy",
                    run_number=run_number,
                    success=True,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                )
            else:
                return TestResult(
                    mode="forward_secrecy",
                    run_number=run_number,
                    success=False,
                    encode_time=encode_time,
                    decode_time=decode_time,
                    file_size=file_size,
                    error=f"Content mismatch",
                )

        except Exception as e:
            import traceback

            return TestResult(
                mode="forward_secrecy",
                run_number=run_number,
                success=False,
                encode_time=time.time() - start_time,
                decode_time=0,
                file_size=0,
                error=f"{str(e)}\n{traceback.format_exc()}",
            )


def test_schrodinger_mode(run_number: int, verbose: bool = False) -> TestResult:
    """
    Test Schrödinger Mode dual-secret encoding/decoding.

    Encodes two separate secrets into one superposition where the correct
    password determines which reality is revealed. Neither secret can be
    proven to exist without the correct password (quantum plausible deniability).
    """
    start_time = time.time()

    try:
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data

        # Create two separate secrets
        real_secret = f"REAL SECRET #{run_number} - 🐱 {secrets.token_hex(32)}"
        decoy_secret = f"DECOY #{run_number} - innocent cat photos {secrets.token_hex(32)}"

        real_bytes = real_secret.encode("utf-8")
        decoy_bytes = decoy_secret.encode("utf-8")

        real_password = f"real_schrodinger_{run_number}!"
        decoy_password = f"decoy_schrodinger_{run_number}!"

        # Encode: interleave two encrypted realities
        encode_start = time.time()
        superposition, manifest = schrodinger_encode_data(
            real_data=real_bytes,
            decoy_data=decoy_bytes,
            real_password=real_password,
            decoy_password=decoy_password,
            block_size=256,
        )
        encode_time = time.time() - encode_start

        # Decode with real password → should get real secret
        decode_start = time.time()
        recovered_real = schrodinger_decode_data(superposition, manifest, real_password)
        decode_time_real = time.time() - decode_start

        if recovered_real is None:
            return TestResult(
                mode="schrodinger",
                run_number=run_number,
                success=False,
                encode_time=encode_time,
                decode_time=decode_time_real,
                file_size=len(superposition),
                error="Real password returned None",
            )

        if recovered_real != real_bytes:
            return TestResult(
                mode="schrodinger",
                run_number=run_number,
                success=False,
                encode_time=encode_time,
                decode_time=decode_time_real,
                file_size=len(superposition),
                error="Real password returned wrong data",
            )

        # Decode with decoy password → should get decoy secret
        recovered_decoy = schrodinger_decode_data(superposition, manifest, decoy_password)
        if recovered_decoy is None:
            return TestResult(
                mode="schrodinger",
                run_number=run_number,
                success=False,
                encode_time=encode_time,
                decode_time=decode_time_real,
                file_size=len(superposition),
                error="Decoy password returned None",
            )

        if recovered_decoy != decoy_bytes:
            return TestResult(
                mode="schrodinger",
                run_number=run_number,
                success=False,
                encode_time=encode_time,
                decode_time=decode_time_real,
                file_size=len(superposition),
                error="Decoy password returned wrong data",
            )

        # Verify wrong password returns None (no oracle)
        wrong_result = schrodinger_decode_data(superposition, manifest, "wrong_password!")
        if wrong_result is not None:
            return TestResult(
                mode="schrodinger",
                run_number=run_number,
                success=False,
                encode_time=encode_time,
                decode_time=decode_time_real,
                file_size=len(superposition),
                error="Wrong password did not return None",
            )

        decode_time = time.time() - decode_start

        return TestResult(
            mode="schrodinger",
            run_number=run_number,
            success=True,
            encode_time=encode_time,
            decode_time=decode_time,
            file_size=len(superposition),
        )

    except Exception as e:
        import traceback

        return TestResult(
            mode="schrodinger",
            run_number=run_number,
            success=False,
            encode_time=time.time() - start_time,
            decode_time=0,
            file_size=0,
            error=f"{str(e)}\n{traceback.format_exc()}",
        )


def print_result(result: TestResult, verbose: bool = False):
    """Print a single test result."""
    status = "✅ PASS" if result.success else "❌ FAIL"
    print(
        f"  Run {result.run_number}: {status} | "
        f"encode: {result.encode_time:.3f}s | "
        f"decode: {result.decode_time:.3f}s | "
        f"size: {result.file_size:,} bytes"
    )
    if not result.success and result.error:
        if verbose:
            print(f"    Error: {result.error}")
        else:
            # Truncate error for non-verbose
            error_line = result.error.split("\n")[0][:80]
            print(f"    Error: {error_line}...")


def print_summary(results: list, mode_name: str):
    """Print summary for a mode."""
    passed = sum(1 for r in results if r.success)
    total = len(results)
    avg_encode = sum(r.encode_time for r in results) / total if total > 0 else 0
    avg_decode = sum(r.decode_time for r in results) / total if total > 0 else 0

    status = "✅" if passed == total else "❌"
    print(f"\n{status} {mode_name}: {passed}/{total} passed")
    print(f"   Avg encode: {avg_encode:.3f}s | Avg decode: {avg_decode:.3f}s")


def main():
    """Run all tests."""
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    num_runs = 5

    print("=" * 70)
    print("🐱 Meow Decoder Web Demo - Comprehensive Test Suite")
    print("=" * 70)
    print(f"Running {num_runs} tests per mode...")
    print(f"MEOW_TEST_MODE: {os.environ.get('MEOW_TEST_MODE', 'not set')}")
    print()

    all_results = []

    # Test 1: Normal Mode
    print("📦 Testing Normal Mode...")
    normal_results = []
    for i in range(1, num_runs + 1):
        result = test_normal_mode(i, verbose)
        normal_results.append(result)
        print_result(result, verbose)
    all_results.extend(normal_results)
    print_summary(normal_results, "Normal Mode")

    # Test 2: Cat Mode (GIF encoding)
    print("\n😺 Testing Cat Mode (GIF encoding)...")
    cat_results = []
    for i in range(1, num_runs + 1):
        result = test_cat_mode(i, verbose)
        cat_results.append(result)
        print_result(result, verbose)
    all_results.extend(cat_results)
    print_summary(cat_results, "Cat Mode (GIF)")

    # Test 3: Cat Mode Server Encryption (binary API)
    print("\n🔐 Testing Cat Mode Server Encryption API...")
    cat_server_results = []
    for i in range(1, num_runs + 1):
        result = test_cat_mode_server_encryption(i, verbose)
        cat_server_results.append(result)
        print_result(result, verbose)
    all_results.extend(cat_server_results)
    print_summary(cat_server_results, "Cat Mode Server API")

    # Test 4: Duress Mode
    print("\n🚨 Testing Duress Mode...")
    duress_results = []
    for i in range(1, num_runs + 1):
        result = test_duress_mode(i, verbose)
        duress_results.append(result)
        print_result(result, verbose)
    all_results.extend(duress_results)
    print_summary(duress_results, "Duress Mode")

    # Test 5: Forward Secrecy Mode (MEOW3)
    print("\n🔐 Testing Forward Secrecy Mode (X25519)...")
    fs_results = []
    for i in range(1, num_runs + 1):
        result = test_forward_secrecy_mode(i, verbose)
        fs_results.append(result)
        print_result(result, verbose)
    all_results.extend(fs_results)
    print_summary(fs_results, "Forward Secrecy Mode")

    # Test 6: Schrödinger Mode (dual-secret)
    print("\n⚛️  Testing Schrödinger Mode (dual-secret)...")
    schrodinger_results = []
    for i in range(1, num_runs + 1):
        result = test_schrodinger_mode(i, verbose)
        schrodinger_results.append(result)
        print_result(result, verbose)
    all_results.extend(schrodinger_results)
    print_summary(schrodinger_results, "Schrödinger Mode")

    # Final Summary
    print("\n" + "=" * 70)
    total_passed = sum(1 for r in all_results if r.success)
    total_tests = len(all_results)

    if total_passed == total_tests:
        print(f"🎉 ALL TESTS PASSED: {total_passed}/{total_tests}")
        print("=" * 70)
        return 0
    else:
        print(f"❌ TESTS FAILED: {total_passed}/{total_tests} passed")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
