#!/usr/bin/env python3
"""
Characterize Python's cryptography library AES-CTR mode.

Determines:
1. IV length (16 bytes confirmed by streaming_crypto.py)
2. Counter size and structure (full 128-bit or nonce||counter)
3. Endianness of counter increment
4. Byte-for-byte test vector for Rust equivalence
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def test_counter_format():
    """Verify counter is big-endian 128-bit, incrementing full 16 bytes."""
    key = bytes(range(32))  # 0x00..0x1f (deterministic)

    # IV with last 4 bytes near overflow to test increment behavior
    nonce = b"\x00" * 12 + b"\xff\xff\xff\xfe"

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()

    # Encrypt 64 bytes of zeros (4 AES blocks) - ciphertext IS keystream
    plaintext = b"\x00" * 64
    ct = enc.update(plaintext) + enc.finalize()

    print("=== CTR Counter Format Test ===")
    print(f"Key: {key.hex()}")
    print(f"IV:  {nonce.hex()}")
    print(f"Plaintext: {plaintext.hex()}")
    print()

    print("Keystream blocks (ciphertext of zeros):")
    for i in range(4):
        block = ct[i * 16 : (i + 1) * 16]
        print(f"  Block {i}: {block.hex()}")

    # Verify: big-endian 128-bit counter, full IV is counter
    print()
    print("=== Verification: AES-ECB of expected counter values ===")
    counter_base = int.from_bytes(nonce, "big")

    all_match = True
    for i in range(4):
        counter_val = (counter_base + i) % (2**128)
        counter_bytes = counter_val.to_bytes(16, "big")

        ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        ecb_block = ecb.update(counter_bytes) + ecb.finalize()

        match = ecb_block == ct[i * 16 : (i + 1) * 16]
        all_match = all_match and match
        status = "MATCH" if match else "NO MATCH"
        print(f"  AES-ECB(ctr={counter_bytes.hex()}) -> {status}")

    if all_match:
        print(
            "\nCONFIRMED: Counter is big-endian 128-bit, full 16-byte IV is initial counter block."
        )
    else:
        print("\nWARNING: Counter format does NOT match big-endian 128-bit assumption!")
        # Try little-endian
        print("\nTrying little-endian 128-bit counter...")
        counter_base_le = int.from_bytes(nonce, "little")
        for i in range(4):
            counter_val = (counter_base_le + i) % (2**128)
            counter_bytes = counter_val.to_bytes(16, "little")
            ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            ecb_block = ecb.update(counter_bytes) + ecb.finalize()
            match = ecb_block == ct[i * 16 : (i + 1) * 16]
            status = "MATCH" if match else "NO MATCH"
            print(f"  AES-ECB(ctr_le={counter_bytes.hex()}) -> {status}")


def generate_golden_vector():
    """Generate a deterministic AES-256-CTR golden test vector."""
    # Use the exact same pattern as streaming_crypto.py
    key = bytes([0x60 + i for i in range(32)])  # Distinct from other tests
    iv = bytes([0xA0 + i for i in range(16)])

    # Multi-chunk plaintext to test streaming
    plaintext = b"Hello, AES-CTR streaming test! This is exactly 64 bytes long!?!"
    assert len(plaintext) == 64, f"Plaintext is {len(plaintext)} bytes, expected 64"

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc = cipher.encryptor()

    # Simulate streaming: encrypt in 2 chunks
    ct_part1 = enc.update(plaintext[:32])
    ct_part2 = enc.update(plaintext[32:])
    ct_final = enc.finalize()
    ciphertext = ct_part1 + ct_part2 + ct_final

    # Verify: single-shot produces same result
    cipher2 = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc2 = cipher2.encryptor()
    ct_single = enc2.update(plaintext) + enc2.finalize()
    assert ciphertext == ct_single, "Streaming and single-shot must produce identical output"

    # Verify decryption
    cipher3 = Cipher(algorithms.AES(key), modes.CTR(iv))
    dec = cipher3.decryptor()
    recovered = dec.update(ciphertext) + dec.finalize()
    assert recovered == plaintext, "Decryption must recover plaintext"

    print()
    print("=== AES-256-CTR Golden Test Vector ===")
    print(f"Key:        {key.hex()}")
    print(f"IV:         {iv.hex()}")
    print(f"Plaintext:  {plaintext.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Length:     {len(ciphertext)} bytes")
    print()
    print("Streaming consistency: PASS")
    print("Decrypt roundtrip:     PASS")

    # Also test with non-zero partial blocks (CTR handles arbitrary lengths)
    plaintext2 = b"Short"  # 5 bytes (not block-aligned)
    cipher4 = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc4 = cipher4.encryptor()
    ct_short = enc4.update(plaintext2) + enc4.finalize()

    print()
    print("=== Short plaintext (5 bytes) ===")
    print(f"Plaintext:  {plaintext2.hex()}")
    print(f"Ciphertext: {ct_short.hex()}")
    print(f"Length:     {len(ct_short)} bytes")

    # Verify short ciphertext is prefix of long ciphertext XOR'd stream
    # Both start from same IV, so first 5 bytes of keystream should match
    cipher5 = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc5 = cipher5.encryptor()
    keystream = enc5.update(b"\x00" * 64) + enc5.finalize()
    expected_short = bytes(a ^ b for a, b in zip(plaintext2, keystream[:5]))
    assert ct_short == expected_short, "Short ciphertext must match XOR with keystream prefix"
    print("Keystream prefix check: PASS")

    return key, iv, plaintext, ciphertext


def test_empty_finalize():
    """Verify that finalize() returns empty bytes for CTR mode."""
    key = bytes(range(32))
    iv = bytes(range(16))
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc = cipher.encryptor()
    ct = enc.update(b"test")
    final = enc.finalize()
    print()
    print(f"=== Finalize test ===")
    print(f"enc.finalize() returns: {final!r} (length {len(final)})")
    print(f"CTR finalize is empty: {'PASS' if len(final) == 0 else 'FAIL'}")


if __name__ == "__main__":
    test_counter_format()
    generate_golden_vector()
    test_empty_finalize()
