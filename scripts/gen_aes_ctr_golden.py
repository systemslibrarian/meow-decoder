#!/usr/bin/env python3
"""Generate AES-256-CTR golden vector for Rust equivalence testing."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Fixed golden vector inputs
key = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

# 80 bytes of plaintext (5 AES blocks, tests multi-block + partial)
plaintext = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9e53f3cdac355977"
    "b2351234ab4f7890de765432cafe1234"
    "0011223344556677889900aabbccddee"
    "deadbeefcafebabe1234567890abcdef"
)

# Encrypt single-shot
cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Decrypt (verify roundtrip)
cipher2 = Cipher(algorithms.AES(key), modes.CTR(nonce))
decryptor = cipher2.decryptor()
recovered = decryptor.update(ciphertext) + decryptor.finalize()

assert recovered == plaintext, "Roundtrip failed!"

print(f"key       = {key.hex()}")
print(f"nonce     = {nonce.hex()}")
print(f"plaintext = {plaintext.hex()}")
print(f"ciphertext= {ciphertext.hex()}")
print(f"pt_len    = {len(plaintext)}")
print(f"ct_len    = {len(ciphertext)}")
print(f"roundtrip = OK")

# Chunked test (streaming pattern — must produce identical output)
cipher3 = Cipher(algorithms.AES(key), modes.CTR(nonce))
encryptor3 = cipher3.encryptor()
ct_chunks = b""
ct_chunks += encryptor3.update(plaintext[:16])
ct_chunks += encryptor3.update(plaintext[16:48])
ct_chunks += encryptor3.update(plaintext[48:])
ct_chunks += encryptor3.finalize()
assert ct_chunks == ciphertext, "Chunked encryption mismatch!"
print(f"chunked   = OK (matches single-shot)")

# Output Rust-ready hex constants
print()
print("// Rust test constants:")
for i in range(0, len(ciphertext), 16):
    chunk = ciphertext[i : i + 16].hex()
    print(f"//   {chunk}")
