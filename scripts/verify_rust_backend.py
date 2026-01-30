
import meow_crypto_rs
import os

print(f"Meow Crypto RS version: {getattr(meow_crypto_rs, '__version__', 'unknown')}")

# Test Argon2id
password = b"password"
salt = os.urandom(16)
key = meow_crypto_rs.derive_key_argon2id(
    password,
    salt,
    32,
    1,
    65536,
    1
)
print(f"Argon2id Key: {key.hex()}")
assert len(key) == 32

# Test Kyber
pk, sk = meow_crypto_rs.mlkem768_keygen()
print(f"Kyber PK length: {len(pk)}")
print(f"Kyber SK length: {len(sk)}")
assert len(pk) == 1184
assert len(sk) == 2400

ct, ss_sender = meow_crypto_rs.mlkem768_encapsulate(pk)
print(f"Kyber CT length: {len(ct)}")
print(f"Kyber Shared Secret (Sender) length: {len(ss_sender)}")
assert len(ct) == 1088
assert len(ss_sender) == 32

ss_receiver = meow_crypto_rs.mlkem768_decapsulate(ct, sk)
print(f"Kyber Shared Secret (Receiver) length: {len(ss_receiver)}")
assert len(ss_receiver) == 32

assert ss_sender == ss_receiver
print("Kyber Shared Secrets match!")
