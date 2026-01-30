"""Core tests for v1.2/v1.3.1 spec modules."""

import time
import pytest

from meow_decoder.spec_v12.steganography import (
    find_gif_insertion_point,
    embed_in_gif,
    extract_from_gif,
)
from meow_decoder.spec_v12.encode import encode_file
from meow_decoder.spec_v12.decode import decode_file
from meow_decoder.spec_v12.multi_tier import encode_multi_tier, decode_multi_tier
from meow_decoder.spec_v12.key_management import SoftwareBackend, ed25519_pk_to_x25519_pk, ed25519_sk_to_x25519_sk

from cryptography.hazmat.primitives.asymmetric import ed25519


def _minimal_gif() -> bytes:
    # GIF89a + 1x1 Logical Screen Descriptor + trailer
    return b"GIF89a" + bytes([1, 0, 1, 0, 0, 0, 0]) + b"\x3B"


def _gif_with_app_extension() -> bytes:
    header = b"GIF89a" + bytes([1, 0, 1, 0, 0, 0, 0])
    # Application Extension: NETSCAPE2.0 with a single sub-block
    ext = b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00"
    return header + ext + b"\x3B"


def _gif_with_comment_extension() -> bytes:
    header = b"GIF89a" + bytes([1, 0, 1, 0, 0, 0, 0])
    ext = b"\x21\xFE\x03hi!\x00"
    return header + ext + b"\x3B"


def test_dynamic_gif_insertion_points():
    minimal = _minimal_gif()
    assert find_gif_insertion_point(minimal) == 13

    app_gif = _gif_with_app_extension()
    assert find_gif_insertion_point(app_gif) > 13

    comment_gif = _gif_with_comment_extension()
    assert find_gif_insertion_point(comment_gif) > 13


def test_embed_extract_roundtrip():
    payload = b"secret payload"
    gif = _minimal_gif()
    embedded = embed_in_gif(gif, payload)
    extracted = extract_from_gif(embedded)
    assert extracted == payload


def test_encode_decode_roundtrip_v12():
    nacl = pytest.importorskip("nacl")
    _ = nacl  # silence unused

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()

    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()

    plaintext = b"secret message v1.2"
    gif_carrier = _minimal_gif()

    embedded = encode_file(plaintext, recipient_pk, sender_sk, gif_carrier)
    recovered = decode_file(embedded, sender_pk, recipient_sk)

    assert recovered == plaintext


def test_recipient_pk_in_header_generic_error():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()
    wrong_backend = SoftwareBackend()

    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()
    wrong_sk, _ = wrong_backend.generate_ed25519_keypair()

    plaintext = b"test"
    gif_carrier = _minimal_gif()

    embedded = encode_file(plaintext, recipient_pk, sender_sk, gif_carrier)

    with pytest.raises(ValueError, match="Decryption failed"):
        decode_file(embedded, sender_pk, wrong_sk)


def test_multi_tier_roundtrip_and_padding():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()

    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()

    plaintexts = [b"tier1", b"tier2 data", b"tier3 data data"]
    gif_carrier = _minimal_gif()

    embedded = encode_multi_tier(plaintexts, recipient_pk, sender_sk, gif_carrier)
    recovered = decode_multi_tier(embedded, sender_pk, recipient_sk, tier_index=1)

    # Returned tier should start with original plaintext (padding may follow)
    assert recovered.startswith(plaintexts[1])

    # Verify equal ciphertext lengths by parsing payload
    payload = extract_from_gif(embedded)
    tier_count = payload[34]
    offset = 35

    expected_kdf_info_len = payload[offset + 72]
    tier_header_len = 73 + expected_kdf_info_len
    per_tier_overhead = tier_header_len + 64
    total_cipher_bytes = len(payload) - len(payload[:35]) - (per_tier_overhead * tier_count)
    assert total_cipher_bytes > 0
    assert total_cipher_bytes % tier_count == 0
    cipher_len = total_cipher_bytes // tier_count

    ciphertext_lengths = []

    for i in range(tier_count):
        kdf_info_len = payload[offset + 72]
        assert kdf_info_len == expected_kdf_info_len
        tier_header_len = 73 + expected_kdf_info_len
        ciphertext_start = offset + tier_header_len + 64
        ciphertext = payload[ciphertext_start : ciphertext_start + cipher_len]
        ciphertext_lengths.append(len(ciphertext))
        offset = ciphertext_start + cipher_len

    assert len(set(ciphertext_lengths)) == 1


def test_multi_tier_constant_time_soft():
    """Best-effort timing consistency check (soft)."""
    nacl = pytest.importorskip("nacl")
    _ = nacl

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()

    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()

    plaintexts = [b"tier1" + b"X" * 64, b"tier2" + b"Y" * 64, b"tier3" + b"Z" * 64]
    gif_carrier = _minimal_gif()

    embedded = encode_multi_tier(plaintexts, recipient_pk, sender_sk, gif_carrier)

    times = []
    for tier in range(3):
        start = time.perf_counter()
        decode_multi_tier(embedded, sender_pk, recipient_sk, tier_index=tier)
        times.append(time.perf_counter() - start)

    mean_time = sum(times) / len(times)
    for t in times:
        # Soft threshold to avoid flakiness in CI
        assert abs(t - mean_time) / mean_time < 0.25


def test_signature_domain_separator():
    sender_backend = SoftwareBackend()
    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    sender_priv = ed25519.Ed25519PrivateKey.from_private_bytes(sender_sk[:32])
    sender_pub = ed25519.Ed25519PublicKey.from_public_bytes(sender_pk)

    header = b"\x00\x02" + b"A" * 64
    domain_sep = b"meow-decoder-v1.2-signature\0\0\0\0\0"
    signature = sender_priv.sign(domain_sep + header)
    sender_pub.verify(signature, domain_sep + header)


def test_aad_placeholder_construction():
    version = (0x0002).to_bytes(2, "big")
    recipient_pk = bytes(32)
    ephemeral_pk = bytes(32)
    salt = bytes(16)
    nonce = bytes(24)
    kdf_info = b"meow-decoder-v1.2-xchacha20poly1305"
    kdf_info_len = len(kdf_info).to_bytes(1, "big")

    header_before_sig = version + recipient_pk + ephemeral_pk + salt + nonce + kdf_info_len + kdf_info
    signature_placeholder = b"\x00" * 64
    aad = header_before_sig + signature_placeholder

    assert len(aad) == 2 + 32 + 32 + 16 + 24 + 1 + len(kdf_info) + 64


def test_unified_key_conversion():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    backend = SoftwareBackend()
    ed_sk, ed_pk = backend.generate_ed25519_keypair()

    x_sk = ed25519_sk_to_x25519_sk(ed_sk)
    x_pk = ed25519_pk_to_x25519_pk(ed_pk)

    assert len(x_sk) == 32
    assert len(x_pk) == 32


def test_ecdh_hkdf_kat_v12():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    from nacl import signing
    from nacl.bindings import (
        crypto_sign_ed25519_pk_to_curve25519,
        crypto_scalarmult,
        crypto_scalarmult_base,
    )
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    recipient_seed = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    recipient_sk = signing.SigningKey(recipient_seed)
    recipient_pk = recipient_sk.verify_key.encode()
    recipient_x_pk = crypto_sign_ed25519_pk_to_curve25519(recipient_pk)

    ephemeral_sk = bytes.fromhex(
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
    )
    ephemeral_pk = crypto_scalarmult_base(ephemeral_sk)
    shared = crypto_scalarmult(ephemeral_sk, recipient_x_pk)

    hkdf_salt = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    info = b"meow-decoder-v1.2-xchacha20poly1305"

    key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=hkdf_salt,
        info=info,
    ).derive(shared)

    assert recipient_pk.hex() == "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    assert recipient_x_pk.hex() == "4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01"
    assert ephemeral_pk.hex() == "87968c1c1642bd0600f6ad869b88f92c9623d0dfc44f01deffe21c9add3dca5f"
    assert shared.hex() == "e80e5f719e7b677b4c6e3c71021ff9d51bba38d1edc86edfed5d83cf2c5ba023"
    assert key.hex() == "4b2bc48366860f9818c7dc4c2bde19584935b177f2a8f67d008322fe2b299836"


def test_wrong_version_fails_generic():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()
    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()

    gif_carrier = _minimal_gif()
    embedded = encode_file(b"message", recipient_pk, sender_sk, gif_carrier)
    payload = bytearray(extract_from_gif(embedded))
    payload[0:2] = b"\x00\x01"
    tampered = embed_in_gif(gif_carrier, bytes(payload))

    with pytest.raises(ValueError, match="Decryption failed"):
        decode_file(tampered, sender_pk, recipient_sk)


def test_signature_tampering_fails():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()
    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()

    gif_carrier = _minimal_gif()
    embedded = encode_file(b"message", recipient_pk, sender_sk, gif_carrier)
    payload = bytearray(extract_from_gif(embedded))

    # Flip a byte inside the signature region
    kdf_info_len = payload[106]
    signature_offset = 107 + kdf_info_len
    payload[signature_offset] ^= 0x01
    tampered = embed_in_gif(gif_carrier, bytes(payload))

    with pytest.raises(ValueError, match="Decryption failed"):
        decode_file(tampered, sender_pk, recipient_sk)


def test_aad_tampering_fails():
    nacl = pytest.importorskip("nacl")
    _ = nacl

    sender_backend = SoftwareBackend()
    recipient_backend = SoftwareBackend()
    sender_sk, sender_pk = sender_backend.generate_ed25519_keypair()
    recipient_sk, recipient_pk = recipient_backend.generate_ed25519_keypair()

    gif_carrier = _minimal_gif()
    embedded = encode_file(b"message", recipient_pk, sender_sk, gif_carrier)
    payload = bytearray(extract_from_gif(embedded))

    # Flip bit in recipient_pk (part of AAD)
    payload[10] ^= 0x01
    tampered = embed_in_gif(gif_carrier, bytes(payload))

    with pytest.raises(ValueError, match="Decryption failed"):
        decode_file(tampered, sender_pk, recipient_sk)
