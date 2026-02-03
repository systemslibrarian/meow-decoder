import hashlib

import meow_decoder.crypto as crypto
import meow_decoder.schrodinger_encode as schrodinger_encode
import meow_decoder.schrodinger_decode as schrodinger_decode


def _fast_derive_key(password: str, salt: bytes, keyfile=None) -> bytes:
    return hashlib.sha256(password.encode("utf-8") + salt).digest()


def test_schrodinger_manifest_pack_unpack_roundtrip():
    manifest = schrodinger_encode.SchrodingerManifest(
        salt_a=b"a" * 16,
        salt_b=b"b" * 16,
        nonce_a=b"c" * 12,
        nonce_b=b"d" * 12,
        reality_a_hmac=b"e" * 32,
        reality_b_hmac=b"f" * 32,
        metadata_a=b"g" * 104,
        metadata_b=b"h" * 104,
        block_count=2,
        block_size=256,
        superposition_len=512,
    )
    packed = manifest.pack()
    unpacked = schrodinger_encode.SchrodingerManifest.unpack(packed)
    assert unpacked.salt_a == manifest.salt_a
    assert unpacked.salt_b == manifest.salt_b
    assert unpacked.metadata_a == manifest.metadata_a
    assert unpacked.metadata_b == manifest.metadata_b
    assert len(packed) == 382
    assert len(manifest.pack_core_for_auth()) == 318


def test_schrodinger_encode_decode_roundtrip(monkeypatch):
    monkeypatch.setattr(crypto, "derive_key", _fast_derive_key)
    monkeypatch.setattr(schrodinger_encode, "derive_key", _fast_derive_key)
    monkeypatch.setattr(schrodinger_decode, "derive_key", _fast_derive_key)

    real = b"real secret data" * 5
    decoy = b"decoy data" * 7
    real_pw = "real-password"
    decoy_pw = "decoy-password"

    superposition, manifest = schrodinger_encode.schrodinger_encode_data(
        real, decoy, real_pw, decoy_pw, block_size=128
    )

    decoded_real = schrodinger_decode.schrodinger_decode_data(
        superposition, manifest, real_pw
    )
    decoded_decoy = schrodinger_decode.schrodinger_decode_data(
        superposition, manifest, decoy_pw
    )
    decoded_none = schrodinger_decode.schrodinger_decode_data(
        superposition, manifest, "wrong-password"
    )

    assert decoded_real == real
    assert decoded_decoy == decoy
    assert decoded_none is None
