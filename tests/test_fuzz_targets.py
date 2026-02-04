"""
Tests for fuzz targets (smoke coverage for fuzz harnesses).
"""

import os
import secrets

import pytest

from fuzz import fuzz_crypto, fuzz_manifest, fuzz_fountain, afl_fuzz_manifest, seed_corpus


def test_fuzz_crypto_smoke():
    data = secrets.token_bytes(128)
    fuzz_crypto.fuzz_derive_key(data)
    fuzz_crypto.fuzz_decrypt(data)
    fuzz_crypto.fuzz_hmac_verify(data)


def test_fuzz_manifest_smoke():
    # Random data should be handled safely
    data = secrets.token_bytes(200)
    fuzz_manifest.fuzz_unpack_manifest(data)

    # Valid-ish MEOW2 minimal buffer
    valid_like = b"MEOW2" + b"\x00" * 110
    fuzz_manifest.fuzz_unpack_manifest(valid_like)


def test_fuzz_fountain_smoke():
    data = secrets.token_bytes(300)
    fuzz_fountain.fuzz_unpack_droplet(data)
    fuzz_fountain.fuzz_fountain_decoder(data)


def test_afl_fuzz_manifest_requires_afl():
    with pytest.raises(RuntimeError, match="afl is required"):
        afl_fuzz_manifest.main()


def test_seed_corpus_generation(tmp_path):
    manifest_dir = tmp_path / "manifest"
    fountain_dir = tmp_path / "fountain"
    crypto_dir = tmp_path / "crypto"

    seed_corpus.generate_manifest_samples(manifest_dir, count=3)
    seed_corpus.generate_fountain_samples(fountain_dir, count=3)
    seed_corpus.generate_crypto_samples(crypto_dir, count=2)

    assert any(manifest_dir.iterdir())
    assert any(fountain_dir.iterdir())
    assert any(crypto_dir.iterdir())


@pytest.mark.parametrize("afl", [True, False])
def test_seed_corpus_main(tmp_path, monkeypatch, afl):
    output_dir = tmp_path / "corpus"
    args = ["seed_corpus.py", "--output", str(output_dir)]
    if afl:
        args.append("--afl")

    monkeypatch.setattr(seed_corpus, "Path", seed_corpus.Path)
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(os, "environ", os.environ)

    monkeypatch.setattr(seed_corpus, "sys", seed_corpus.sys)
    monkeypatch.setattr(seed_corpus.sys, "argv", args)
    monkeypatch.chdir(tmp_path)

    seed_corpus.main()

    if afl:
        afl_dir = seed_corpus.Path("fuzz/afl-corpus")
        assert afl_dir.exists()
        assert any(afl_dir.iterdir())
    else:
        assert output_dir.exists()
        assert any(output_dir.iterdir())
