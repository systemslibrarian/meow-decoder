import runpy
import sys
from pathlib import Path

import pytest


def test_deserialize_public_key_rejects_wrong_length():
    from meow_decoder.x25519_forward_secrecy import deserialize_public_key

    with pytest.raises(ValueError):
        deserialize_public_key(b"\x00" * 31)


def test_save_receiver_keypair_without_password_uses_no_encryption(tmp_path: Path):
    from meow_decoder.x25519_forward_secrecy import (
        generate_receiver_keypair,
        save_receiver_keypair,
        load_receiver_keypair,
        serialize_public_key,
    )

    priv, pub = generate_receiver_keypair()

    priv_path = tmp_path / "receiver_private.pem"
    pub_path = tmp_path / "receiver_public.key"

    save_receiver_keypair(priv, pub, str(priv_path), str(pub_path), password=None)

    loaded_priv, loaded_pub = load_receiver_keypair(str(priv_path), str(pub_path), password=None)
    assert serialize_public_key(loaded_pub) == serialize_public_key(pub)


def test_load_receiver_keypair_rejects_non_x25519_private_key(tmp_path: Path, monkeypatch):
    from meow_decoder.x25519_forward_secrecy import (
        generate_receiver_keypair,
        save_receiver_keypair,
        load_receiver_keypair,
    )

    priv, pub = generate_receiver_keypair()

    priv_path = tmp_path / "receiver_private.pem"
    pub_path = tmp_path / "receiver_public.key"

    save_receiver_keypair(priv, pub, str(priv_path), str(pub_path), password="secret")

    import cryptography.hazmat.primitives.serialization as ser

    monkeypatch.setattr(ser, "load_pem_private_key", lambda *_args, **_kwargs: object())

    with pytest.raises(ValueError):
        load_receiver_keypair(str(priv_path), str(pub_path), password="secret")


def test_generate_receiver_keys_cli_password_prompt_mismatch(tmp_path: Path, monkeypatch):
    from meow_decoder.x25519_forward_secrecy import generate_receiver_keys_cli

    import getpass as gp
    import sys

    answers = iter(["a", "b"])
    monkeypatch.setattr(gp, "getpass", lambda _prompt="": next(answers))

    # Force the interactive getpass() branch regardless of how pytest runs stdin.
    class _TtyStdin:
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", _TtyStdin())

    with pytest.raises(ValueError):
        generate_receiver_keys_cli(output_dir=str(tmp_path), password=None)


def test_x25519_module_main_usage_prints(capsys, monkeypatch):
    # Run the module as __main__ without args so it prints its usage.
    monkeypatch.setattr(sys, "argv", ["x25519_forward_secrecy.py"])
    runpy.run_module("meow_decoder.x25519_forward_secrecy", run_name="__main__")

    out = capsys.readouterr().out
    assert "Usage:" in out
    assert "Generates receiver keypair" in out
