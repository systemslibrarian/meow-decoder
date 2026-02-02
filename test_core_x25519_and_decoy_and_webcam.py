import io
import zipfile
from pathlib import Path

import numpy as np
import pytest

from meow_decoder.decoy_generator import DecoyGenerator, generate_convincing_decoy
from meow_decoder.x25519_forward_secrecy import (
    derive_shared_secret,
    generate_ephemeral_keypair,
    generate_receiver_keypair,
    generate_receiver_keys_cli,
    load_receiver_keypair,
    save_receiver_keypair,
    serialize_public_key,
    deserialize_public_key,
)


def test_x25519_public_key_serialize_roundtrip():
    priv, pub = generate_receiver_keypair()
    pub_bytes = serialize_public_key(pub)
    assert len(pub_bytes) == 32

    pub2 = deserialize_public_key(pub_bytes)
    assert serialize_public_key(pub2) == pub_bytes


def test_x25519_shared_secret_matches_both_sides():
    password = "password_test"
    salt = b"S" * 16

    receiver_priv, receiver_pub = generate_receiver_keypair()
    sender_ephemeral = generate_ephemeral_keypair()

    # Sender derives with ephemeral private + receiver public
    sender_key = derive_shared_secret(
        sender_ephemeral.ephemeral_private,
        receiver_pub,
        password,
        salt,
    )

    # Receiver derives with receiver private + sender ephemeral public
    receiver_key = derive_shared_secret(
        receiver_priv,
        sender_ephemeral.ephemeral_public,
        password,
        salt,
    )

    assert sender_key == receiver_key
    assert len(sender_key) == 32


def test_x25519_save_and_load_keypair_password(tmp_path: Path):
    priv, pub = generate_receiver_keypair()

    priv_path = tmp_path / "receiver_private.pem"
    pub_path = tmp_path / "receiver_public.key"

    save_receiver_keypair(priv, pub, str(priv_path), str(pub_path), password="secret")
    assert priv_path.exists()
    assert pub_path.exists()

    loaded_priv, loaded_pub = load_receiver_keypair(str(priv_path), str(pub_path), password="secret")
    assert serialize_public_key(loaded_pub) == serialize_public_key(pub)

    # Wrong password should fail
    with pytest.raises(Exception):
        load_receiver_keypair(str(priv_path), str(pub_path), password="wrong")


def test_x25519_generate_receiver_keys_cli_noninteractive(tmp_path: Path, capsys):
    # Provide password to avoid prompting.
    generate_receiver_keys_cli(output_dir=str(tmp_path), password="secret")
    assert (tmp_path / "receiver_private.pem").exists()
    assert (tmp_path / "receiver_public.key").exists()


def test_decoy_archive_small_has_no_photos_branch():
    # Small target size should skip the photo-filling branch.
    decoy = DecoyGenerator.generate_decoy_archive(target_size=500)
    with zipfile.ZipFile(io.BytesIO(decoy), "r") as zf:
        names = set(zf.namelist())

    assert "The_Feline_Manifesto.pdf" in names
    assert "shopping_list.txt" in names
    assert "notes.txt" in names
    assert not any(n.startswith("vacation_photos/") for n in names)


def test_decoy_archive_large_adds_photos_branch():
    decoy = generate_convincing_decoy(target_size=200_000)
    with zipfile.ZipFile(io.BytesIO(decoy), "r") as zf:
        names = set(zf.namelist())

    assert any(n.startswith("vacation_photos/") for n in names)


def test_webcam_qr_reader_init_and_read_next(monkeypatch):
    import meow_decoder.qr_code as qr

    class _FakeCap:
        def __init__(self, frames):
            self._frames = list(frames)
            self._opened = True

        def isOpened(self):
            return self._opened

        def read(self):
            if not self._frames:
                return False, None
            return True, self._frames.pop(0)

        def release(self):
            self._opened = False

    # Init failure path
    monkeypatch.setattr(qr.cv2, "VideoCapture", lambda device: _FakeCap([]))
    cap = qr.cv2.VideoCapture(0)
    cap._opened = False
    monkeypatch.setattr(qr.cv2, "VideoCapture", lambda device: cap)

    with pytest.raises(RuntimeError):
        qr.WebcamQRReader(device=0)

    # Happy path: skip frames and return decoded payload
    frames = [np.zeros((10, 10, 3), dtype=np.uint8) for _ in range(3)]
    monkeypatch.setattr(qr.cv2, "VideoCapture", lambda device: _FakeCap(frames))

    reader = qr.WebcamQRReader(device=0, preprocessing="normal", frame_skip=1)

    # First eligible (every 2nd frame) returns a QR payload
    monkeypatch.setattr(reader.reader, "read_frame", lambda frame: [b"payload"])

    result = reader.read_next()
    assert result is not None
    payload, frame = result
    assert payload == b"payload"
    assert isinstance(frame, np.ndarray)

    reader.release()
