import json
from pathlib import Path

import meow_decoder.clowder_encode as clowder_encode
import meow_decoder.clowder_decode as clowder_decode


def test_collect_files_and_hash_password(tmp_path):
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("one")
    file_b.write_text("two")

    files = clowder_encode.collect_files(tmp_path)
    assert file_a in files and file_b in files

    h1 = clowder_encode.hash_password("secret")
    h2 = clowder_encode.hash_password("secret")
    assert h1 == h2
    assert len(h1) == 16


def test_encode_and_decode_clowder_roundtrip(tmp_path, monkeypatch):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    recovered_dir = tmp_path / "recovered"
    input_dir.mkdir()

    file_a = input_dir / "a.txt"
    file_b = input_dir / "b.txt"
    file_a.write_text("alpha")
    file_b.write_text("bravo")

    def fake_encode_file(input_path, output_path, password, config=None, verbose=False):
        Path(output_path).write_bytes(b"GIFDATA")
        return {"qr_frames": 3, "output_size": 7}

    monkeypatch.setattr(clowder_encode, "encode_file", fake_encode_file)

    stats = clowder_encode.encode_clowder(
        input_dir,
        output_dir,
        password="pw",
        max_files_per_yarn=10,
        resume=False,
        verbose=False,
    )
    assert stats["total_files"] == 2

    manifest_path = output_dir / "clowder_manifest.json"
    assert manifest_path.exists()

    with open(manifest_path) as f:
        manifest = json.load(f)

    yarn_ball = manifest["yarn_balls"][0]

    combined = b""
    for info in yarn_ball["file_index"]:
        combined += Path(info["path"]).read_bytes()

    def fake_decode_gif(input_path, output_path, password, verbose=False):
        Path(output_path).write_bytes(combined)

    monkeypatch.setattr(clowder_decode, "decode_gif", fake_decode_gif)

    decode_stats = clowder_decode.decode_clowder(
        output_dir,
        recovered_dir,
        password="pw",
        verbose=False,
    )
    assert decode_stats["decoded_files"] == 2

    assert (recovered_dir / "a.txt").read_text() == "alpha"
    assert (recovered_dir / "b.txt").read_text() == "bravo"


def test_decode_clowder_wrong_password(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    manifest_path = output_dir / "clowder_manifest.json"
    manifest = {
        "type": "meow_clowder",
        "version": "5.0",
        "clowder_id": "id",
        "password_hash": clowder_decode.hash_password("pw"),
        "created_at": "now",
        "total_files": 0,
        "total_bytes": 0,
        "total_yarn_balls": 0,
        "yarn_balls": [],
        "completed": True,
    }
    manifest_path.write_text(json.dumps(manifest))

    try:
        clowder_decode.decode_clowder(output_dir, tmp_path / "out", "wrong")
        assert False, "Expected wrong password error"
    except ValueError as exc:
        assert "Wrong password" in str(exc)
