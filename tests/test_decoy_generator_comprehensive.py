import io
import zipfile
import runpy
import secrets

from meow_decoder.decoy_generator import DecoyGenerator, generate_convincing_decoy


def test_generate_lorem_pdf_content_has_pdf_markers():
    content = DecoyGenerator.generate_lorem_pdf_content()
    assert isinstance(content, bytes)
    assert content.startswith(b"%PDF-1.4")
    assert b"%%EOF" in content


def test_generate_shopping_list_structure_and_item_count():
    content = DecoyGenerator.generate_shopping_list()
    assert content.startswith("Shopping List - ")
    assert "Remember: Don't forget the cat treats!" in content

    items = [
        line
        for line in content.splitlines()
        if line.strip().startswith(tuple(f"{i}." for i in range(1, 30)))
    ]
    assert 5 <= len(items) <= len(DecoyGenerator.SHOPPING_ITEMS)


def test_generate_shopping_list_min_items(monkeypatch):
    class DummyRand:
        def sample(self, items, k):
            return list(items)[:k]

    monkeypatch.setattr(secrets, "SystemRandom", lambda: DummyRand())
    monkeypatch.setattr(secrets, "randbelow", lambda n: 0)

    content = DecoyGenerator.generate_shopping_list()
    items = [line for line in content.splitlines() if line.strip().startswith(tuple(f"{i}." for i in range(1, 30)))]
    assert len(items) == 5


def test_generate_shopping_list_max_items(monkeypatch):
    class DummyRand:
        def sample(self, items, k):
            return list(items)[:k]

    monkeypatch.setattr(secrets, "SystemRandom", lambda: DummyRand())
    max_offset = len(DecoyGenerator.SHOPPING_ITEMS) - 6
    monkeypatch.setattr(secrets, "randbelow", lambda n: max_offset)

    content = DecoyGenerator.generate_shopping_list()
    items = [line for line in content.splitlines() if line.strip().startswith(tuple(f"{i}." for i in range(1, 30)))]
    assert len(items) == len(DecoyGenerator.SHOPPING_ITEMS) - 1


def test_generate_fake_image_size_and_markers():
    size = 4096
    data = DecoyGenerator.generate_fake_image(size)
    assert isinstance(data, bytes)
    assert len(data) == size
    assert data.startswith(b"\xff\xd8\xff\xe0")
    assert data.endswith(b"\xff\xd9")


def test_generate_vacation_photos_count_and_sizes():
    photos = DecoyGenerator.generate_vacation_photos(3)
    assert 1 <= len(photos) <= 3
    for name, data in photos:
        assert name.endswith(".jpg")
        assert data.startswith(b"\xff\xd8\xff\xe0")
        assert data.endswith(b"\xff\xd9")
        assert 50000 <= len(data) <= 200000


def test_generate_notes_file_contains_expected_sections():
    content = DecoyGenerator.generate_notes_file()
    assert content.startswith("Personal Notes")
    assert "Things to remember:" in content
    assert "Random thoughts:" in content
    assert DecoyGenerator.CAT_LOREM.strip().splitlines()[0] in content


def test_generate_decoy_archive_is_valid_zip_and_contains_expected_files():
    target_size = 120000
    archive = DecoyGenerator.generate_decoy_archive(target_size)
    assert isinstance(archive, bytes)
    assert len(archive) > 1000

    with zipfile.ZipFile(io.BytesIO(archive), "r") as zf:
        names = set(zf.namelist())
        assert "The_Feline_Manifesto.pdf" in names
        assert "shopping_list.txt" in names
        assert "notes.txt" in names

        has_photos = any(name.startswith("vacation_photos/") for name in names)
        assert has_photos


def test_generate_decoy_archive_small_target_adds_no_photos():
    # Target size small enough to skip adding photos
    archive = DecoyGenerator.generate_decoy_archive(1000)
    with zipfile.ZipFile(io.BytesIO(archive), "r") as zf:
        names = set(zf.namelist())
        assert "The_Feline_Manifesto.pdf" in names
        assert "shopping_list.txt" in names
        assert "notes.txt" in names
        assert not any(name.startswith("vacation_photos/") for name in names)


def test_generate_vacation_photos_caps_count():
    photos = DecoyGenerator.generate_vacation_photos(999)
    assert len(photos) <= len(DecoyGenerator.PHOTO_NAMES)


def test_generate_convincing_decoy_default_size_range():
    decoy = generate_convincing_decoy()
    assert isinstance(decoy, bytes)
    assert 40000 <= len(decoy) <= 200000


def test_decoy_generator_module_main_runs():
    runpy.run_module("meow_decoder.decoy_generator", run_name="__main__")
