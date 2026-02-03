import io

import meow_decoder.progress as progress
import meow_decoder.progress_bar as progress_bar


def test_progress_bar_fallback_updates(capsys, monkeypatch):
    monkeypatch.setattr(progress, "HAS_TQDM", False)
    bar = progress.ProgressBar(total=5, desc="Test", disable=False)
    for _ in range(5):
        bar.update()
    bar.close()
    out = capsys.readouterr().out
    assert "Test" in out
    assert "done" in out


def test_progress_iter_fallback(capsys, monkeypatch):
    monkeypatch.setattr(progress, "HAS_TQDM", False)
    items = list(progress.progress_iter([1, 2, 3], desc="Iter", total=3))
    out = capsys.readouterr().out
    assert items == [1, 2, 3]
    assert "Iter" in out
    assert "done" in out


def test_spinner_context_manager(capsys):
    with progress.spinner("Working") as sp:
        sp.tick()
    out = capsys.readouterr().out
    assert "Working" in out
    assert "done" in out


def test_progress_stats_percentage_and_elapsed(monkeypatch):
    stats = progress_bar.ProgressStats(total_items=10, received_items=5)
    assert stats.percentage == 50.0

    base = progress_bar.time.time()
    monkeypatch.setattr(progress_bar.time, "time", lambda: base + 65)
    stats.start_time = base
    assert stats.elapsed_str == "01:05"


def test_progress_bar_rendering_basic(monkeypatch):
    monkeypatch.setattr(progress_bar.sys.stdout, "isatty", lambda: False)
    bar = progress_bar.ProgressBar(total=4, width=4, title="Test", use_color=True)
    bar.mark_received(0)
    rendered = bar.render_compact()
    assert "Test" in rendered
    assert "1/4" in rendered


def test_fountain_progress_update_decoding(monkeypatch):
    monkeypatch.setattr(progress_bar.sys.stdout, "isatty", lambda: False)
    fpb = progress_bar.FountainProgressBar(k_blocks=4, expected_droplets=6, width=4)
    fpb.update_decoding(blocks_decoded=2, droplets_received=3, bytes_count=100)
    rendered = fpb.render_compact()
    assert "2/4" in rendered
    assert "3 droplets" in rendered


def test_create_progress_returns_fountain():
    fpb = progress_bar.create_progress(10, fountain=True)
    assert isinstance(fpb, progress_bar.FountainProgressBar)
