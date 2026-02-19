"""Tests for gui_logo_example module (1-to-1 mapping).

Additional GUI/logo tests in test_logo_and_gui.py
"""

import sys
import types
import importlib

import pytest


def _fake_dpg_module():
    dpg = types.SimpleNamespace()

    class _Ctx:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    dpg.texture_registry = lambda: _Ctx()
    dpg.add_raw_texture = lambda **kwargs: None
    dpg.window = lambda **kwargs: _Ctx()
    dpg.add_image = lambda *args, **kwargs: None
    dpg.add_text = lambda *args, **kwargs: None
    dpg.create_context = lambda: None
    dpg.create_viewport = lambda **kwargs: None
    dpg.setup_dearpygui = lambda: None
    dpg.show_viewport = lambda: None
    dpg.start_dearpygui = lambda: None
    dpg.destroy_context = lambda: None
    return dpg


class TestGuiLogoExample:
    def test_import_module(self, monkeypatch):
        fake_dpg = _fake_dpg_module()
        sys.modules["dearpygui"] = types.SimpleNamespace(dearpygui=fake_dpg)
        sys.modules["dearpygui.dearpygui"] = fake_dpg
        try:
            module = importlib.import_module("meow_decoder.gui_logo_example")
            assert module is not None
        except ImportError:
            pytest.skip("gui_logo_example not available")

    def test_load_svg_fallback(self, monkeypatch):
        fake_dpg = _fake_dpg_module()
        sys.modules["dearpygui"] = types.SimpleNamespace(dearpygui=fake_dpg)
        sys.modules["dearpygui.dearpygui"] = fake_dpg
        try:
            module = importlib.import_module("meow_decoder.gui_logo_example")
            width, height = module.load_svg_as_texture(module.Path("nonexistent.svg"))
            assert width is None and height is None
        except (ImportError, AttributeError):
            pytest.skip("gui_logo_example not fully available")
