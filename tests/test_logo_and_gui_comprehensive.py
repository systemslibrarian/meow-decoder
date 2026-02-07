import importlib
import sys
import types

from PIL import Image

import meow_decoder.logo_eyes as logo_eyes


def _fake_dpg_module():
    dpg = types.SimpleNamespace()

    class _Ctx:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    dpg.mvFormat_Float_rgba = 0
    dpg.texture_registry = lambda: _Ctx()
    dpg.add_raw_texture = lambda **kwargs: None
    dpg.get_viewport_width = lambda: 800
    dpg.get_viewport_height = lambda: 600
    dpg.window = lambda **kwargs: _Ctx()
    dpg.add_image = lambda *args, **kwargs: None
    dpg.add_spacing = lambda **kwargs: None
    dpg.add_loading_indicator = lambda **kwargs: None
    dpg.add_text = lambda *args, **kwargs: None
    dpg.does_item_exist = lambda tag: False
    dpg.delete_item = lambda tag: None
    dpg.does_alias_exist = lambda tag: False
    dpg.add_separator = lambda: None
    dpg.add_button = lambda **kwargs: None
    dpg.create_context = lambda: None
    dpg.create_viewport = lambda **kwargs: None
    dpg.setup_dearpygui = lambda: None
    dpg.set_primary_window = lambda *args, **kwargs: None
    dpg.show_viewport = lambda: None
    dpg.start_dearpygui = lambda: None
    dpg.destroy_context = lambda: None

    return dpg


def test_logo_eyes_visible_and_stego_frames(tmp_path):
    qr = Image.new("RGB", (50, 50), (255, 255, 255))
    config = logo_eyes.LogoConfig(
        scale=1.0, visible_qr=True, logo_path=str(tmp_path / "missing.png")
    )
    encoder = logo_eyes.LogoEyesEncoder(config)
    frame = encoder.generate_frame(qr, 0)
    assert frame.size == (encoder.width, encoder.height)

    config_stego = logo_eyes.LogoConfig(
        scale=1.0, visible_qr=False, logo_path=str(tmp_path / "missing.png")
    )
    encoder_stego = logo_eyes.LogoEyesEncoder(config_stego)
    frame_stego = encoder_stego.generate_frame(qr, 0)
    assert frame_stego.size == (encoder_stego.width, encoder_stego.height)


def test_decode_from_logo_eyes_returns_frames(tmp_path):
    qr = Image.new("RGB", (50, 50), (255, 255, 255))
    config = logo_eyes.LogoConfig(
        scale=1.0, visible_qr=True, logo_path=str(tmp_path / "missing.png")
    )
    frames = logo_eyes.encode_with_logo_eyes([qr], config=config)
    extracted = logo_eyes.decode_from_logo_eyes(frames, config=config, lsb_bits=1)
    assert len(extracted) == 1


def test_gui_logo_example_import_and_load_svg_fallback(monkeypatch):
    fake_dpg = _fake_dpg_module()
    sys.modules["dearpygui"] = types.SimpleNamespace(dearpygui=fake_dpg)
    sys.modules["dearpygui.dearpygui"] = fake_dpg

    module = importlib.import_module("meow_decoder.gui_logo_example")

    width, height = module.load_svg_as_texture(module.Path("nonexistent.svg"))
    assert width is None and height is None
