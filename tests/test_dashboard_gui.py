import importlib
import sys
import types


def _install_fake_dpg():
    values = {}

    class _Ctx:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    dpg = types.SimpleNamespace()
    dpg.mvAll = 0
    dpg.mvThemeCol_Text = 1
    dpg.mvThemeCol_Button = 2
    dpg.mvThemeCol_ButtonHovered = 3
    dpg.mvThemeCol_ButtonActive = 4
    dpg.mvStyleVar_FrameRounding = 5
    dpg.mvStyleVar_WindowRounding = 6
    dpg.mvThemeCol_WindowBg = 7
    dpg.mvThemeCol_FrameBg = 8
    dpg.mvThemeCol_TitleBg = 9
    dpg.mvThemeCol_TitleBgActive = 10

    dpg.create_context = lambda: None
    dpg.create_viewport = lambda **kwargs: None
    dpg.setup_dearpygui = lambda: None
    dpg.show_viewport = lambda: None
    dpg.set_primary_window = lambda *args, **kwargs: None
    dpg.start_dearpygui = lambda: None
    dpg.destroy_context = lambda: None
    dpg.bind_theme = lambda theme: None

    dpg.window = lambda **kwargs: _Ctx()
    dpg.tab_bar = lambda **kwargs: _Ctx()
    dpg.tab = lambda **kwargs: _Ctx()
    dpg.group = lambda **kwargs: _Ctx()
    dpg.theme = lambda **kwargs: _Ctx()
    dpg.theme_component = lambda *args, **kwargs: _Ctx()
    dpg.texture_registry = lambda **kwargs: _Ctx()

    dpg.add_text = lambda *args, **kwargs: None
    dpg.add_separator = lambda *args, **kwargs: None
    dpg.add_input_text = lambda *args, **kwargs: None
    dpg.add_button = lambda *args, **kwargs: None
    dpg.add_checkbox = lambda *args, **kwargs: None
    dpg.add_slider_float = lambda *args, **kwargs: None
    dpg.add_slider_int = lambda *args, **kwargs: None
    dpg.add_progress_bar = lambda *args, **kwargs: None
    dpg.add_spacer = lambda *args, **kwargs: None
    dpg.add_combo = lambda *args, **kwargs: None
    dpg.add_loading_indicator = lambda *args, **kwargs: None
    dpg.add_image = lambda *args, **kwargs: None
    dpg.add_raw_texture = lambda *args, **kwargs: None
    dpg.add_theme_color = lambda *args, **kwargs: None
    dpg.add_theme_style = lambda *args, **kwargs: None

    # Texture formats
    dpg.mvFormat_Float_rgba = 0

    dpg.set_value = lambda tag, value: values.__setitem__(tag, value)
    dpg.get_value = lambda tag: values.get(tag)

    dpg.does_item_exist = lambda tag: False
    dpg.delete_item = lambda tag: None
    dpg.does_alias_exist = lambda tag: False

    sys.modules["dearpygui"] = types.SimpleNamespace(dearpygui=dpg)
    sys.modules["dearpygui.dearpygui"] = dpg

    return dpg


def test_meow_dashboard_demo_create_dashboard():
    _install_fake_dpg()
    module = importlib.import_module("meow_decoder.meow_dashboard_demo")
    dashboard = module.MeowDashboard()
    dashboard.create_dashboard()


def test_meow_gui_enhanced_init():
    _install_fake_dpg()
    module = importlib.import_module("meow_decoder.meow_gui_enhanced")
    gui = module.MeowGUI()
    assert gui is not None
