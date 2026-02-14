"""Tests for logo_eyes module (1-to-1 mapping).

Additional GUI/logo tests in test_logo_and_gui.py
"""

import pytest
from PIL import Image


class TestLogoEyes:
    def test_import_module(self):
        from meow_decoder import logo_eyes

        assert logo_eyes is not None

    def test_logo_config(self):
        from meow_decoder.logo_eyes import LogoConfig

        config = LogoConfig(scale=1.0, visible_qr=True, logo_path="missing.png")
        assert config.scale == 1.0
        assert config.visible_qr is True

    def test_logo_eyes_encoder(self, tmp_path):
        from meow_decoder.logo_eyes import LogoConfig, LogoEyesEncoder

        config = LogoConfig(scale=1.0, visible_qr=True, logo_path=str(tmp_path / "missing.png"))
        encoder = LogoEyesEncoder(config)
        qr = Image.new("RGB", (50, 50), (255, 255, 255))
        frame = encoder.generate_frame(qr, 0)
        assert frame.size == (encoder.width, encoder.height)
