import runpy


def test_crypto_selftest_runs():
    # Executes the __main__ test block for extra coverage.
    runpy.run_module("meow_decoder.crypto", run_name="__main__")


def test_fountain_selftest_runs():
    runpy.run_module("meow_decoder.fountain", run_name="__main__")


def test_config_selftest_runs():
    runpy.run_module("meow_decoder.config", run_name="__main__")


def test_frame_mac_selftest_runs():
    runpy.run_module("meow_decoder.frame_mac", run_name="__main__")


def test_forward_secrecy_selftest_runs():
    runpy.run_module("meow_decoder.forward_secrecy", run_name="__main__")


def test_constant_time_selftest_runs():
    runpy.run_module("meow_decoder.constant_time", run_name="__main__")


def test_metadata_obfuscation_selftest_runs():
    runpy.run_module("meow_decoder.metadata_obfuscation", run_name="__main__")


def test_gif_handler_selftest_runs():
    runpy.run_module("meow_decoder.gif_handler", run_name="__main__")


def test_qr_code_selftest_runs():
    runpy.run_module("meow_decoder.qr_code", run_name="__main__")


def test_decoy_generator_selftest_runs():
    runpy.run_module("meow_decoder.decoy_generator", run_name="__main__")
