import json
from types import SimpleNamespace
from pathlib import Path

import meow_decoder.deadmans_switch_cli as deadman


def test_deadman_state_save_load_and_renew(tmp_path):
    gif_path = tmp_path / "secret.gif"
    gif_path.write_bytes(b"gif")

    state = deadman.DeadManSwitchState(
        gif_path=str(gif_path),
        checkin_interval_seconds=10,
        grace_period_seconds=5,
        decoy_file=None,
    )
    state.save()

    loaded = deadman.DeadManSwitchState.load(str(gif_path))
    assert loaded.gif_path == gif_path
    assert loaded.checkin_interval == 10

    loaded.renew()
    assert loaded.state["last_checkin"] is not None


def test_deadman_trigger_and_disable(tmp_path):
    gif_path = tmp_path / "secret.gif"
    gif_path.write_bytes(b"gif")

    state = deadman.DeadManSwitchState(
        gif_path=str(gif_path),
        checkin_interval_seconds=10,
        grace_period_seconds=5,
        decoy_file=None,
    )
    state.save()
    state.trigger()
    assert state.state["status"] == "triggered"
    state.disable()
    assert state.state["status"] == "disabled"


def test_cmd_setup_and_renew(tmp_path):
    gif_path = tmp_path / "secret.gif"
    gif_path.write_bytes(b"gif")

    args = SimpleNamespace(gif=str(gif_path), duration="1h", decoy=None, grace=1)
    assert deadman.cmd_setup(args) == 0

    args_renew = SimpleNamespace(gif=str(gif_path))
    assert deadman.cmd_renew(args_renew) == 0


def test_cmd_status_missing_state(tmp_path):
    gif_path = tmp_path / "secret.gif"
    gif_path.write_bytes(b"gif")
    args = SimpleNamespace(gif=str(gif_path))
    assert deadman.cmd_status(args) == 1


def test_cmd_trigger_and_disable_confirm(tmp_path):
    gif_path = tmp_path / "secret.gif"
    gif_path.write_bytes(b"gif")

    state_file = gif_path.with_suffix(".deadman.json")
    state_file.write_text(
        json.dumps(
            {
                "configured_at": "now",
                "checkin_interval_seconds": 3600,
                "grace_period_seconds": 3600,
                "decoy_file": None,
                "last_checkin": None,
                "next_deadline": None,
                "status": "armed",
            }
        )
    )

    args_trigger = SimpleNamespace(gif=str(gif_path), confirm=True)
    assert deadman.cmd_trigger(args_trigger) == 0

    args_disable = SimpleNamespace(gif=str(gif_path), confirm=True)
    assert deadman.cmd_disable(args_disable) == 0
