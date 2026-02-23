"""
Tests for air-gap verification module.

Tests cover:
- Air-gap status structure
- Network interface checks
- DNS resolver checks
- WiFi/Bluetooth detection
- Default route detection
- Non-Linux platform handling
"""

import os
import platform
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from meow_decoder.air_gap import (
    AirGapStatus,
    _check_bluetooth,
    _check_default_route,
    _check_dns,
    _check_network_interfaces,
    _check_wifi,
    verify_air_gap,
)


class TestAirGapStatus:
    """Tests for AirGapStatus data structure."""

    def test_empty_status_is_airgapped(self):
        """Empty checks = air-gapped (vacuously true)."""
        s = AirGapStatus()
        assert s.air_gapped is True
        assert s.unknown is False

    def test_all_true_is_airgapped(self):
        """All checks True = air-gapped."""
        s = AirGapStatus()
        s.checks["no_network"] = True
        s.checks["no_dns"] = True
        assert s.air_gapped is True

    def test_one_false_not_airgapped(self):
        """Any check False = not air-gapped."""
        s = AirGapStatus()
        s.checks["no_network"] = True
        s.checks["no_dns"] = False
        assert s.air_gapped is False

    def test_none_means_unknown(self):
        """None checks indicate unknown status."""
        s = AirGapStatus()
        s.checks["no_network"] = None
        assert s.unknown is True
        # None is treated as "not failing" (ambiguous)
        assert s.air_gapped is True

    def test_to_dict(self):
        """to_dict should return plain dict."""
        s = AirGapStatus()
        s.checks["no_network"] = True
        s.details["no_network"] = "All clear"

        d = s.to_dict()
        assert isinstance(d, dict)
        assert d["air_gapped"] is True
        assert d["checks"]["no_network"] is True
        assert d["details"]["no_network"] == "All clear"


class TestCheckNetworkInterfaces:
    """Tests for network interface detection."""

    @patch("subprocess.run")
    def test_no_active_interfaces(self, mock_run):
        """No active non-loopback interfaces = pass."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n",
        )
        status = AirGapStatus()
        _check_network_interfaces(status)
        assert status.checks["no_active_network"] is True

    @patch("subprocess.run")
    def test_active_eth0(self, mock_run):
        """Active eth0 = fail."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "1: lo: <LOOPBACK,UP> mtu 65536\n" "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n"
            ),
        )
        status = AirGapStatus()
        _check_network_interfaces(status)
        assert status.checks["no_active_network"] is False
        assert "eth0" in status.details.get("no_active_network", "")

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_ip_command_missing(self, mock_run):
        """Missing ip command = unknown."""
        status = AirGapStatus()
        _check_network_interfaces(status)
        assert status.checks["no_active_network"] is None

    @patch("subprocess.run")
    def test_ip_command_fails(self, mock_run):
        """ip command failure = unknown."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        status = AirGapStatus()
        _check_network_interfaces(status)
        assert status.checks["no_active_network"] is None


class TestCheckDns:
    """Tests for DNS resolver detection."""

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.read_text", return_value="# No nameservers\n")
    def test_no_nameservers(self, mock_read, mock_exists):
        """No nameserver lines = pass."""
        status = AirGapStatus()
        _check_dns(status)
        assert status.checks["no_dns"] is True

    @patch("pathlib.Path.exists", return_value=True)
    @patch(
        "pathlib.Path.read_text",
        return_value="nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
    )
    def test_external_nameservers(self, mock_read, mock_exists):
        """External nameservers = fail."""
        status = AirGapStatus()
        _check_dns(status)
        assert status.checks["no_dns"] is False
        assert "8.8.8.8" in status.details.get("no_dns", "")

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.read_text", return_value="nameserver 127.0.0.53\n")
    def test_localhost_resolver_ok(self, mock_read, mock_exists):
        """Localhost resolver (systemd-resolved) = pass."""
        status = AirGapStatus()
        _check_dns(status)
        assert status.checks["no_dns"] is True

    @patch("pathlib.Path.exists", return_value=False)
    def test_no_resolv_conf(self, mock_exists):
        """Missing resolv.conf = pass (no DNS configured)."""
        status = AirGapStatus()
        _check_dns(status)
        assert status.checks["no_dns"] is True


class TestCheckWifi:
    """Tests for WiFi adapter detection."""

    @patch("pathlib.Path.exists", return_value=False)
    def test_no_sys_class_net(self, mock_exists):
        """No /sys/class/net = check via rfkill."""
        status = AirGapStatus()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            _check_wifi(status)
        assert status.checks["no_wifi"] is True

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.iterdir")
    def test_no_wireless_dirs(self, mock_iterdir, mock_exists):
        """No wireless/ subdirectories = no WiFi."""
        iface = MagicMock()
        iface.name = "eth0"
        wireless = MagicMock()
        wireless.exists.return_value = False
        iface.__truediv__ = MagicMock(return_value=wireless)
        mock_iterdir.return_value = [iface]

        status = AirGapStatus()
        _check_wifi(status)
        assert status.checks["no_wifi"] is True


class TestCheckBluetooth:
    """Tests for Bluetooth adapter detection."""

    @patch("pathlib.Path.exists", return_value=False)
    def test_no_bluetooth_dir(self, mock_exists):
        """No /sys/class/bluetooth = check rfkill."""
        status = AirGapStatus()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            _check_bluetooth(status)
        assert status.checks["no_bluetooth"] is True


class TestCheckDefaultRoute:
    """Tests for default route detection."""

    @patch("subprocess.run")
    def test_no_default_route(self, mock_run):
        """Empty route output = pass."""
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        status = AirGapStatus()
        _check_default_route(status)
        assert status.checks["no_default_route"] is True

    @patch("subprocess.run")
    def test_has_default_route(self, mock_run):
        """Default route present = fail."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
        )
        status = AirGapStatus()
        _check_default_route(status)
        assert status.checks["no_default_route"] is False
        assert "192.168.1.1" in status.details.get("no_default_route", "")

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_ip_missing(self, mock_run):
        """Missing ip command = unknown."""
        status = AirGapStatus()
        _check_default_route(status)
        assert status.checks["no_default_route"] is None


class TestVerifyAirGap:
    """Integration tests for verify_air_gap."""

    @patch("meow_decoder.air_gap.platform")
    def test_non_linux_returns_unknown(self, mock_platform):
        """Non-Linux platforms should return unknown."""
        mock_platform.system.return_value = "Darwin"
        status = verify_air_gap()
        assert status.unknown is True
        assert "platform" in status.checks

    @patch("meow_decoder.air_gap.platform")
    def test_linux_runs_all_checks(self, mock_platform):
        """Linux should run all 5 checks."""
        mock_platform.system.return_value = "Linux"

        with (
            patch("meow_decoder.air_gap._check_network_interfaces") as m1,
            patch("meow_decoder.air_gap._check_dns") as m2,
            patch("meow_decoder.air_gap._check_wifi") as m3,
            patch("meow_decoder.air_gap._check_bluetooth") as m4,
            patch("meow_decoder.air_gap._check_default_route") as m5,
        ):
            verify_air_gap()
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()
            m5.assert_called_once()
