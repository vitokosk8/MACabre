"""macOS paths: reading and changing an interface MAC with ifconfig."""

import sys

import pytest

from macabre.attacks import common, mac_cloning


@pytest.fixture
def darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")


def test_macos_reads_the_mac_from_ifconfig_and_pads_octets(darwin):
    calls = []
    output = "en5: flags=8863<UP>\n\tether 0:e0:4c:f8:d1:a8\n\tinet 192.168.1.20 netmask 0xffffff00"

    def fake_run(argv):
        calls.append(argv)
        return output

    assert common.read_interface_mac("en5", run=fake_run) == "00:e0:4c:f8:d1:a8"
    assert calls == [["ifconfig", "en5"]]


def test_macos_clone_is_a_single_ifconfig_command(darwin):
    assert mac_cloning.set_mac_commands("en5", "02:00:00:00:00:50") == [
        ["ifconfig", "en5", "ether", "02:00:00:00:00:50"],
    ]


def test_macos_missing_mac_raises(darwin):
    with pytest.raises(RuntimeError):
        common.read_interface_mac("en5", run=lambda argv: "en5: flags=8863<UP>")


def test_linux_still_uses_ip(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    calls = []

    def fake_run(argv):
        calls.append(argv)
        return "2: eth9: <UP> link/ether 02:00:00:00:00:30 brd ff:ff:ff:ff:ff:ff"

    assert common.read_interface_mac("eth9", run=fake_run) == "02:00:00:00:00:30"
    assert calls[0][:2] == ["ip", "-o"]
    assert mac_cloning.set_mac_commands("eth9", "02:00:00:00:00:50")[0] == ["ip", "link", "set", "dev", "eth9", "down"]
