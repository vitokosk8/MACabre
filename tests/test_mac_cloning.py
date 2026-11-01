import threading

import pytest

from macabre.attacks import mac_cloning as cloning
from macabre.attacks.mac_cloning import MacCloningConfig

ORIGINAL = "02:00:00:00:00:30"
TARGET = "02:00:00:00:00:20"

LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ORIGINAL} brd ff:ff:ff:ff:ff:ff"
)


class FakeHost:
    """Records the commands a clone run would execute, and answers `ip -o link show`."""

    def __init__(self, mac=ORIGINAL):
        self.mac = mac
        self.commands = []

    def __call__(self, argv):
        self.commands.append(argv)
        if argv[:4] == ["ip", "-o", "link", "show"]:
            return LINK_OUTPUT.replace(ORIGINAL, self.mac)
        return ""


def test_clone_sets_target_then_restores_original_on_stop():
    host = FakeHost()
    stop = threading.Event()
    stop.set()  # stop immediately after cloning
    config = MacCloningConfig(iface="eth9", target_mac=TARGET)

    stats = cloning.run_cloning(config, stop, lambda _s: None, run=host)

    assert host.commands[0] == ["ip", "-o", "link", "show", "dev", "eth9"]
    assert host.commands[1:4] == cloning.set_mac_commands("eth9", TARGET)
    assert host.commands[4:7] == cloning.set_mac_commands("eth9", ORIGINAL)
    assert stats.active is False
    assert stats.status == f"Restored original MAC {ORIGINAL} on eth9."


def test_clone_stays_active_until_stop_is_set():
    host = FakeHost()
    stop = threading.Event()
    seen = []

    def on_progress(stats):
        seen.append(stats)
        stop.set()

    stats = cloning.run_cloning(
        MacCloningConfig(iface="eth9", target_mac=TARGET), stop, on_progress, run=host
    )

    assert seen[0].active is True
    assert seen[0].cloned_mac == TARGET
    assert seen[0].original_mac == ORIGINAL
    assert stats.active is False


def test_target_is_normalized_to_lowercase():
    host = FakeHost()
    stop = threading.Event()
    stop.set()
    cloning.run_cloning(
        MacCloningConfig(iface="eth9", target_mac="02:AA:BB:CC:DD:EE"), stop, lambda _s: None, run=host
    )
    assert ["ip", "link", "set", "dev", "eth9", "address", "02:aa:bb:cc:dd:ee"] in host.commands


def test_dry_run_runs_no_commands():
    host = FakeHost()
    config = MacCloningConfig(iface="eth9", target_mac=TARGET, dry_run=True)
    stats = cloning.run_cloning(config, threading.Event(), lambda _s: None, run=host)
    assert host.commands == []
    assert stats.status.startswith("Dry run")


def test_unreadable_mac_is_an_error():
    def no_mac(argv):
        return "2: eth9: <UP> mtu 1500"

    with pytest.raises(RuntimeError, match="Cannot read the MAC"):
        cloning.run_cloning(
            MacCloningConfig(iface="eth9", target_mac=TARGET),
            threading.Event(),
            lambda _s: None,
            run=no_mac,
        )


@pytest.mark.parametrize("value, message", [
    ("", "required"),
    ("nope", "Invalid MAC"),
    ("01:00:5e:00:00:01", "unicast"),
])
def test_invalid_target_is_rejected(value, message):
    with pytest.raises(ValueError, match=message):
        MacCloningConfig(iface="eth9", target_mac=value)


def test_restore_runs_even_if_setting_the_mac_fails():
    calls = []

    def flaky(argv):
        calls.append(argv)
        if argv[:4] == ["ip", "-o", "link", "show"]:
            return LINK_OUTPUT
        if "address" in argv and TARGET in argv:
            raise RuntimeError("RTNETLINK answers: Device or resource busy")
        return ""

    with pytest.raises(RuntimeError):
        cloning.run_cloning(
            MacCloningConfig(iface="eth9", target_mac=TARGET),
            threading.Event(),
            lambda _s: None,
            run=flaky,
        )
    assert ["ip", "link", "set", "dev", "eth9", "address", ORIGINAL] in calls
