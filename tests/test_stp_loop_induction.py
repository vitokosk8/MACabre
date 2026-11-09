import sys
import threading

import pytest

from macabre.attacks import stp_loop_induction as sli
from macabre.attacks.stp_loop_induction import StpLoopInductionConfig


def config(**overrides):
    values = dict(iface_a="a1", iface_b="a2")
    values.update(overrides)
    return StpLoopInductionConfig(**values)


def recorder(fail_on=None):
    calls = []

    def run(argv):
        calls.append(argv)
        if fail_on is not None and argv[:len(fail_on)] == fail_on:
            raise RuntimeError("boom")
        return ""

    return calls, run


def stopped():
    event = threading.Event()
    event.set()
    return event


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")


def test_bridge_is_built_with_stp_off_and_both_ports_enslaved(linux):
    calls, run = recorder()
    sli.run_stp_loop_induction(config(), stopped(), lambda _s: None, run=run)
    assert calls[0] == ["ip", "link", "add", "name", "br-loop", "type", "bridge", "stp_state", "0"]
    assert ["ip", "link", "set", "a1", "master", "br-loop"] in calls
    assert ["ip", "link", "set", "a2", "master", "br-loop"] in calls


def test_stp_bpdus_are_dropped_when_the_bridge_runs_no_stp(linux):
    calls, run = recorder()
    sli.run_stp_loop_induction(config(), stopped(), lambda _s: None, run=run)
    rule = ["nft", "add", "rule", "bridge", sli.NFT_TABLE, sli.NFT_CHAIN, "ether", "daddr", sli.STP_GROUP_MAC, "drop"]
    assert rule in calls


def test_control_runs_stp_and_keeps_bpdus(linux):
    calls, run = recorder()
    sli.run_stp_loop_induction(config(run_stp=True), stopped(), lambda _s: None, run=run)
    assert calls[0][-2:] == ["stp_state", "1"]
    assert not any(argv[0] == "nft" for argv in calls)


def test_teardown_removes_the_bridge_and_the_rule(linux):
    calls, run = recorder()
    sli.run_stp_loop_induction(config(), stopped(), lambda _s: None, run=run)
    assert ["nft", "delete", "table", "bridge", sli.NFT_TABLE] in calls
    assert calls[-1] == ["ip", "link", "delete", "br-loop"]


def test_teardown_runs_even_when_a_setup_command_fails(linux):
    calls, run = recorder(fail_on=["ip", "link", "set", "a2", "master"])
    with pytest.raises(RuntimeError):
        sli.run_stp_loop_induction(config(), stopped(), lambda _s: None, run=run)
    assert calls[-1] == ["ip", "link", "delete", "br-loop"]


def test_the_bridge_is_held_until_the_stop_event_is_set(linux):
    calls, run = recorder()
    event = threading.Event()
    timer = threading.Timer(0.05, event.set)
    timer.start()
    sli.run_stp_loop_induction(config(), event, lambda _s: None, run=run)
    timer.join()
    assert calls[-1] == ["ip", "link", "delete", "br-loop"]


def test_the_same_interface_twice_is_rejected():
    with pytest.raises(ValueError, match="must be different"):
        config(iface_b="a1")


@pytest.mark.parametrize("name", ["", "a1;rm", "x" * 16, "a 1"])
def test_invalid_interface_names_are_rejected(name):
    with pytest.raises(ValueError, match="Invalid interface name"):
        config(iface_a=name)


def test_dry_run_changes_nothing(linux):
    calls, run = recorder()
    stats = sli.run_stp_loop_induction(config(dry_run=True), stopped(), lambda _s: None, run=run)
    assert calls == []
    assert stats.status.startswith("Dry run")


def test_refuses_to_run_off_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    calls, run = recorder()
    with pytest.raises(RuntimeError, match="needs Linux"):
        sli.run_stp_loop_induction(config(), stopped(), lambda _s: None, run=run)
    assert calls == []


def test_iface_property_is_the_first_interface_for_the_gui_log():
    assert config(iface_a="a1", iface_b="a2").iface == "a1"
