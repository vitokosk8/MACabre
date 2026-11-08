import struct
import threading

import pytest

from macabre.attacks import root_bridge_impersonation as rbi
from macabre.attacks.root_bridge_impersonation import RootBridgeImpersonationConfig

ATTACKER = "02:00:00:00:00:30"
ROOT = "52:d2:98:a4:6d:04"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def config(**overrides):
    values = dict(iface="eth9", root_priority=8192, root_mac=ROOT, count=2, interval=0.01)
    values.update(overrides)
    return RootBridgeImpersonationConfig(**values)


def fields(frame):
    body = bytes(frame.load)[3:]
    return {
        "root_priority": struct.unpack("!H", body[5:7])[0],
        "root_mac": body[7:13].hex(":"),
        "root_cost": struct.unpack("!I", body[13:17])[0],
        "bridge_priority": struct.unpack("!H", body[17:19])[0],
        "bridge_mac": body[19:25].hex(":"),
    }


def test_frames_carry_the_copied_root_id_and_this_bridge_as_sender():
    sent = []
    rbi.run_root_bridge_impersonation(config(), threading.Event(), lambda _s: None,
                                      run=fake_run, send=capture(sent))
    values = fields(sent[0][1])
    assert values["root_priority"] == 8192
    assert values["root_mac"] == ROOT
    assert values["bridge_mac"] == ATTACKER
    assert values["bridge_priority"] == 0
    assert values["root_cost"] == 0


def test_run_reports_the_copied_root_id():
    sent = []
    stats = rbi.run_root_bridge_impersonation(config(), threading.Event(), lambda _s: None,
                                              run=fake_run, send=capture(sent))
    assert stats.frames == 2 and len(sent) == 2
    assert stats.root_id == f"2000.{ROOT}"


def test_root_mac_is_required():
    with pytest.raises(ValueError, match="Root MAC is required"):
        RootBridgeImpersonationConfig(iface="eth9", root_priority=8192, root_mac="")


def test_copied_root_cannot_be_this_interface():
    sent = []
    with pytest.raises(RuntimeError, match="takeover"):
        rbi.run_root_bridge_impersonation(config(root_mac=ATTACKER), threading.Event(),
                                          lambda _s: None, run=fake_run, send=capture(sent))
    assert sent == []


def test_root_priority_must_be_a_multiple_of_4096():
    with pytest.raises(ValueError, match="multiple of 4096"):
        config(root_priority=100)


def test_advertised_path_cost_is_carried_in_the_bpdu():
    sent = []
    rbi.run_root_bridge_impersonation(config(root_path_cost=7), threading.Event(), lambda _s: None,
                                      run=fake_run, send=capture(sent))
    assert fields(sent[0][1])["root_cost"] == 7


def test_path_cost_must_fit_in_32_bits():
    with pytest.raises(ValueError, match="32 bits"):
        config(root_path_cost=0x1_0000_0000)


def test_dry_run_sends_nothing_and_reads_nothing():
    calls = []
    sent = []
    stats = rbi.run_root_bridge_impersonation(config(dry_run=True), threading.Event(), lambda _s: None,
                                              run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")


def test_bridge_priority_is_carried_in_the_bpdu():
    sent = []
    rbi.run_root_bridge_impersonation(config(bridge_priority=4096), threading.Event(), lambda _s: None,
                                      run=fake_run, send=capture(sent))
    assert fields(sent[0][1])["bridge_priority"] == 4096
