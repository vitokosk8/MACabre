import struct
import threading

import pytest

from macabre.attacks import root_bridge_takeover as rbt
from macabre.attacks.bpdu_spoofing import build_bpdu_frame
from macabre.attacks.root_bridge_takeover import RootBridgeTakeoverConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_claim_advertises_this_bridge_as_its_own_root():
    body = bytes(build_bpdu_frame(ATTACKER, root_priority=0, root_mac=ATTACKER, bridge_priority=0).load)[3:]
    root_priority = struct.unpack("!H", body[5:7])[0]
    root_mac = body[7:13].hex(":")
    bridge_priority = struct.unpack("!H", body[17:19])[0]
    bridge_mac = body[19:25].hex(":")
    assert (root_priority, root_mac) == (bridge_priority, bridge_mac) == (0, ATTACKER)


def test_run_sends_the_requested_number_of_claims_on_the_interface():
    sent = []
    config = RootBridgeTakeoverConfig(iface="eth9", count=4, interval=0.01)
    stats = rbt.run_root_bridge_takeover(config, threading.Event(), lambda _s: None,
                                         run=fake_run, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4
    assert all(iface == "eth9" for iface, _ in sent)
    assert stats.root_id == f"0000.{ATTACKER}"


def test_every_claim_comes_from_this_interface_mac():
    sent = []
    config = RootBridgeTakeoverConfig(iface="eth9", count=2, interval=0.01)
    rbt.run_root_bridge_takeover(config, threading.Event(), lambda _s: None,
                                 run=fake_run, send=capture(sent))
    assert all(frame.src == ATTACKER for _, frame in sent)


def test_priority_is_checked_like_other_bridge_priorities():
    with pytest.raises(ValueError, match="multiple of 4096"):
        RootBridgeTakeoverConfig(iface="eth9", priority=100)


def test_interval_must_be_positive():
    with pytest.raises(ValueError, match="positive"):
        RootBridgeTakeoverConfig(iface="eth9", interval=0)


def test_dry_run_sends_nothing_and_reads_nothing():
    calls = []
    sent = []
    config = RootBridgeTakeoverConfig(iface="eth9", count=3, dry_run=True)
    stats = rbt.run_root_bridge_takeover(config, threading.Event(), lambda _s: None,
                                         run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")
