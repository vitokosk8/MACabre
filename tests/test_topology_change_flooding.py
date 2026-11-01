import struct
import threading

import pytest

from macabre.attacks import topology_change_flooding as tcf
from macabre.attacks.topology_change_flooding import TopologyChangeFloodingConfig

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
    values = dict(iface="eth9", root_priority=8192, root_mac=ROOT, count=3, interval=0.01)
    values.update(overrides)
    return TopologyChangeFloodingConfig(**values)


def test_every_bpdu_carries_the_topology_change_flag():
    sent = []
    tcf.run_topology_change_flooding(config(), threading.Event(), lambda _s: None,
                                     run=fake_run, send=capture(sent))
    assert len(sent) == 3
    for _, frame in sent:
        assert bytes(frame.load)[3:][4] == 0x01


def test_the_copied_root_id_is_kept():
    sent = []
    tcf.run_topology_change_flooding(config(), threading.Event(), lambda _s: None,
                                     run=fake_run, send=capture(sent))
    body = bytes(sent[0][1].load)[3:]
    assert struct.unpack("!H", body[5:7])[0] == 8192
    assert body[7:13].hex(":") == ROOT


def test_the_same_checks_as_impersonation_apply():
    with pytest.raises(ValueError, match="Root MAC is required"):
        TopologyChangeFloodingConfig(iface="eth9", root_priority=8192, root_mac="")
    with pytest.raises(ValueError, match="multiple of 4096"):
        config(root_priority=100)
    with pytest.raises(ValueError, match="positive"):
        config(interval=0)


def test_dry_run_sends_nothing_and_reads_nothing():
    calls = []
    sent = []
    stats = tcf.run_topology_change_flooding(config(dry_run=True), threading.Event(), lambda _s: None,
                                             run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")
