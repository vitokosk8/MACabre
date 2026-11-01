import threading

import pytest
from scapy.all import Ether

from macabre.attacks import tcn_spoofing as tcn
from macabre.attacks.tcn_spoofing import TcnSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_tcn_goes_to_the_stp_group_address_from_the_sender():
    frame = tcn.build_tcn_frame(ATTACKER)
    assert frame[Ether].dst == "01:80:c2:00:00:00"
    assert frame[Ether].src == ATTACKER


def test_tcn_body_is_four_bytes_with_type_0x80():
    payload = bytes(tcn.build_tcn_frame(ATTACKER).load)
    assert payload == bytes.fromhex("424203" "00000080")
    assert tcn.build_tcn_frame(ATTACKER)[Ether].type == 7


def test_run_sends_the_requested_number_of_tcns():
    sent = []
    stats = tcn.run_tcn_spoofing(TcnSpoofingConfig(iface="eth9", count=5, interval=0.01),
                                 threading.Event(), lambda _s: None, run=fake_run,
                                 send=lambda f, iface, verbose: sent.append((iface, f)))
    assert stats.frames == 5 and len(sent) == 5
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing_and_reads_nothing():
    calls = []
    sent = []
    stats = tcn.run_tcn_spoofing(TcnSpoofingConfig(iface="eth9", count=3, dry_run=True),
                                 threading.Event(), lambda _s: None,
                                 run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("interval", [0, -1])
def test_interval_must_be_positive(interval):
    with pytest.raises(ValueError, match="positive"):
        TcnSpoofingConfig(iface="eth9", interval=interval)
