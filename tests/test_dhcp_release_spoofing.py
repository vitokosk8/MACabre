import random
import threading

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP, Ether

from macabre.attacks.dhcp_release_spoofing import (
    MAX_RELEASES,
    ReleaseSpoofingConfig,
    build_release,
    run_release_spoofing,
)

VICTIM = "02:00:00:00:00:50"
VICTIM_IP = "10.99.0.105"
SERVER_IP = "10.99.0.1"
SERVER_MAC = "02:00:00:00:00:02"


def config(**overrides):
    values = dict(iface="eth0", client_mac=VICTIM, client_ip=VICTIM_IP, server_ip=SERVER_IP)
    values.update(overrides)
    return ReleaseSpoofingConfig(**values)


def option(packet, name):
    return dict(o for o in packet[DHCP].options if isinstance(o, tuple))[name]


def test_release_carries_the_victims_mac_address_and_server_identifier():
    frame = build_release(config(), xid=1234)
    assert frame[Ether].src == VICTIM
    assert frame[IP].src == VICTIM_IP
    assert frame[IP].dst == SERVER_IP
    assert frame[UDP].sport == 68 and frame[UDP].dport == 67
    assert frame[BOOTP].op == 1
    assert frame[BOOTP].xid == 1234
    assert frame[BOOTP].ciaddr == VICTIM_IP
    assert frame[BOOTP].chaddr[:6] == bytes.fromhex(VICTIM.replace(":", ""))
    assert option(frame, "message-type") == "release"
    assert option(frame, "server_id") == SERVER_IP


def test_release_goes_to_the_server_mac_when_given():
    assert build_release(config(server_mac=SERVER_MAC), xid=1)[Ether].dst == SERVER_MAC


def test_release_is_broadcast_without_a_server_mac():
    assert build_release(config(), xid=1)[Ether].dst == "ff:ff:ff:ff:ff:ff"


@pytest.mark.parametrize("overrides", [
    dict(client_mac="not-a-mac"),
    dict(client_ip="10.99.0"),
    dict(server_ip="nope"),
    dict(server_mac="zz:zz"),
    dict(releases=0),
    dict(releases=MAX_RELEASES + 1),
])
def test_bad_inputs_are_refused(overrides):
    with pytest.raises(ValueError):
        config(**overrides)


def test_run_sends_each_release_once_with_its_own_xid():
    sent = []
    stats = run_release_spoofing(
        config(releases=3), threading.Event(), lambda s: None,
        rng=random.Random(1), send=lambda frame, **kw: sent.append(frame),
    )
    assert stats.releases == 3
    assert len(sent) == 3
    assert len({f[BOOTP].xid for f in sent}) == 3


def test_dry_run_sends_nothing():
    sent = []
    stats = run_release_spoofing(
        config(dry_run=True), threading.Event(), lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert "Nothing sent" in stats.status


def test_stop_event_set_before_run_sends_nothing():
    stop = threading.Event()
    stop.set()
    sent = []
    run_release_spoofing(config(), stop, lambda s: None, send=lambda *a, **kw: sent.append(a))
    assert sent == []
