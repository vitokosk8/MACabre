import threading

import pytest
from scapy.all import IP, UDP, Ether, Raw

from macabre.attacks.private_vlan_bypass import (
    MAX_PROBES,
    PAYLOAD,
    PrivateVlanBypassConfig,
    build_probe,
    run_private_vlan_bypass,
)

ATTACKER = "02:00:00:00:00:20"
TARGET = "02:00:00:00:00:30"
RELAY = "02:00:00:00:00:01"


def config(**kw):
    base = dict(iface="eth0", source_mac=ATTACKER, source_ip="10.77.0.20", target_mac=TARGET, target_ip="10.77.0.30")
    base.update(kw)
    return PrivateVlanBypassConfig(**base)


def test_direct_probe_goes_to_the_target_mac():
    frame = build_probe(config())
    assert frame[Ether].dst == TARGET
    assert frame[IP].dst == "10.77.0.30"
    assert frame[UDP].dport == 4000
    assert bytes(frame[Raw]) == PAYLOAD


def test_relayed_probe_goes_to_the_relay_mac_with_the_target_ip():
    frame = build_probe(config(relay_mac=RELAY))
    assert frame[Ether].dst == RELAY
    assert frame[IP].dst == "10.77.0.30"


def test_config_rejects_bad_values():
    with pytest.raises(ValueError):
        config(source_mac="bad")
    with pytest.raises(ValueError):
        config(target_ip="not-an-ip")
    with pytest.raises(ValueError):
        config(relay_mac="bad")
    with pytest.raises(ValueError):
        config(probes=0)
    with pytest.raises(ValueError):
        config(probes=MAX_PROBES + 1)


def test_run_sends_the_probes():
    sent = []
    stats = run_private_vlan_bypass(
        config(relay_mac=RELAY, probes=4),
        threading.Event(),
        lambda s: None,
        send=lambda frame, **kw: sent.append(frame),
    )
    assert stats.probes == 4
    assert len(sent) == 4


def test_dry_run_sends_nothing():
    sent = []
    stats = run_private_vlan_bypass(
        config(dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert "Nothing sent" in stats.status


def test_stop_event_set_before_run_sends_nothing():
    stop = threading.Event()
    stop.set()
    sent = []
    stats = run_private_vlan_bypass(config(), stop, lambda s: None, send=lambda *a, **kw: sent.append(a))
    assert sent == []
    assert stats.probes == 0
