import random
import threading

import pytest
from scapy.all import Ether
from scapy.contrib.lacp import LACP

from macabre.attacks.lacp_spoofing import (
    LacpSpoofingConfig,
    MAX_FRAMES,
    SLOW_PROTOCOLS_MAC,
    build_lacpdu,
    run_lacp_spoofing,
)

SYSTEM = "02:00:00:00:00:81"


def test_lacpdu_is_sent_to_the_slow_protocols_address_with_the_claimed_actor():
    frame = build_lacpdu(SYSTEM, key=7, port_number=3)
    assert frame[Ether].src == SYSTEM
    assert frame[Ether].dst == SLOW_PROTOCOLS_MAC == "01:80:c2:00:00:02"
    assert frame[Ether].type == 0x8809
    assert frame[LACP].actor_system == SYSTEM
    assert frame[LACP].actor_key == 7
    assert frame[LACP].actor_port_number == 3


def test_partner_fields_are_left_empty():
    frame = build_lacpdu(SYSTEM)
    assert frame[LACP].partner_system == "00:00:00:00:00:00"
    assert frame[LACP].partner_key == 0


def test_run_sends_the_configured_number_of_frames():
    sent = []
    config = LacpSpoofingConfig(iface="eth9", system_mac=SYSTEM, frames=3, interval=0.001)
    stats = run_lacp_spoofing(config, threading.Event(), lambda _s: None,
                              send=lambda frame, iface, verbose: sent.append((iface, frame)))
    assert stats.frames == 3 and len(sent) == 3
    assert all(iface == "eth9" for iface, _ in sent)


def test_empty_system_mac_uses_one_random_mac_for_the_run():
    sent = []
    config = LacpSpoofingConfig(iface="eth9", frames=2, interval=0.001)
    run_lacp_spoofing(config, threading.Event(), lambda _s: None, rng=random.Random(1),
                      send=lambda frame, iface, verbose: sent.append(frame))
    assert sent[0][Ether].src == sent[1][Ether].src != "00:00:00:00:00:00"


def test_dry_run_sends_nothing():
    sent = []
    stats = run_lacp_spoofing(LacpSpoofingConfig(iface="eth9", system_mac=SYSTEM, dry_run=True),
                              threading.Event(), lambda _s: None,
                              send=lambda frame, iface, verbose: sent.append(frame))
    assert sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("kwargs", [
    {"frames": 0}, {"frames": MAX_FRAMES + 1}, {"key": 0x10000}, {"port_number": -1},
    {"state": 256}, {"interval": 0}, {"system_mac": "01:00:00:00:00:01"},
])
def test_config_rejects_out_of_range_values(kwargs):
    with pytest.raises(ValueError):
        LacpSpoofingConfig(iface="eth9", **kwargs)
