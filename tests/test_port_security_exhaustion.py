import random
import threading

import pytest
from scapy.all import Ether

from macabre.attacks.port_security_exhaustion import (
    EXPERIMENTAL_ETHERTYPE,
    MAX_RATE,
    PortSecurityExhaustionConfig,
    exhaustion_frames,
    run_port_security_exhaustion,
)


def test_each_frame_has_a_new_unicast_source_mac():
    frames = exhaustion_frames(random.Random(1), 50)
    sources = [f[Ether].src for f in frames]
    assert len(set(sources)) == 50
    for src in sources:
        assert int(src.split(":")[0], 16) & 0x01 == 0  # unicast
        assert int(src.split(":")[0], 16) & 0x02 == 0x02  # locally administered


def test_frames_use_broadcast_destination_and_experimental_ethertype():
    frame = exhaustion_frames(random.Random(2), 1)[0]
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[Ether].type == EXPERIMENTAL_ETHERTYPE


def test_config_rejects_bad_rate_and_count():
    with pytest.raises(ValueError):
        PortSecurityExhaustionConfig(iface="x", rate=0)
    with pytest.raises(ValueError):
        PortSecurityExhaustionConfig(iface="x", rate=MAX_RATE + 1)
    with pytest.raises(ValueError):
        PortSecurityExhaustionConfig(iface="x", count=-1)


def test_run_sends_exactly_count_frames():
    sent = []
    stats = run_port_security_exhaustion(
        PortSecurityExhaustionConfig(iface="eth0", rate=100, count=25),
        threading.Event(),
        lambda s: None,
        rng=random.Random(3),
        send=lambda frames, **kw: sent.extend(frames),
    )
    assert stats.frames == 25
    assert len(sent) == 25
    assert len({f[Ether].src for f in sent}) == 25


def test_dry_run_sends_nothing():
    sent = []
    stats = run_port_security_exhaustion(
        PortSecurityExhaustionConfig(iface="eth0", count=10, dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
    assert "Nothing sent" in stats.status


def test_stop_event_ends_the_run():
    stop = threading.Event()
    stop.set()
    sent = []
    stats = run_port_security_exhaustion(
        PortSecurityExhaustionConfig(iface="eth0", count=0),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
