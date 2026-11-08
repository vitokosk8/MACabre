import threading

import pytest
from scapy.all import ARP, Ether, Raw

from macabre.attacks.unknown_unicast_flooding import (
    MAX_DURATION,
    UnknownUnicastConfig,
    UnknownUnicastStats,
    flooded_destination,
    observe,
    run_unknown_unicast_flooding,
)

OWN = "02:00:00:00:00:70"


def unicast(src: str, dst: str) -> Ether:
    return Ether(src=src, dst=dst) / Raw(b"x")


def test_unicast_to_another_host_is_counted():
    stats = UnknownUnicastStats()
    observe(stats, unicast("02:00:00:00:00:50", "02:00:00:00:00:51"), OWN)
    assert stats.frames == 1
    assert stats.destinations == {"02:00:00:00:00:51"}


def test_frames_addressed_to_this_host_are_ignored():
    stats = UnknownUnicastStats()
    observe(stats, unicast("02:00:00:00:00:50", OWN), OWN)
    assert stats.frames == 0


def test_frames_sent_by_this_host_are_ignored():
    stats = UnknownUnicastStats()
    observe(stats, unicast(OWN, "02:00:00:00:00:51"), OWN)
    assert stats.frames == 0


def test_broadcast_and_multicast_are_not_unicast():
    assert flooded_destination(unicast("02:00:00:00:00:50", "ff:ff:ff:ff:ff:ff"), OWN) is None
    assert flooded_destination(unicast("02:00:00:00:00:50", "01:00:5e:00:00:01"), OWN) is None


def test_non_ethernet_frames_are_ignored():
    assert flooded_destination(ARP(), OWN) is None


def test_destinations_are_counted_once_each():
    stats = UnknownUnicastStats()
    for _ in range(3):
        observe(stats, unicast("02:00:00:00:00:50", "02:00:00:00:00:51"), OWN)
    observe(stats, unicast("02:00:00:00:00:50", "02:00:00:00:00:52"), OWN)
    assert stats.frames == 4
    assert len(stats.destinations) == 2


def test_config_rejects_bad_duration():
    with pytest.raises(ValueError):
        UnknownUnicastConfig(iface="eth0", duration=-1)
    with pytest.raises(ValueError):
        UnknownUnicastConfig(iface="eth0", duration=MAX_DURATION + 1)


class FakeSniffer:
    """Stands in for AsyncSniffer: delivers the given frames to prn when started."""

    def __init__(self, frames, **kwargs):
        self.frames = frames
        self.prn = kwargs["prn"]
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        for frame in self.frames:
            self.prn(frame)

    def stop(self):
        self.stopped = True


def test_run_counts_frames_from_the_sniffer():
    frames = [unicast("02:00:00:00:00:50", "02:00:00:00:00:51") for _ in range(5)]
    created = {}

    def make(**kwargs):
        created["sniffer"] = FakeSniffer(frames, **kwargs)
        return created["sniffer"]

    stop = threading.Event()
    stop.set()  # run returns at once after the sniffer has been started
    stats = run_unknown_unicast_flooding(
        UnknownUnicastConfig(iface="eth0", duration=30),
        stop,
        lambda s: None,
        own_mac=OWN,
        make_sniffer=make,
    )
    assert stats.frames == 5
    assert created["sniffer"].started and created["sniffer"].stopped
    assert "5 to 1 destination" in stats.status


def test_dry_run_captures_nothing():
    created = []
    stats = run_unknown_unicast_flooding(
        UnknownUnicastConfig(iface="eth0", duration=30, dry_run=True),
        threading.Event(),
        lambda s: None,
        own_mac=OWN,
        make_sniffer=lambda **kw: created.append(kw),
    )
    assert created == []
    assert stats.frames == 0
    assert "Nothing captured" in stats.status
