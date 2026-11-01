import random
import threading

import pytest

from macabre.attacks import multicast_flooding as mflood
from macabre.attacks.multicast_flooding import MulticastFloodingConfig


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_group_macs_are_ipv4_multicast_addresses():
    rng = random.Random(1)
    for _ in range(200):
        mac = mflood.group_mac(rng)
        assert mac.startswith("01:00:5e:")
        assert int(mac.split(":")[3], 16) < 0x80  # the top bit of the 4th octet is always zero


def test_frames_go_to_random_groups_from_random_local_macs():
    frames = mflood.flood_frames(random.Random(2), 20, 50)
    assert len({frame.dst for frame in frames}) > 15
    assert len({frame.src for frame in frames}) == 20
    assert all(frame.dst.startswith("01:00:5e:") for frame in frames)
    assert all(len(bytes(frame.load)) == 50 for frame in frames)


def test_run_sends_the_requested_total_in_batches():
    sent = []
    stats = mflood.run_multicast_flooding(MulticastFloodingConfig(iface="eth9", rate=100, count=25),
                                          threading.Event(), lambda _s: None, rng=random.Random(3),
                                          send=capture(sent))
    assert stats.frames == 25
    assert sum(len(frames) for _, frames in sent) == 25


@pytest.mark.parametrize("kwargs", [{"rate": 0}, {"rate": 5001}, {"payload_size": 1401}, {"count": -1}])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        MulticastFloodingConfig(iface="eth9", **kwargs)


def test_dry_run_sends_nothing():
    sent = []
    stats = mflood.run_multicast_flooding(MulticastFloodingConfig(iface="eth9", dry_run=True),
                                          threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == [] and stats.status.startswith("Dry run")
