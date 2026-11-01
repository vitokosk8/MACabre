import random
import threading

import pytest

from macabre.attacks import broadcast_storm as storm
from macabre.attacks.broadcast_storm import BroadcastStormConfig


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_frames_are_broadcast_from_random_local_macs_with_the_payload_size():
    frames = storm.storm_frames(random.Random(1), 20, 100)
    assert all(frame.dst == "ff:ff:ff:ff:ff:ff" for frame in frames)
    assert len({frame.src for frame in frames}) == 20
    assert all(len(bytes(frame.load)) == 100 for frame in frames)
    assert all(frame.type == 0x88B5 for frame in frames)


def test_run_sends_the_requested_total_in_batches():
    sent = []
    stats = storm.run_broadcast_storm(BroadcastStormConfig(iface="eth9", rate=100, count=25),
                                      threading.Event(), lambda _s: None, rng=random.Random(2),
                                      send=capture(sent))
    assert stats.frames == 25
    assert sum(len(frames) for _, frames in sent) == 25


@pytest.mark.parametrize("kwargs", [{"rate": 0}, {"rate": 5001}, {"payload_size": -1},
                                    {"payload_size": 1401}, {"count": -1}])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        BroadcastStormConfig(iface="eth9", **kwargs)


def test_dry_run_sends_nothing():
    sent = []
    stats = storm.run_broadcast_storm(BroadcastStormConfig(iface="eth9", dry_run=True), threading.Event(),
                                      lambda _s: None, send=capture(sent))
    assert sent == [] and stats.status.startswith("Dry run")
