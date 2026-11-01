import random
import threading

import pytest

from macabre.attacks import dhcp_discover_flooding as flood
from macabre.attacks.dhcp_discover_flooding import DiscoverFloodConfig
from macabre.attacks.dhcp_starvation import _message_type


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_every_frame_is_a_discover_from_a_different_random_client():
    sent = []
    flood.run_discover_flooding(DiscoverFloodConfig(iface="eth9", rate=100, count=40),
                                threading.Event(), lambda _s: None,
                                rng=random.Random(1), send=capture(sent))
    frames = [f for _, batch in sent for f in batch]
    assert len(frames) == 40
    assert all(_message_type(f) == "discover" for f in frames)
    assert len({f.src for f in frames}) == 40


def test_run_sends_the_requested_total_on_the_interface():
    sent = []
    stats = flood.run_discover_flooding(DiscoverFloodConfig(iface="eth9", rate=100, count=25),
                                        threading.Event(), lambda _s: None,
                                        rng=random.Random(2), send=capture(sent))
    assert stats.frames == 25
    assert sum(len(batch) for _, batch in sent) == 25
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = flood.run_discover_flooding(DiscoverFloodConfig(iface="eth9", rate=100, count=5, dry_run=True),
                                        threading.Event(), lambda _s: None,
                                        rng=random.Random(3), send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("rate", [0, -1, 5001])
def test_rate_must_be_within_limits(rate):
    with pytest.raises(ValueError, match="Rate"):
        DiscoverFloodConfig(iface="eth9", rate=rate)
