import random
import threading

import pytest

from macabre.attacks import mndp_flooding as flood
from macabre.attacks.mndp_flooding import MndpFloodingConfig
from macabre.attacks.mndp_spoofing import TLV_IDENTITY, TLV_IPV4, parse_mndp


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_every_announcement_is_from_a_random_local_mac_for_a_different_router():
    frames = flood.flood_frames(random.Random(1), 20)
    sources = {frame.src for frame in frames}
    assert len(sources) == 20
    assert all(int(src.split(":")[0], 16) & 0x02 for src in sources)
    identities = {parse_mndp(bytes(frame.load))[TLV_IDENTITY] for frame in frames}
    assert len(identities) == 20


def test_each_announcement_carries_its_own_address_and_sequence():
    frames = flood.flood_frames(random.Random(2), 5, first_sequence=10)
    for n, frame in enumerate(frames):
        payload = bytes(frame.load)
        assert payload[2:4] == (10 + n).to_bytes(2, "little")
        assert parse_mndp(payload)[TLV_IPV4] == bytes(int(o) for o in frame["IP"].src.split("."))


def test_run_sends_the_requested_total_in_batches():
    sent = []
    stats = flood.run_mndp_flooding(MndpFloodingConfig(iface="eth9", rate=100, count=25),
                                    threading.Event(), lambda _s: None, rng=random.Random(3),
                                    send=capture(sent))
    assert stats.frames == 25
    assert sum(len(frames) for _, frames in sent) == 25


@pytest.mark.parametrize("rate", [0, -1, 5001])
def test_rate_must_be_positive_and_capped(rate):
    with pytest.raises(ValueError, match="Rate"):
        MndpFloodingConfig(iface="eth9", rate=rate)


def test_dry_run_sends_nothing():
    sent = []
    stats = flood.run_mndp_flooding(MndpFloodingConfig(iface="eth9", rate=100, count=10, dry_run=True),
                                    threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")
