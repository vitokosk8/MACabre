import random
import threading

import pytest

from macabre.attacks import cdp_flooding as flood
from macabre.attacks.cdp_flooding import CdpFloodingConfig
import struct



def tlvs_of(message):
    out, pos = [], 4
    while pos < len(message):
        kind, length = struct.unpack("!HH", message[pos:pos + 4])
        out.append((kind, message[pos + 4:pos + length]))
        pos += length
    return out


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_every_frame_is_from_a_random_local_mac_for_a_different_device():
    frames = flood.flood_frames(random.Random(1), 20)
    sources = {frame.src for frame in frames}
    assert len(sources) == 20
    assert all(int(src.split(":")[0], 16) & 0x02 for src in sources)
    device_ids = set()
    for frame in frames:
        values = dict(tlvs_of(bytes(frame.load)[8:]))
        device_ids.add(values[0x0001])
    assert len(device_ids) == 20


def test_run_sends_the_requested_total_in_batches():
    sent = []
    stats = flood.run_cdp_flooding(CdpFloodingConfig(iface="eth9", rate=100, count=25),
                                   threading.Event(), lambda _s: None, rng=random.Random(2),
                                   send=capture(sent))
    assert stats.frames == 25
    assert sum(len(frames) for _, frames in sent) == 25
    assert all(iface == "eth9" for iface, _ in sent)


def test_rate_sets_the_batch_size():
    sent = []
    flood.run_cdp_flooding(CdpFloodingConfig(iface="eth9", rate=50, count=10),
                           threading.Event(), lambda _s: None, rng=random.Random(3), send=capture(sent))
    assert len(sent[0][1]) == 5


@pytest.mark.parametrize("rate", [0, -1, 5001])
def test_rate_must_be_positive_and_capped(rate):
    with pytest.raises(ValueError, match="Rate"):
        CdpFloodingConfig(iface="eth9", rate=rate)


def test_dry_run_sends_nothing():
    sent = []
    stats = flood.run_cdp_flooding(CdpFloodingConfig(iface="eth9", rate=100, count=10, dry_run=True),
                                   threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")
