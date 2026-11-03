import threading

import pytest

from macabre.attacks import static_mac_impersonation as sm
from macabre.attacks.static_mac_impersonation import StaticMacImpersonationConfig

REGISTERED = "02:00:00:00:00:50"


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_frames_carry_the_registered_source_and_a_broadcast_destination():
    frames = sm.impersonation_frames(REGISTERED, 5)
    assert all(frame.src == REGISTERED for frame in frames)
    assert all(frame.dst == "ff:ff:ff:ff:ff:ff" for frame in frames)
    assert all(frame.type == 0x88B5 for frame in frames)


def test_run_sends_the_requested_total_from_this_port():
    sent = []
    stats = sm.run_static_mac_impersonation(
        StaticMacImpersonationConfig(iface="att0", source_mac=REGISTERED, rate=50, count=12),
        threading.Event(), lambda _s: None, send=capture(sent),
    )
    assert stats.frames == 12
    assert sum(len(frames) for _, frames in sent) == 12
    assert all(iface == "att0" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = sm.run_static_mac_impersonation(
        StaticMacImpersonationConfig(iface="att0", source_mac=REGISTERED, count=5, dry_run=True),
        threading.Event(), lambda _s: None, send=capture(sent),
    )
    assert sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("mac", ["", "01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff", "not-a-mac"])
def test_source_must_be_a_valid_unicast_mac(mac):
    with pytest.raises(ValueError):
        StaticMacImpersonationConfig(iface="att0", source_mac=mac)


@pytest.mark.parametrize("rate", [0, -1, 101])
def test_rate_must_be_within_limits(rate):
    with pytest.raises(ValueError, match="Rate"):
        StaticMacImpersonationConfig(iface="att0", source_mac=REGISTERED, rate=rate)
