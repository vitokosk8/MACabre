import ipaddress
import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

from macabre.attacks import slaac_prefix_spoofing as sps
from macabre.attacks.slaac_prefix_spoofing import SlaacPrefixSpoofingConfig

ATTACKER = "02:00:00:00:10:03"
PREFIX = "2001:db8:bad:1::/64"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, prefix=PREFIX, frames=2)
    values.update(overrides)
    return SlaacPrefixSpoofingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_advertisement_has_router_lifetime_zero():
    frame = sps.build_advertisement(config())
    assert frame.getlayer(ICMPv6ND_RA).routerlifetime == 0


def test_prefix_option_is_autonomous_and_carries_the_fraudulent_prefix():
    option = sps.build_advertisement(config()).getlayer(ICMPv6NDOptPrefixInfo)
    assert option.A == 1 and option.L == 1
    assert option.prefixlen == 64
    assert option.prefix == "2001:db8:bad:1::"


def test_lifetimes_are_applied():
    option = sps.build_advertisement(config(valid_lifetime=600, preferred_lifetime=300)).getlayer(ICMPv6NDOptPrefixInfo)
    assert option.validlifetime == 600 and option.preferredlifetime == 300


def test_advertisement_uses_hop_limit_255_all_nodes_and_link_local_source():
    frame = sps.build_advertisement(config())
    ip = frame.getlayer("IPv6")
    assert ip.hlim == 255
    assert ip.dst == "ff02::1"
    assert ip.src == "fe80::ff:fe00:1003"
    assert frame.dst == "33:33:00:00:00:01" and frame.src == ATTACKER


def test_run_sends_the_configured_number_of_advertisements():
    sent = []
    stats = sps.run_slaac_prefix_spoofing(config(frames=4), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = sps.run_slaac_prefix_spoofing(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = sps.run_slaac_prefix_spoofing(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("prefix", ["2001:db8::/48", "2001:db8::/128", "10.0.0.0/24", "not-a-prefix"])
def test_prefix_must_be_a_slaac_64(prefix):
    with pytest.raises(ValueError):
        config(prefix=prefix)


def test_preferred_lifetime_cannot_exceed_valid_lifetime():
    with pytest.raises(ValueError, match="Preferred"):
        config(valid_lifetime=100, preferred_lifetime=101)


def test_valid_lifetime_must_be_positive():
    with pytest.raises(ValueError, match="Valid lifetime"):
        config(valid_lifetime=0)


@pytest.mark.parametrize("frames", [0, 101])
def test_frame_count_out_of_range_is_refused(frames):
    with pytest.raises(ValueError, match="Frames"):
        config(frames=frames)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
