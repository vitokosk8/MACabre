import ipaddress
import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr

from macabre.attacks import ndp_neighbor_cache_exhaustion as nce
from macabre.attacks.ndp_neighbor_cache_exhaustion import NdpNeighborCacheExhaustionConfig

ATTACKER = "02:00:00:00:10:03"
TARGET = "2001:db8:c0::1"
PREFIX = "2001:db8:c0::/64"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, target=TARGET, prefix=PREFIX, count=5)
    values.update(overrides)
    return NdpNeighborCacheExhaustionConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_each_solicitation_comes_from_a_new_source_inside_the_prefix():
    frames = nce.build_solicitations(config(count=20))
    sources = [f.getlayer("IPv6").src for f in frames]
    assert len(set(sources)) == 20
    network = ipaddress.IPv6Network(PREFIX)
    assert all(ipaddress.IPv6Address(s) in network for s in sources)


def test_solicitation_asks_for_the_target_with_the_operators_mac_as_source_option():
    for frame in nce.build_solicitations(config()):
        assert str(frame.getlayer(ICMPv6ND_NS).tgt) == TARGET
        assert frame.getlayer(ICMPv6NDOptSrcLLAddr).lladdr == ATTACKER


def test_solicitation_goes_to_the_solicited_node_address_with_hop_limit_255():
    frame = nce.build_solicitation(config(), 0)
    ip = frame.getlayer("IPv6")
    assert ip.hlim == 255
    assert ip.dst == "ff02::1:ff00:1"
    assert frame.dst == "33:33:ff:00:00:01"
    assert frame.src == ATTACKER


def test_solicited_node_helpers_use_the_last_24_bits_of_the_target():
    target = ipaddress.IPv6Address("2001:db8:c0:0:aa:bbcc:dd:ee12")
    assert nce.solicited_node(target) == "ff02::1:ffdd:ee12"
    assert nce.solicited_node_mac(target) == "33:33:ff:dd:ee:12"


def test_run_sends_one_solicitation_per_source():
    sent = []
    stats = nce.run_ndp_neighbor_cache_exhaustion(config(count=7), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.frames == 7 and len(sent) == 7
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = nce.run_ndp_neighbor_cache_exhaustion(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = nce.run_ndp_neighbor_cache_exhaustion(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("prefix", ["2001:db8::/48", "2001:db8::/128", "10.0.0.0/24", "not-a-prefix"])
def test_prefix_must_be_a_64(prefix):
    with pytest.raises(ValueError):
        config(prefix=prefix, target="2001:db8::1")


def test_target_must_be_inside_the_prefix():
    with pytest.raises(ValueError, match="inside the source prefix"):
        config(target="2001:db8:ffff::1")


@pytest.mark.parametrize("target", ["ff02::1", "::", "not-an-address"])
def test_target_must_be_a_unicast_address(target):
    with pytest.raises(ValueError):
        config(target=target)


def test_target_is_required():
    with pytest.raises(ValueError, match="Target"):
        config(target="")


@pytest.mark.parametrize("count", [0, 501])
def test_count_out_of_range_is_refused(count):
    with pytest.raises(ValueError, match="Solicitations"):
        config(count=count)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
