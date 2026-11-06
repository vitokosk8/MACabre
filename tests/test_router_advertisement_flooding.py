import ipaddress
import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

from macabre.attacks import router_advertisement_flooding as raf
from macabre.attacks.router_advertisement_flooding import RouterAdvertisementFloodingConfig

ATTACKER = "02:00:00:00:10:03"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, advertisements=5)
    values.update(overrides)
    return RouterAdvertisementFloodingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_each_advertisement_comes_from_a_different_router_address():
    frames = raf.build_advertisements(config(advertisements=10))
    sources = [f.getlayer("IPv6").src for f in frames]
    assert len(set(sources)) == 10
    assert sources[0] == "fe80::1" and sources[-1] == "fe80::a"


def test_each_advertisement_carries_a_different_slaac_prefix_inside_the_base():
    frames = raf.build_advertisements(config(advertisements=10))
    prefixes = [f.getlayer(ICMPv6NDOptPrefixInfo).prefix for f in frames]
    assert len(set(prefixes)) == 10
    base = ipaddress.IPv6Network(raf.DEFAULT_PREFIX_BASE)
    for prefix in prefixes:
        assert ipaddress.IPv6Address(prefix) in base
    assert all(f.getlayer(ICMPv6NDOptPrefixInfo).prefixlen == 64 for f in frames)


def test_advertisements_use_hop_limit_255_and_all_nodes():
    for frame in raf.build_advertisements(config()):
        ip = frame.getlayer("IPv6")
        assert ip.hlim == 255
        assert ip.dst == "ff02::1"
        assert frame.dst == "33:33:00:00:00:01"
        assert frame.src == ATTACKER
        assert frame.getlayer(ICMPv6ND_RA) is not None


def test_router_lifetime_is_applied_to_every_advertisement():
    frames = raf.build_advertisements(config(router_lifetime=600))
    assert all(f.getlayer(ICMPv6ND_RA).routerlifetime == 600 for f in frames)


def test_run_sends_one_advertisement_per_router():
    sent = []
    stats = raf.run_router_advertisement_flooding(config(advertisements=7), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.advertisements == 7 and len(sent) == 7
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = raf.run_router_advertisement_flooding(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = raf.run_router_advertisement_flooding(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.advertisements == 0


@pytest.mark.parametrize("advertisements", [0, 501])
def test_advertisement_count_out_of_range_is_refused(advertisements):
    with pytest.raises(ValueError, match="Advertisements"):
        config(advertisements=advertisements)


@pytest.mark.parametrize("prefix", ["2001:db8::/64", "2001:db8::/12", "10.0.0.0/8", "not-a-prefix"])
def test_prefix_base_must_be_an_ipv6_block_between_16_and_48(prefix):
    with pytest.raises(ValueError):
        config(prefix_base=prefix)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
