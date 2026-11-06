import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptMTU

from macabre.attacks import slaac_configuration_abuse as sca
from macabre.attacks.slaac_configuration_abuse import SlaacConfigurationAbuseConfig

ATTACKER = "02:00:00:00:10:03"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, frames=2)
    values.update(overrides)
    return SlaacConfigurationAbuseConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_advertisement_carries_the_chosen_hop_limit_and_router_lifetime():
    ra = sca.build_advertisement(config(hop_limit=32, router_lifetime=600)).getlayer(ICMPv6ND_RA)
    assert ra.chlim == 32
    assert ra.routerlifetime == 600


def test_advertisement_carries_the_chosen_mtu():
    option = sca.build_advertisement(config(mtu=1400)).getlayer(ICMPv6NDOptMTU)
    assert option.mtu == 1400


def test_advertisement_uses_hop_limit_255_all_nodes_and_link_local_source():
    frame = sca.build_advertisement(config())
    ip = frame.getlayer("IPv6")
    assert ip.hlim == 255
    assert ip.dst == "ff02::1"
    assert ip.src == "fe80::ff:fe00:1003"
    assert frame.dst == "33:33:00:00:00:01" and frame.src == ATTACKER


def test_run_sends_the_configured_number_of_advertisements():
    sent = []
    stats = sca.run_slaac_configuration_abuse(config(frames=4), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = sca.run_slaac_configuration_abuse(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = sca.run_slaac_configuration_abuse(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("mtu", [1279, 65536])
def test_mtu_out_of_range_is_refused(mtu):
    with pytest.raises(ValueError, match="MTU"):
        config(mtu=mtu)


@pytest.mark.parametrize("hop_limit", [0, 256])
def test_hop_limit_out_of_range_is_refused(hop_limit):
    with pytest.raises(ValueError, match="Hop limit"):
        config(hop_limit=hop_limit)


def test_router_lifetime_out_of_range_is_refused():
    with pytest.raises(ValueError, match="Router lifetime"):
        config(router_lifetime=0)


@pytest.mark.parametrize("frames", [0, 101])
def test_frame_count_out_of_range_is_refused(frames):
    with pytest.raises(ValueError, match="Frames"):
        config(frames=frames)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
