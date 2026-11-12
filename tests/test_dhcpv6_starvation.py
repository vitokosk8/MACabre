import random
import threading

import pytest
from scapy.all import Ether, IPv6
from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Request, DHCP6_Solicit, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6OptClientId, DHCP6OptServerId, DUID_LLT

from macabre.attacks.dhcpv6_starvation import (
    Dhcpv6StarvationConfig,
    build_request,
    build_solicit,
    link_local_from_mac,
    parse_advertise,
    run_dhcpv6_starvation,
)

CLIENT = "02:00:00:00:00:61"
SERVER = "02:00:00:00:00:01"


def test_link_local_address_is_derived_from_the_mac():
    assert link_local_from_mac("00:11:22:33:44:55") == "fe80::0211:22ff:fe33:4455"
    assert link_local_from_mac(CLIENT) == "fe80::0000:00ff:fe00:0061"


def test_solicit_goes_to_the_all_servers_multicast_with_the_client_identity():
    frame = build_solicit(CLIENT, trid=0x123456, iaid=42)
    assert frame[Ether].src == CLIENT
    assert frame[Ether].dst == "33:33:00:01:00:02"
    assert frame[IPv6].dst == "ff02::1:2"
    assert frame[DHCP6_Solicit].trid == 0x123456
    assert frame[DHCP6OptClientId].duid.lladdr == CLIENT
    assert frame[DHCP6OptIA_NA].iaid == 42


def test_request_names_the_server_and_the_offered_address():
    frame = build_request(CLIENT, trid=7, iaid=42, server_mac=SERVER, offered="2001:db8::150")
    assert frame[DHCP6_Request].trid == 7
    assert frame[DHCP6OptServerId].duid.lladdr == SERVER
    assert frame[DHCP6OptIA_NA].ianaopts[0].addr == "2001:db8::150"


def test_an_advertise_is_parsed_with_its_offer():
    adv = (Ether(src=SERVER) / IPv6(src="fe80::1", dst=link_local_from_mac(CLIENT))
           / DHCP6_Advertise(trid=7)
           / DHCP6OptServerId(duid=DUID_LLT(lladdr=SERVER, timeval=0))
           / DHCP6OptClientId(duid=DUID_LLT(lladdr=CLIENT, timeval=0))
           / DHCP6OptIA_NA(iaid=42, ianaopts=[DHCP6OptIAAddress(addr="2001:db8::150", preflft=60, validlft=120)]))
    parsed = parse_advertise(adv)
    assert (parsed.trid, parsed.client_mac, parsed.server_mac, parsed.offered, parsed.iaid) == (
        7, CLIENT, SERVER, "2001:db8::150", 42)


@pytest.mark.parametrize("kwargs", [dict(count=-1), dict(interval=-1)])
def test_bad_config_is_refused(kwargs):
    with pytest.raises(ValueError):
        Dhcpv6StarvationConfig(iface="eth0", **kwargs)


def test_run_sends_the_requested_number_of_solicits_with_distinct_identities():
    sent = []
    stats = run_dhcpv6_starvation(
        Dhcpv6StarvationConfig(iface="eth0", count=4, interval=0),
        threading.Event(), lambda s: None,
        rng=random.Random(3), send=lambda frame, **kw: sent.append(frame),
        sniffer_factory=lambda **kw: type("S", (), {"start": lambda self: None, "stop": lambda self: None})(),
    )
    assert stats.solicits == 4
    assert len({f[Ether].src for f in sent}) == 4


def test_dry_run_sends_nothing():
    sent = []
    stats = run_dhcpv6_starvation(
        Dhcpv6StarvationConfig(iface="eth0", dry_run=True), threading.Event(), lambda s: None,
        send=lambda *a, **kw: sent.append(a), sniffer_factory=lambda **kw: None,
    )
    assert sent == []
    assert "Nothing sent" in stats.status


def test_request_copies_the_server_duid_from_the_advertise():
    from scapy.layers.dhcp6 import DUID_LLT

    advertised = DUID_LLT(lladdr=SERVER, timeval=0x32889123)
    frame = build_request(CLIENT, trid=7, iaid=42, server_mac=SERVER,
                          offered="2001:db8::150", server_duid=advertised)
    assert frame[DHCP6OptServerId].duid.timeval == 0x32889123
    assert frame[DHCP6OptServerId].duid.lladdr == SERVER
