import threading

import pytest
from scapy.all import Ether, IPv6, UDP
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptDNSDomains,
    DHCP6OptDNSServers,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptPref,
    DHCP6OptServerId,
    DUID_LLT,
)

from macabre.attacks.rogue_dhcpv6_server import (
    RogueDhcpv6Config,
    domain_names,
    respond,
    run_rogue_dhcpv6,
)

SERVER_MAC = "02:00:00:00:00:01"
CLIENT_MAC = "02:00:00:00:00:60"


def config(**overrides):
    values = dict(iface="eth0", server_mac=SERVER_MAC, server_ll="fe80::1", offer_ip6="2001:db8::150")
    values.update(overrides)
    return RogueDhcpv6Config(**values)


def solicit(trid=5):
    return (Ether(src=CLIENT_MAC) / IPv6(src="fe80::60", dst="ff02::1:2") / UDP(sport=546, dport=547)
            / DHCP6_Solicit(trid=trid) / DHCP6OptClientId(duid=DUID_LLT(lladdr=CLIENT_MAC, timeval=1))
            / DHCP6OptIA_NA(iaid=1))


def request(server_mac=SERVER_MAC, trid=6):
    return (Ether(src=CLIENT_MAC) / IPv6(src="fe80::60", dst="fe80::1") / UDP(sport=546, dport=547)
            / DHCP6_Request(trid=trid) / DHCP6OptClientId(duid=DUID_LLT(lladdr=CLIENT_MAC, timeval=1))
            / DHCP6OptServerId(duid=DUID_LLT(lladdr=server_mac, timeval=0)) / DHCP6OptIA_NA(iaid=1))


def test_solicit_gets_an_advertise_with_the_chosen_values():
    kind, frame = respond(config(dns="2001:db8::53", domains="lab.example", preference=200), solicit(trid=9))
    assert kind == "advertise"
    assert frame[DHCP6_Advertise].trid == 9
    assert frame[DHCP6OptDNSServers].dnsservers == ["2001:db8::53"]
    assert frame[DHCP6OptDNSDomains].dnsdomains == ["lab.example."]
    assert frame[DHCP6OptPref].prefval == 200
    assert frame[DHCP6OptIA_NA].ianaopts[0].addr == "2001:db8::150"
    assert frame[DHCP6OptServerId].duid.lladdr == SERVER_MAC
    assert frame[DHCP6OptClientId].duid.lladdr == CLIENT_MAC
    assert frame[Ether].dst == CLIENT_MAC
    assert frame[IPv6].dst == "fe80::60"
    assert frame[IPv6].src == "fe80::1"


def test_dns_defaults_to_this_server_when_not_given():
    _, frame = respond(config(), solicit())
    assert frame[DHCP6OptDNSServers].dnsservers == ["fe80::1"]


def test_request_for_this_server_gets_a_reply():
    kind, frame = respond(config(dns="2001:db8::53"), request())
    assert kind == "reply"
    assert frame[DHCP6_Reply].trid == 6
    assert frame[DHCP6OptIA_NA].ianaopts[0].addr == "2001:db8::150"


def test_request_for_another_server_is_ignored():
    assert respond(config(), request(server_mac="02:00:00:00:00:99")) is None


def test_own_frames_are_ignored():
    own = solicit()
    own[Ether].src = SERVER_MAC
    assert respond(config(), own) is None


@pytest.mark.parametrize("overrides", [
    dict(server_ll="2001:db8::1"),
    dict(offer_ip6="not-an-ip"),
    dict(dns="2001:db8::53, nope"),
    dict(domains="bad..domain"),
    dict(preference=256),
    dict(server_mac="zz"),
])
def test_bad_inputs_are_refused(overrides):
    with pytest.raises(ValueError):
        config(**overrides)


def test_domain_names_end_with_a_dot():
    assert domain_names("lab.example, corp.example") == ["lab.example.", "corp.example."]


def test_run_dry_run_sends_nothing():
    sent = []
    stats = run_rogue_dhcpv6(
        config(dry_run=True), threading.Event(), lambda s: None,
        send=lambda *a, **kw: sent.append(a), sniffer_factory=lambda **kw: None,
    )
    assert sent == []
    assert "Nothing sent" in stats.status
