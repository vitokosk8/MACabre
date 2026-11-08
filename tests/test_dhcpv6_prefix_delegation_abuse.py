import random
import threading

import pytest
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptIA_PD,
    DHCP6OptIAPrefix,
    DHCP6OptServerId,
    DUID_LLT,
)

from macabre.attacks import dhcpv6_prefix_delegation_abuse as pd
from macabre.attacks.dhcpv6_prefix_delegation_abuse import (
    Dhcpv6PrefixDelegationAbuseConfig,
    build_request,
    build_solicit,
    parse_advertise,
    reply_confirms_prefix,
)

ATTACKER = "02:00:00:00:10:03"
SERVER = "02:00:00:00:10:01"


def config(**overrides):
    values = dict(iface="eth9", drain=0)
    values.update(overrides)
    return Dhcpv6PrefixDelegationAbuseConfig(**values)


def test_solicit_asks_for_a_prefix_with_the_length_hint():
    frame = build_solicit(ATTACKER, trid=0x123456, iaid=7, plen=56)
    solicit = frame.getlayer(DHCP6_Solicit)
    assert solicit is not None and solicit.trid == 0x123456
    ia = frame.getlayer(DHCP6OptIA_PD)
    assert ia is not None and ia.iaid == 7
    assert ia.iapdopt[0].plen == 56


def test_solicit_is_sent_to_the_servers_group_from_the_mac_link_local():
    frame = build_solicit(ATTACKER, trid=1, iaid=1, plen=56)
    assert frame.getlayer("IPv6").dst == "ff02::1:2"
    assert frame.getlayer("IPv6").src == "fe80::ff:fe00:1003"
    assert frame.getlayer(DHCP6OptClientId).duid.lladdr == ATTACKER


def test_request_carries_the_offered_prefix_and_server_id():
    frame = build_request(ATTACKER, trid=5, iaid=9, server_mac=SERVER, prefix="2001:db8:f000:100::", plen=56)
    assert frame.getlayer(DHCP6_Request).trid == 5
    assert frame.getlayer(DHCP6OptServerId).duid.lladdr == SERVER
    prefix = frame.getlayer(DHCP6OptIA_PD).iapdopt[0]
    assert prefix.prefix == "2001:db8:f000:100::"
    assert prefix.plen == 56


def advertise(mac, server, trid, iaid, prefix, plen):
    return (
        DHCP6_Advertise(trid=trid)
        / DHCP6OptServerId(duid=DUID_LLT(lladdr=server, timeval=0))
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=mac, timeval=0))
        / DHCP6OptIA_PD(iaid=iaid, T1=0, T2=0, iapdopt=[DHCP6OptIAPrefix(plen=plen, prefix=prefix)])
    )


def test_parse_advertise_reads_the_offered_prefix():
    offer = parse_advertise(advertise(ATTACKER, SERVER, 42, 7, "2001:db8:f000:100::", 56))
    assert offer is not None
    assert (offer.trid, offer.client_mac, offer.server_mac, offer.iaid) == (42, ATTACKER, SERVER, 7)
    assert (offer.prefix, offer.plen) == ("2001:db8:f000:100::", 56)


def test_parse_advertise_ignores_offers_without_a_prefix():
    no_prefix = (
        DHCP6_Advertise(trid=1)
        / DHCP6OptServerId(duid=DUID_LLT(lladdr=SERVER, timeval=0))
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=ATTACKER, timeval=0))
        / DHCP6OptIA_PD(iaid=1, T1=0, T2=0)
    )
    assert parse_advertise(no_prefix) is None


def test_reply_confirms_a_prefix():
    reply = (
        DHCP6_Reply(trid=42)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=ATTACKER, timeval=0))
        / DHCP6OptIA_PD(iaid=7, T1=0, T2=0, iapdopt=[DHCP6OptIAPrefix(plen=56, prefix="2001:db8:f000:100::")])
    )
    assert reply_confirms_prefix(reply) == (42, "2001:db8:f000:100::")


@pytest.mark.parametrize("plen", [47, 65])
def test_prefix_length_must_be_sensible(plen):
    with pytest.raises(ValueError, match="Prefix length"):
        config(plen=plen)


def test_negative_count_is_refused():
    with pytest.raises(ValueError, match="Count"):
        config(count=-1)


def test_dry_run_sends_nothing():
    sent = []
    stats = pd.run_dhcpv6_prefix_delegation_abuse(
        config(dry_run=True, count=3), threading.Event(), lambda _s: None,
        send=lambda frame, **_kw: sent.append(frame),
    )
    assert sent == []
    assert stats.status.startswith("Dry run")


class Harness:
    """Stands in for the network: each SOLICIT is answered with an ADVERTISE, each REQUEST with a REPLY."""

    def __init__(self):
        self.prn = None
        self.sent = []

    def sniffer_factory(self, iface, store, prn):
        self.prn = prn

        class _Sniffer:
            def start(self_inner):
                pass

            def stop(self_inner):
                pass

        return _Sniffer()

    def send(self, frame, iface, verbose):
        self.sent.append(frame)
        if frame.haslayer(DHCP6_Solicit):
            trid = frame[DHCP6_Solicit].trid
            mac = frame[DHCP6OptClientId].duid.lladdr
            ia = frame[DHCP6OptIA_PD]
            self.prn(advertise(mac, SERVER, trid, ia.iaid, "2001:db8:f000:100::", 56))
        elif frame.haslayer(DHCP6_Request):
            trid = frame[DHCP6_Request].trid
            mac = frame[DHCP6OptClientId].duid.lladdr
            ia = frame[DHCP6OptIA_PD]
            reply = (
                DHCP6_Reply(trid=trid)
                / DHCP6OptClientId(duid=DUID_LLT(lladdr=mac, timeval=0))
                / DHCP6OptIA_PD(iaid=ia.iaid, T1=0, T2=0,
                                iapdopt=[DHCP6OptIAPrefix(plen=56, prefix=ia.iapdopt[0].prefix)])
            )
            self.prn(reply)


def test_each_confirmed_prefix_counts_as_a_binding():
    harness = Harness()
    stats = pd.run_dhcpv6_prefix_delegation_abuse(
        config(count=5, interval=0), threading.Event(), lambda _s: None,
        rng=random.Random(1),
        send=harness.send, sniffer_factory=harness.sniffer_factory,
    )
    assert stats.solicits == 5
    assert stats.advertises == 5
    assert stats.requests == 5
    assert stats.bindings == 5


def test_no_binding_without_a_reply():
    harness = Harness()

    def silent_send(frame, iface, verbose):
        harness.sent.append(frame)
        if frame.haslayer(DHCP6_Solicit):
            trid = frame[DHCP6_Solicit].trid
            mac = frame[DHCP6OptClientId].duid.lladdr
            harness.prn(advertise(mac, SERVER, trid, frame[DHCP6OptIA_PD].iaid, "2001:db8:f000:100::", 56))

    stats = pd.run_dhcpv6_prefix_delegation_abuse(
        config(count=3, interval=0), threading.Event(), lambda _s: None,
        rng=random.Random(2),
        send=silent_send, sniffer_factory=harness.sniffer_factory,
    )
    assert stats.requests == 3
    assert stats.bindings == 0
