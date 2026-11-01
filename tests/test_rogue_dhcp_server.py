import threading

import pytest
from scapy.all import BOOTP, DHCP, Ether

from macabre.attacks import rogue_dhcp_server as rogue
from macabre.attacks.dhcp_starvation import build_discover, build_request
from macabre.attacks.rogue_dhcp_server import RogueDhcpConfig

ATTACKER = "02:00:00:00:00:30"
CLIENT = "02:00:00:00:00:50"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def config(**overrides):
    values = dict(iface="eth9", server_ip="10.99.0.250", offer_ip="10.99.0.200")
    values.update(overrides)
    return RogueDhcpConfig(**values)


def option_map(packet):
    return {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}


def test_offer_points_clients_at_this_server_for_gateway_and_dns():
    kind, offer = rogue.respond(config(), ATTACKER, build_discover(CLIENT, 1234))
    assert kind == "offer"
    assert offer[BOOTP].op == 2
    assert offer[BOOTP].xid == 1234
    assert offer[BOOTP].yiaddr == "10.99.0.200"
    assert offer[BOOTP].chaddr[:6] == bytes.fromhex("020000000050")
    opts = option_map(offer)
    assert opts["message-type"] == "offer"
    assert opts["server_id"] == "10.99.0.250"
    assert opts["router"] == "10.99.0.250"
    assert opts["name_server"] == "10.99.0.250"


def test_router_and_dns_can_be_set_separately():
    kind, offer = rogue.respond(config(router="10.99.0.1", dns="1.1.1.1"), ATTACKER,
                                build_discover(CLIENT, 1))
    opts = option_map(offer)
    assert opts["router"] == "10.99.0.1"
    assert opts["name_server"] == "1.1.1.1"


def test_request_for_this_server_is_acked_with_the_requested_address():
    request = build_request(CLIENT, 77, "10.99.0.200", "10.99.0.250")
    kind, ack = rogue.respond(config(), ATTACKER, request)
    assert kind == "ack"
    assert option_map(ack)["message-type"] == "ack"
    assert ack[BOOTP].yiaddr == "10.99.0.200"


def test_request_for_another_server_is_ignored():
    request = build_request(CLIENT, 77, "10.99.0.105", "10.99.0.1")
    assert rogue.respond(config(), ATTACKER, request) is None


def test_own_frames_and_non_dhcp_are_ignored():
    own = rogue.build_offer(config(), ATTACKER, build_discover(CLIENT, 1))
    assert rogue.respond(config(), ATTACKER, own) is None
    assert rogue.respond(config(), ATTACKER, Ether(src=CLIENT) / b"x") is None


@pytest.mark.parametrize("field,value", [("server_ip", "10.99.0"), ("offer_ip", "300.1.1.1"),
                                         ("router", "gateway"), ("subnet_mask", "x")])
def test_bad_addresses_are_rejected(field, value):
    with pytest.raises(ValueError):
        config(**{field: value})


def test_lease_time_must_be_positive():
    with pytest.raises(ValueError, match="Lease time"):
        config(lease_time=0)


def test_dry_run_sends_nothing_and_listens_to_nothing():
    calls, sent, sniffers = [], [], []
    stats = rogue.run_rogue_dhcp(
        config(dry_run=True), threading.Event(), lambda _s: None,
        run=lambda argv: calls.append(argv) or "",
        send=lambda *a, **k: sent.append(a),
        sniffer_factory=lambda **k: sniffers.append(k),
    )
    assert calls == [] and sent == [] and sniffers == []
    assert stats.status.startswith("Dry run")
