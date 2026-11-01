import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import arp_gateway_impersonation as gateway
from macabre.attacks.arp_gateway_impersonation import GatewayImpersonationConfig

ATTACKER = "02:00:00:00:00:30"
GATEWAY = "10.97.0.1"
VICTIMS = "10.97.0.10, 10.97.0.11"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


class FakeHost:
    """Records commands and answers the reads the attack makes."""

    def __init__(self, forwarding="0"):
        self.forwarding = forwarding
        self.commands = []

    def __call__(self, argv):
        self.commands.append(argv)
        if argv[:4] == ["ip", "-o", "link", "show"]:
            return LINK_OUTPUT
        if argv == ["sysctl", "-n", gateway.FORWARDING_KEY]:
            return self.forwarding + "\n"
        return ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_each_victim_gets_a_reply_claiming_the_gateway():
    sent = []
    config = GatewayImpersonationConfig(iface="eth9", gateway_ip=GATEWAY, victims=VICTIMS, count=2, interval=0)
    stats = gateway.run_gateway_impersonation(config, threading.Event(), lambda _s: None,
                                              run=FakeHost(), send=capture(sent))
    assert stats.rounds == 2 and stats.frames == 4 and stats.victims == 2
    assert {frame[ARP].pdst for _, frame in sent} == {"10.97.0.10", "10.97.0.11"}
    for _, frame in sent:
        assert frame[ARP].op == 2
        assert frame[ARP].psrc == GATEWAY
        assert frame[ARP].hwsrc == ATTACKER
        assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"


def test_forwarding_is_enabled_during_the_attack_and_restored_after():
    host = FakeHost(forwarding="0")
    config = GatewayImpersonationConfig(iface="eth9", gateway_ip=GATEWAY, victims=VICTIMS, count=1, interval=0)
    stats = gateway.run_gateway_impersonation(config, threading.Event(), lambda _s: None,
                                              run=host, send=capture([]))
    enable = host.commands.index(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    restore = host.commands.index(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    assert enable < restore
    assert host.commands[-1] == ["sysctl", "-w", "net.ipv4.ip_forward=0"]
    assert stats.forwarding_active is False
    assert stats.status == "Restored net.ipv4.ip_forward to 0."


def test_forwarding_is_restored_even_if_sending_fails():
    host = FakeHost(forwarding="0")

    def broken_send(frame, iface, verbose):
        raise OSError("network down")

    config = GatewayImpersonationConfig(iface="eth9", gateway_ip=GATEWAY, victims=VICTIMS, count=1, interval=0)
    with pytest.raises(OSError):
        gateway.run_gateway_impersonation(config, threading.Event(), lambda _s: None,
                                          run=host, send=broken_send)
    assert host.commands[-1] == ["sysctl", "-w", "net.ipv4.ip_forward=0"]


def test_forwarding_can_be_left_alone():
    host = FakeHost()
    config = GatewayImpersonationConfig(iface="eth9", gateway_ip=GATEWAY, victims=VICTIMS,
                                        count=1, interval=0, enable_forwarding=False)
    gateway.run_gateway_impersonation(config, threading.Event(), lambda _s: None,
                                      run=host, send=capture([]))
    assert not any(argv[:2] == ["sysctl", "-n"] or argv[:2] == ["sysctl", "-w"] for argv in host.commands)


def test_dry_run_changes_nothing():
    host = FakeHost()
    sent = []
    config = GatewayImpersonationConfig(iface="eth9", gateway_ip=GATEWAY, victims=VICTIMS, dry_run=True)
    stats = gateway.run_gateway_impersonation(config, threading.Event(), lambda _s: None,
                                              run=host, send=capture(sent))
    assert host.commands == [] and sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("kwargs, message", [
    ({"gateway_ip": "10.97.0.999", "victims": VICTIMS}, "Invalid gateway IP"),
    ({"gateway_ip": "", "victims": VICTIMS}, "gateway IP is required"),
    ({"gateway_ip": GATEWAY, "victims": ""}, "At least one victim"),
    ({"gateway_ip": GATEWAY, "victims": "10.97.0.10, nope"}, "Invalid victim IP"),
    ({"gateway_ip": GATEWAY, "victims": f"{GATEWAY}, 10.97.0.10"}, "cannot also be a victim"),
])
def test_invalid_parameters_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        GatewayImpersonationConfig(iface="eth9", **kwargs)


def test_duplicate_victims_are_sent_once():
    sent = []
    config = GatewayImpersonationConfig(iface="eth9", gateway_ip=GATEWAY,
                                        victims="10.97.0.10 10.97.0.10,10.97.0.10", count=1, interval=0)
    stats = gateway.run_gateway_impersonation(config, threading.Event(), lambda _s: None,
                                              run=FakeHost(), send=capture(sent))
    assert stats.frames == 1 and stats.victims == 1
