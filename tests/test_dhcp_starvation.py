import random
import threading

from scapy.all import BOOTP, DHCP, UDP, IP, Ether

from macabre.attacks import dhcp_starvation as dhcp
from macabre.attacks.dhcp_starvation import DhcpStarvationConfig


def test_random_mac_is_unicast_locally_administered():
    rng = random.Random(1234)
    for _ in range(200):
        mac = dhcp.random_mac(rng)
        octets = [int(part, 16) for part in mac.split(":")]
        assert len(octets) == 6
        assert octets[0] & 0x01 == 0      # unicast
        assert octets[0] & 0x02 == 0x02   # administrada localmente


def test_build_discover_fields():
    mac = "02:11:22:33:44:55"
    frame = dhcp.build_discover(mac, xid=0xDEADBEEF)

    assert frame[Ether].src == mac
    assert frame[Ether].dst == dhcp.BROADCAST_MAC
    assert frame[IP].src == "0.0.0.0"
    assert frame[IP].dst == "255.255.255.255"
    assert frame[UDP].sport == 68
    assert frame[UDP].dport == 67
    assert frame[BOOTP].xid == 0xDEADBEEF
    assert frame[BOOTP].chaddr[:6] == bytes.fromhex("021122334455")
    assert frame[BOOTP].chaddr[6:] == b"\x00" * 10
    assert frame[DHCP].options[0] == ("message-type", "discover")


def test_dry_run_generates_exact_count_without_sending(monkeypatch):
    sent = []
    monkeypatch.setattr(dhcp, "sendp", lambda *a, **k: sent.append((a, k)))

    progress = []
    config = DhcpStarvationConfig(iface="lo", count=5, interval=0.0, dry_run=True)
    total = dhcp.run_starvation(
        config, threading.Event(), progress.append, rng=random.Random(1)
    )

    assert total == 5
    assert progress == [1, 2, 3, 4, 5]
    assert sent == []


def test_real_run_calls_sendp_with_interface(monkeypatch):
    sent = []
    monkeypatch.setattr(dhcp, "sendp", lambda frame, iface, verbose: sent.append(iface))

    config = DhcpStarvationConfig(iface="eth9", count=3, interval=0.0)
    dhcp.run_starvation(config, threading.Event(), lambda _n: None, rng=random.Random(2))

    assert sent == ["eth9", "eth9", "eth9"]


def test_stop_event_interrupts_continuous_run(monkeypatch):
    stop = threading.Event()
    progress = []

    def on_progress(n):
        progress.append(n)
        if n == 4:
            stop.set()

    config = DhcpStarvationConfig(iface="lo", count=0, interval=0.0, dry_run=True)
    total = dhcp.run_starvation(config, stop, on_progress, rng=random.Random(3))

    assert total == 4
