"""L2 loop amplification: send a few broadcast or multicast frames into a loop and count the copies.

A bridged network that contains a loop has no time-to-live on Ethernet frames. A broadcast
or multicast frame that enters the loop is flooded again by every bridge it reaches, and it
comes back to the bridge that flooded it. Without loop protection the copies multiply, and
one frame can cost the network far more than the frame itself.

The factor this module lets you measure is copies per injected frame: how many copies of the
injected frames come back into the switch from the loop during a fixed window. Spanning Tree
and other loop protection should keep that factor near zero.

Every frame here has a random unicast source MAC, chosen per frame, and an experimental
EtherType, so no host parses the payload as IP or ARP. The source MAC must not be the MAC
of the sending host: a host's own MAC learned on a port of the loop stopped the copies in
the lab, so the module never uses it.

Intended only for networks you own or are explicitly authorized to test.

Run as a module inside the sender's network namespace:
    ip netns exec host python -m macabre.attacks.l2_loop_amplification h0 --frames 1
"""

from __future__ import annotations

import argparse
import random
import re
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, random_mac

EXPERIMENTAL_ETHERTYPE = 0x88B5   # IEEE 802 local experimental EtherType
MAX_FRAMES = 1000
MAX_PAYLOAD = 1400
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def normalize_group_mac(value: str) -> str:
    """Return the destination in lowercase. It must be a broadcast or multicast address."""
    mac = value.strip().lower()
    if not mac:
        raise ValueError("Destination is required.")
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {value}")
    if not int(mac.split(":")[0], 16) & 0x01:
        raise ValueError("Destination must be broadcast or multicast (group bit set).")
    return mac


@dataclass(frozen=True)
class L2LoopAmplificationConfig:
    iface: str                          # sender interface, on a port of the switch
    destination: str = BROADCAST_MAC    # broadcast or multicast address of the frames
    frames: int = 1                     # frames to inject; the lab uses one
    interval: float = 0.5               # seconds between frames
    payload_size: int = 32              # payload bytes per frame
    seed: int | None = None             # seeds the random source MACs, for reproducible runs
    dry_run: bool = False

    def __post_init__(self) -> None:
        if not self.iface:
            raise ValueError("Interface is required.")
        normalize_group_mac(self.destination)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Give between 1 and {MAX_FRAMES} frames.")
        if self.interval <= 0:
            raise ValueError("Interval must be positive.")
        if not 1 <= self.payload_size <= MAX_PAYLOAD:
            raise ValueError(f"Payload must be between 1 and {MAX_PAYLOAD} bytes.")


@dataclass
class L2LoopAmplificationStats:
    frames: int = 0
    status: str = ""


def amplification_factor(copies: int, frames: int) -> float:
    """Copies that came back into the switch per injected frame."""
    if frames <= 0:
        raise ValueError("Frames must be positive.")
    if copies < 0:
        raise ValueError("Copies cannot be negative.")
    return copies / frames


def amplification_frame(source: str, destination: str, payload: bytes) -> Packet:
    """One frame: random unicast source, the given group destination, experimental EtherType."""
    return Ether(src=source, dst=destination, type=EXPERIMENTAL_ETHERTYPE) / Raw(payload)


def run_l2_loop_amplification(
    config: L2LoopAmplificationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[L2LoopAmplificationStats], None],
    send: Callable[..., Any] | None = None,
) -> L2LoopAmplificationStats:
    """Send `config.frames` frames, `config.interval` seconds apart, until done or `stop_event`."""
    if config.dry_run:
        stats = L2LoopAmplificationStats(
            status=(f"Dry run: would send {config.frames} frame(s) to {config.destination} "
                    f"with random source MACs. Nothing sent."),
        )
        on_progress(replace(stats))
        return stats

    send = send or sendp
    rng = random.Random(config.seed)
    payload = bytes(config.payload_size)
    destination = normalize_group_mac(config.destination)
    stats = L2LoopAmplificationStats()
    for index in range(config.frames):
        if stop_event.is_set():
            break
        send(amplification_frame(random_mac(rng), destination, payload), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if index < config.frames - 1:
            stop_event.wait(config.interval)
    stats.status = f"Sent {stats.frames} frame(s) to {destination} with random source MACs."
    on_progress(replace(stats))
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send broadcast or multicast frames into a loop.")
    parser.add_argument("iface")
    parser.add_argument("--dst", default=BROADCAST_MAC, help="broadcast or multicast destination")
    parser.add_argument("--frames", type=int, default=1)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--payload-size", type=int, default=32)
    args = parser.parse_args(argv)
    config = L2LoopAmplificationConfig(
        iface=args.iface, destination=args.dst, frames=args.frames,
        interval=args.interval, payload_size=args.payload_size,
    )
    stats = run_l2_loop_amplification(config, threading.Event(), lambda _s: None)
    print(stats.status, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
