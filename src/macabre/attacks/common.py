"""Helpers shared by the attack modules."""

from __future__ import annotations

import random

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def random_mac(rng: random.Random) -> str:
    """Random unicast, locally administered MAC address (LAA bit set)."""
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02
    return ":".join(f"{o:02x}" for o in octets)
