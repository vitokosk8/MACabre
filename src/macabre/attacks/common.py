"""Helpers shared by the attack modules."""

from __future__ import annotations

import random
import re

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def random_mac(rng: random.Random) -> str:
    """Random unicast, locally administered MAC address (LAA bit set)."""
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02
    return ":".join(f"{o:02x}" for o in octets)


def normalize_unicast_mac(value: str) -> str:
    """Return the MAC in lowercase, or raise ValueError if it is not a valid unicast MAC."""
    mac = value.strip().lower()
    if not mac:
        raise ValueError("Target MAC is required.")
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {value}")
    if int(mac.split(":")[0], 16) & 0x01:
        raise ValueError("Target MAC must be unicast (not multicast or broadcast).")
    return mac
