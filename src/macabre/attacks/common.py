"""Helpers shared by the attack modules."""

from __future__ import annotations

import random
import re
import subprocess
import sys
from collections.abc import Callable

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

Runner = Callable[[list[str]], str]

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_LINK_RE = re.compile(r"link/ether ([0-9a-f:]{17})")
# macOS ifconfig prints each octet without its leading zero, e.g. "ether 0:e0:4c:f8:d1:a8".
_IFCONFIG_RE = re.compile(r"\bether ((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b")


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


def run_command(argv: list[str]) -> str:
    """Run a system command and return its standard output; raises on failure."""
    result = subprocess.run(argv, check=True, capture_output=True, text=True)
    return result.stdout


def read_interface_mac(iface: str, run: Runner | None = None) -> str:
    """Current hardware address of `iface` (Scapy caches it).

    Linux reads it with `ip`; macOS reads it with `ifconfig`.
    """
    runner = run or run_command
    if sys.platform == "darwin":
        output = runner(["ifconfig", iface])
        match = _IFCONFIG_RE.search(output)
        if not match:
            raise RuntimeError(f"Cannot read the MAC address of {iface}.")
        return ":".join(f"{int(octet, 16):02x}" for octet in match.group(1).split(":"))
    output = runner(["ip", "-o", "link", "show", "dev", iface])
    match = _LINK_RE.search(output)
    if not match:
        raise RuntimeError(f"Cannot read the MAC address of {iface}.")
    return match.group(1)
