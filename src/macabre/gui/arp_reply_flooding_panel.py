"""Panel for the ARP reply flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.arp_reply_flooding import (
    ArpReplyFloodingConfig,
    ArpReplyFloodingStats,
    run_arp_reply_flooding,
)
from macabre.gui.base_panel import AttackPanel


class ArpReplyFloodingPanel(AttackPanel):
    title = "ARP reply flooding"
    description = (
        "Broadcasts a stream of unsolicited ARP replies from random senders in the subnet you "
        "choose, addressed to a victim IP or to random hosts. Every host parses each broadcast, "
        "and the stream can churn their neighbor caches. Use only with authorization, with a "
        "limited count: it generates load on the whole segment."
    )
    default_interval = 0.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.subnet_edit = QLineEdit()
        self.subnet_edit.setPlaceholderText("Subnet, for example 192.168.1.0/24")
        self.victim_edit = QLineEdit()
        self.victim_edit.setPlaceholderText("Victim IP (optional; empty = random hosts)")
        form.addRow("Subnet:", self.subnet_edit)
        form.addRow("Victim IP:", self.victim_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.subnet_edit.setEnabled(enabled)
        self.victim_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ArpReplyFloodingConfig:
        return ArpReplyFloodingConfig(
            iface=iface,
            subnet=self.subnet_edit.text(),
            victim_ip=self.victim_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ArpReplyFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ArpReplyFloodingStats], None],
    ) -> ArpReplyFloodingStats:
        return run_arp_reply_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: ArpReplyFloodingStats) -> str:
        return f"Replies sent: {stats.frames}"
