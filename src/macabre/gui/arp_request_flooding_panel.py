"""Panel for the ARP request flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.arp_request_flooding import (
    ArpRequestFloodingConfig,
    ArpRequestFloodingStats,
    run_arp_request_flooding,
)
from macabre.gui.base_panel import AttackPanel


class ArpRequestFloodingPanel(AttackPanel):
    title = "ARP request flooding"
    description = (
        "Broadcasts a stream of ARP requests from random senders in the subnet you choose. "
        "Every host processes each broadcast, and a host that owns the target IP fills its "
        "neighbor table. Use only with authorization, with a limited count: it generates load "
        "on the whole segment."
    )
    default_interval = 0.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.subnet_edit = QLineEdit()
        self.subnet_edit.setPlaceholderText("Subnet, for example 192.168.1.0/24")
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Fixed target IP (optional; empty = random hosts)")
        form.addRow("Subnet:", self.subnet_edit)
        form.addRow("Target IP:", self.target_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.subnet_edit.setEnabled(enabled)
        self.target_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ArpRequestFloodingConfig:
        return ArpRequestFloodingConfig(
            iface=iface,
            subnet=self.subnet_edit.text(),
            target_ip=self.target_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ArpRequestFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ArpRequestFloodingStats], None],
    ) -> ArpRequestFloodingStats:
        return run_arp_request_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: ArpRequestFloodingStats) -> str:
        return f"Requests sent: {stats.frames}"
