"""Panel for the ARP cache poisoning attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.arp_poisoning import (
    ArpPoisoningConfig,
    ArpPoisoningStats,
    run_arp_poisoning,
)
from macabre.gui.base_panel import AttackPanel


class ArpPoisoningPanel(AttackPanel):
    title = "ARP cache poisoning"
    description = (
        "Poisons the ARP caches of a victim and its gateway in both directions, and keeps them "
        "poisoned, so traffic between them passes through this interface. Use only with "
        "authorization: it changes two hosts' caches on the real network."
    )
    default_interval = 2.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.victim_ip_edit = QLineEdit()
        self.victim_ip_edit.setPlaceholderText("Victim IP: 192.168.1.20")
        self.victim_mac_edit = QLineEdit()
        self.victim_mac_edit.setPlaceholderText("Victim MAC (optional)")
        self.gateway_ip_edit = QLineEdit()
        self.gateway_ip_edit.setPlaceholderText("Gateway IP: 192.168.1.1")
        self.gateway_mac_edit = QLineEdit()
        self.gateway_mac_edit.setPlaceholderText("Gateway MAC (optional)")
        form.addRow("Victim IP:", self.victim_ip_edit)
        form.addRow("Victim MAC:", self.victim_mac_edit)
        form.addRow("Gateway IP:", self.gateway_ip_edit)
        form.addRow("Gateway MAC:", self.gateway_mac_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.victim_ip_edit, self.victim_mac_edit, self.gateway_ip_edit, self.gateway_mac_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ArpPoisoningConfig:
        return ArpPoisoningConfig(
            iface=iface,
            victim_ip=self.victim_ip_edit.text(),
            gateway_ip=self.gateway_ip_edit.text(),
            victim_mac=self.victim_mac_edit.text(),
            gateway_mac=self.gateway_mac_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ArpPoisoningConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ArpPoisoningStats], None],
    ) -> ArpPoisoningStats:
        return run_arp_poisoning(config, stop_event, on_progress)

    def _format_status(self, stats: ArpPoisoningStats) -> str:
        return f"Rounds: {stats.rounds}   Replies: {stats.frames}"
