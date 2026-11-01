"""Panel for the ARP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.arp_spoofing import (
    ArpSpoofingConfig,
    ArpSpoofingStats,
    run_arp_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class ArpSpoofingPanel(AttackPanel):
    title = "ARP spoofing"
    description = (
        "Sends forged ARP replies that bind the IP address you choose to this interface's MAC, "
        "so the victim sends that IP's traffic here. Use only with authorization: it changes "
        "the victim's ARP cache on the real network."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.spoofed_edit = QLineEdit()
        self.spoofed_edit.setPlaceholderText("IP to impersonate, for example the gateway: 192.168.1.1")
        self.victim_ip_edit = QLineEdit()
        self.victim_ip_edit.setPlaceholderText("Victim IP: 192.168.1.20")
        self.victim_mac_edit = QLineEdit()
        self.victim_mac_edit.setPlaceholderText("Victim MAC (optional; empty = broadcast)")
        form.addRow("Spoofed IP:", self.spoofed_edit)
        form.addRow("Victim IP:", self.victim_ip_edit)
        form.addRow("Victim MAC:", self.victim_mac_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.spoofed_edit.setEnabled(enabled)
        self.victim_ip_edit.setEnabled(enabled)
        self.victim_mac_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ArpSpoofingConfig:
        return ArpSpoofingConfig(
            iface=iface,
            spoofed_ip=self.spoofed_edit.text(),
            victim_ip=self.victim_ip_edit.text(),
            victim_mac=self.victim_mac_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ArpSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ArpSpoofingStats], None],
    ) -> ArpSpoofingStats:
        return run_arp_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: ArpSpoofingStats) -> str:
        return f"Replies sent: {stats.frames}"
