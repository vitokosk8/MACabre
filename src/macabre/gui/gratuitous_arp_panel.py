"""Panel for the gratuitous ARP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.gratuitous_arp_spoofing import (
    GratuitousArpConfig,
    GratuitousArpStats,
    run_gratuitous_arp,
)
from macabre.gui.base_panel import AttackPanel


class GratuitousArpPanel(AttackPanel):
    title = "Gratuitous ARP spoofing"
    description = (
        "Broadcasts announcements that bind the IP address you choose to this interface's MAC. "
        "Every host on the segment that caches that IP may update its entry. Use only with "
        "authorization: it affects all hosts on the segment."
    )
    default_interval = 2.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.spoofed_edit = QLineEdit()
        self.spoofed_edit.setPlaceholderText("IP to announce, for example the gateway: 192.168.1.1")
        form.addRow("Spoofed IP:", self.spoofed_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.spoofed_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> GratuitousArpConfig:
        return GratuitousArpConfig(
            iface=iface,
            spoofed_ip=self.spoofed_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: GratuitousArpConfig,
        stop_event: threading.Event,
        on_progress: Callable[[GratuitousArpStats], None],
    ) -> GratuitousArpStats:
        return run_gratuitous_arp(config, stop_event, on_progress)

    def _format_status(self, stats: GratuitousArpStats) -> str:
        return f"Announcements sent: {stats.frames}"
