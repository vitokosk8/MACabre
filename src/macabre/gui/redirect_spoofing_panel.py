"""Panel for the redirect spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.redirect_spoofing import (
    MAX_FRAMES,
    RedirectSpoofingConfig,
    RedirectSpoofingStats,
    run_redirect_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class RedirectSpoofingPanel(AttackPanel):
    title = "Redirect Spoofing"
    description = (
        "Sends ICMPv6 Redirect messages that claim your router is sending a destination through you. Hosts that "
        "accept them change their route for that destination. Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.router_edit = QLineEdit()
        self.router_edit.setPlaceholderText("Router link-local address to impersonate, e.g. fe80::ff:fe00:1001")
        form.addRow("Router address:", self.router_edit)

        self.victim_edit = QLineEdit()
        self.victim_edit.setPlaceholderText("Victim MAC, e.g. 02:00:00:00:10:02")
        form.addRow("Victim MAC:", self.victim_edit)

        self.destination_edit = QLineEdit("2001:db8:dead::1")
        self.destination_edit.setToolTip("The off-link destination whose route is redirected to you.")
        form.addRow("Destination:", self.destination_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" redirect(s)")
        form.addRow("Redirects:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.router_edit, self.victim_edit, self.destination_edit, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RedirectSpoofingConfig:
        del count, interval  # this attack sends a fixed number of redirects
        return RedirectSpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            router_address=self.router_edit.text().strip(),
            victim_mac=self.victim_edit.text().strip(),
            destination=self.destination_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RedirectSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RedirectSpoofingStats], None],
    ) -> RedirectSpoofingStats:
        return run_redirect_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: RedirectSpoofingStats) -> str:
        return stats.status or f"Redirects sent: {stats.frames}"
