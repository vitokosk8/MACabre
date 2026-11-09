"""Panel for the Router Solicitation flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.router_solicitation_flooding import (
    MAX_FRAMES,
    RouterSolicitationFloodingConfig,
    RouterSolicitationFloodingStats,
    run_router_solicitation_flooding,
)
from macabre.gui.base_panel import AttackPanel


class RouterSolicitationFloodingPanel(AttackPanel):
    title = "Router Solicitation Flooding"
    description = (
        "Sends a stream of Router Solicitations to the all-routers group. Each one makes a router process "
        "the message and possibly reply, so the stream loads the routers and crowds out real traffic. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(500)
        self.frames_spin.setSuffix(" solicitation(s)")
        form.addRow("Solicitations:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RouterSolicitationFloodingConfig:
        del count, interval  # this attack sends a fixed number of solicitations at a fixed rate
        return RouterSolicitationFloodingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RouterSolicitationFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RouterSolicitationFloodingStats], None],
    ) -> RouterSolicitationFloodingStats:
        return run_router_solicitation_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: RouterSolicitationFloodingStats) -> str:
        return stats.status or f"Solicitations sent: {stats.frames}"
