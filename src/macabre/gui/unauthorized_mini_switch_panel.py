"""Panel for the unauthorized mini-switch / hub attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.unauthorized_mini_switch import (
    MAX_CLIENTS,
    MiniSwitchConfig,
    MiniSwitchStats,
    run_mini_switch,
)
from macabre.gui.base_panel import AttackPanel


class UnauthorizedMiniSwitchPanel(AttackPanel):
    title = "Unauthorized Mini-Switch / Hub"
    description = (
        "Sends one frame from each listed client MAC through this port, as a mini-switch behind an authorized "
        "port would. Shows whether the port carries several clients. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.clients_edit = QLineEdit()
        self.clients_edit.setPlaceholderText(f"Client MACs, comma separated (2 to {MAX_CLIENTS})")
        form.addRow("Client MACs:", self.clients_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.clients_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MiniSwitchConfig:
        del count, interval  # one frame per client MAC
        macs = tuple(m.strip() for m in self.clients_edit.text().split(",") if m.strip())
        return MiniSwitchConfig(iface=iface, client_macs=macs, dry_run=dry_run)

    def _run_attack(
        self,
        config: MiniSwitchConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MiniSwitchStats], None],
    ) -> MiniSwitchStats:
        return run_mini_switch(config, stop_event, on_progress)

    def _format_status(self, stats: MiniSwitchStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
