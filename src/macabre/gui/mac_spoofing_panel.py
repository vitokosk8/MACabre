"""Panel for the MAC address spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.mac_spoofing import (
    MacSpoofingConfig,
    SpoofingStats,
    run_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class MacSpoofingPanel(AttackPanel):
    title = "MAC address spoofing"
    description = (
        "Sends frames with the source MAC of a target host, so the switch learns that "
        "address on this port and forwards its traffic here. Use only with authorization."
    )
    default_interval = 0.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("MAC to impersonate, for example 02:00:00:00:00:10")
        form.addRow("Target MAC:", self.target_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.target_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MacSpoofingConfig:
        return MacSpoofingConfig(
            iface=iface,
            target_mac=self.target_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MacSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[SpoofingStats], None],
    ) -> SpoofingStats:
        return run_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: SpoofingStats) -> str:
        return f"Frames sent: {stats.frames}"
