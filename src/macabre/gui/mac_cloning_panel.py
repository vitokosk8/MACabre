"""Panel for the MAC cloning attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.mac_cloning import (
    CloningStats,
    MacCloningConfig,
    run_cloning,
)
from macabre.gui.base_panel import AttackPanel


class MacCloningPanel(AttackPanel):
    title = "MAC cloning"
    description = (
        "Changes this interface's MAC address to the target's, so the whole host presents "
        "that identity. The original address is restored when you press Stop. This changes "
        "the real interface: use a lab or a dedicated adapter. Use only with authorization."
    )
    show_frame_controls = False
    dry_run_label = "Show the commands only (do not change the MAC)"

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("MAC to clone, for example 02:00:00:00:00:20")
        form.addRow("Target MAC:", self.target_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.target_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MacCloningConfig:
        return MacCloningConfig(
            iface=iface,
            target_mac=self.target_edit.text(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MacCloningConfig,
        stop_event: threading.Event,
        on_progress: Callable[[CloningStats], None],
    ) -> CloningStats:
        return run_cloning(config, stop_event, on_progress)

    def _format_status(self, stats: CloningStats) -> str:
        return stats.status or "MAC cloning not started"
