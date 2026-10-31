"""Panel for the MAC flapping attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QComboBox, QFormLayout, QLineEdit
from scapy.all import get_if_list

from macabre.attacks.mac_flapping import (
    FlappingStats,
    MacFlappingConfig,
    run_flapping,
)
from macabre.gui.base_panel import AttackPanel


class MacFlappingPanel(AttackPanel):
    title = "MAC flapping"
    description = (
        "Sends frames with the same source MAC from two interfaces attached to two "
        "switch ports, so the switch keeps moving that MAC between ports. Use only with authorization."
    )
    default_interval = 0.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.iface_b_combo = QComboBox()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Empty = random MAC (for example 02:00:00:00:00:10)")
        form.addRow("Second interface (port B):", self.iface_b_combo)
        form.addRow("Target MAC:", self.target_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.iface_b_combo.setEnabled(enabled)
        self.target_edit.setEnabled(enabled)

    def _refresh_interfaces(self) -> None:
        super()._refresh_interfaces()
        if not hasattr(self, "iface_b_combo"):
            return
        current = self.iface_b_combo.currentText()
        self.iface_b_combo.clear()
        self.iface_b_combo.addItems(get_if_list())
        index = self.iface_b_combo.findText(current)
        if index >= 0:
            self.iface_b_combo.setCurrentIndex(index)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MacFlappingConfig:
        return MacFlappingConfig(
            iface_a=iface,
            iface_b=self.iface_b_combo.currentText(),
            target_mac=self.target_edit.text().strip(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MacFlappingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[FlappingStats], None],
    ) -> FlappingStats:
        return run_flapping(config, stop_event, on_progress)

    def _format_status(self, stats: FlappingStats) -> str:
        return f"Frames sent: {stats.frames}"
