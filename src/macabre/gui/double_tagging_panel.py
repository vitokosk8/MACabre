"""Panel for the double-tagging attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.double_tagging import DoubleTaggingConfig, DoubleTaggingStats, run_double_tagging
from macabre.gui.base_panel import AttackPanel


class DoubleTaggingPanel(AttackPanel):
    title = "Double tagging"
    description = (
        "Sends frames with two 802.1Q tags: an outer tag for the trunk's native VLAN and an inner "
        "tag for the target VLAN. A switch that removes the outer tag may forward the frame into "
        "the target VLAN. The switch decides the result, so verify it on that switch. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.native_edit = QLineEdit()
        self.native_edit.setPlaceholderText("Native VLAN (outer tag), 1 to 4094")
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Target VLAN (inner tag), 1 to 4094")
        self.probe_edit = QLineEdit("192.0.2.1")
        form.addRow("Native VLAN:", self.native_edit)
        form.addRow("Target VLAN:", self.target_edit)
        form.addRow("Probe IP:", self.probe_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.native_edit.setEnabled(enabled)
        self.target_edit.setEnabled(enabled)
        self.probe_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DoubleTaggingConfig:
        native = self.native_edit.text().strip()
        target = self.target_edit.text().strip()
        if not native.isdigit() or not target.isdigit():
            raise ValueError("Both VLANs must be numbers between 1 and 4094.")
        return DoubleTaggingConfig(
            iface=iface,
            native_vlan=int(native),
            target_vlan=int(target),
            probe_ip=self.probe_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: DoubleTaggingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[DoubleTaggingStats], None],
    ) -> DoubleTaggingStats:
        return run_double_tagging(config, stop_event, on_progress)

    def _format_status(self, stats: DoubleTaggingStats) -> str:
        return stats.status or f"Probes sent: {stats.frames}"
