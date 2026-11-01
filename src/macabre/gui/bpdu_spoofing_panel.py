"""Panel for the BPDU spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.bpdu_spoofing import (
    MAX_PRIORITY,
    PRIORITY_STEP,
    BpduSpoofingConfig,
    BpduSpoofingStats,
    run_bpdu_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class BpduSpoofingPanel(AttackPanel):
    title = "BPDU Spoofing"
    description = (
        "Sends configuration BPDUs that advertise a root bridge of your choice. A switch that accepts "
        "them may move its root port and recalculate the spanning tree. Lower priority values win the "
        "election. Use only with authorization."
    )
    default_interval = 2.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.root_priority_spin = QSpinBox()
        self.root_priority_spin.setRange(0, MAX_PRIORITY)
        self.root_priority_spin.setSingleStep(PRIORITY_STEP)
        self.root_priority_spin.setValue(0)
        self.root_priority_spin.setToolTip("Bridge priority of the advertised root (multiple of 4096; lower wins).")
        form.addRow("Root priority:", self.root_priority_spin)

        self.root_mac_edit = QLineEdit()
        self.root_mac_edit.setPlaceholderText("Root MAC (optional; empty = this interface)")
        form.addRow("Root MAC:", self.root_mac_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.root_priority_spin.setEnabled(enabled)
        self.root_mac_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> BpduSpoofingConfig:
        return BpduSpoofingConfig(
            iface=iface,
            root_priority=self.root_priority_spin.value(),
            root_mac=self.root_mac_edit.text().strip(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: BpduSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[BpduSpoofingStats], None],
    ) -> BpduSpoofingStats:
        return run_bpdu_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: BpduSpoofingStats) -> str:
        return stats.status or f"BPDUs sent: {stats.frames}"
