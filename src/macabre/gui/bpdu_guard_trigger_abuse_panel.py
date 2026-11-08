"""Panel for the BPDU Guard trigger abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.bpdu_guard_trigger_abuse import (
    MAX_BPDUS,
    BpduGuardTriggerConfig,
    BpduGuardTriggerStats,
    run_bpdu_guard_trigger,
)
from macabre.gui.base_panel import AttackPanel


class BpduGuardTriggerAbusePanel(AttackPanel):
    title = "BPDU Guard Trigger Abuse"
    description = (
        "Sends STP configuration BPDUs toward a port that has BPDU Guard, such as a host port with PortFast. "
        "A switch that enforces BPDU Guard disables that port. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Sender MAC, e.g. 02:00:00:00:00:20")
        form.addRow("Source MAC:", self.source_edit)

        self.bpdus_spin = QSpinBox()
        self.bpdus_spin.setRange(1, MAX_BPDUS)
        self.bpdus_spin.setValue(3)
        self.bpdus_spin.setSuffix(" BPDU(s)")
        form.addRow("BPDUs:", self.bpdus_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.bpdus_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> BpduGuardTriggerConfig:
        del count, interval  # the BPDU count is set in this panel
        return BpduGuardTriggerConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            bpdus=self.bpdus_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: BpduGuardTriggerConfig,
        stop_event: threading.Event,
        on_progress: Callable[[BpduGuardTriggerStats], None],
    ) -> BpduGuardTriggerStats:
        return run_bpdu_guard_trigger(config, stop_event, on_progress)

    def _format_status(self, stats: BpduGuardTriggerStats) -> str:
        return stats.status or f"BPDUs sent: {stats.bpdus}"
