"""Panel for the STP loop induction attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout
from scapy.all import get_if_list

from macabre.attacks.stp_loop_induction import (
    StpLoopInductionConfig,
    StpLoopInductionStats,
    run_stp_loop_induction,
)
from macabre.gui.base_panel import AttackPanel


class StpLoopInductionPanel(AttackPanel):
    title = "STP Loop Induction"
    description = (
        "Bridges two of your interfaces with STP off and drops the STP BPDUs, so a switch that connects "
        "both interfaces sees both ports as forwarding and a loop forms. Connect each interface to a "
        "different port of the same switch. Check 'Run STP' for the control, where the bridge runs STP "
        "and blocks one of its own ports. Use only with authorization."
    )
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.second_iface_combo = QComboBox()
        self.second_iface_combo.addItems(get_if_list())
        form.addRow("Second interface:", self.second_iface_combo)

        self.run_stp_check = QCheckBox("Run STP in the bridge (control)")
        form.addRow("", self.run_stp_check)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.second_iface_combo.setEnabled(enabled)
        self.run_stp_check.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> StpLoopInductionConfig:
        return StpLoopInductionConfig(
            iface_a=iface,
            iface_b=self.second_iface_combo.currentText(),
            run_stp=self.run_stp_check.isChecked(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: StpLoopInductionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[StpLoopInductionStats], None],
    ) -> StpLoopInductionStats:
        return run_stp_loop_induction(config, stop_event, on_progress)

    def _format_status(self, stats: StpLoopInductionStats) -> str:
        return stats.status or "Bridge idle."
