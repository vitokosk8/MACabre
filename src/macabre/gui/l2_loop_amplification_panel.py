"""Panel for the L2 loop amplification attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.common import BROADCAST_MAC
from macabre.attacks.l2_loop_amplification import (
    L2LoopAmplificationConfig,
    L2LoopAmplificationStats,
    run_l2_loop_amplification,
)
from macabre.gui.base_panel import AttackPanel


class L2LoopAmplificationPanel(AttackPanel):
    title = "L2 Loop Amplification"
    description = (
        "Sends one broadcast or multicast frame with a random source MAC into the interface's switch port. "
        "On a switch with a loop and no loop protection, the frame comes back many times. Count the copies "
        "on the switch ports with the lab, not here. Use only with authorization."
    )
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.destination_edit = QLineEdit(BROADCAST_MAC)
        self.destination_edit.setToolTip("Broadcast or multicast destination (group bit set).")
        form.addRow("Destination:", self.destination_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.destination_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> L2LoopAmplificationConfig:
        return L2LoopAmplificationConfig(
            iface=iface,
            destination=self.destination_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: L2LoopAmplificationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[L2LoopAmplificationStats], None],
    ) -> L2LoopAmplificationStats:
        return run_l2_loop_amplification(config, stop_event, on_progress)

    def _format_status(self, stats: L2LoopAmplificationStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
