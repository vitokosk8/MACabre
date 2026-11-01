"""Panel for the BPDU flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.bpdu_flooding import MAX_RATE, BpduFloodingConfig, BpduFloodingStats, run_bpdu_flooding
from macabre.gui.base_panel import AttackPanel


class BpduFloodingPanel(AttackPanel):
    title = "BPDU Flooding"
    description = (
        "Sends configuration BPDUs at a high rate from random bridge IDs, all at the worst priority, so none "
        "can win the election. The switch must parse each one, which can delay real spanning-tree updates. "
        "Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(500)
        self.rate_spin.setSuffix(" BPDUs/s")
        self.rate_spin.setToolTip("Frames per second. The interval setting does not apply to this attack.")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> BpduFloodingConfig:
        del interval  # the rate sets the timing for this attack
        return BpduFloodingConfig(iface=iface, rate=float(self.rate_spin.value()), count=count, dry_run=dry_run)

    def _run_attack(
        self,
        config: BpduFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[BpduFloodingStats], None],
    ) -> BpduFloodingStats:
        return run_bpdu_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: BpduFloodingStats) -> str:
        return stats.status or f"BPDUs sent: {stats.frames}"
