"""Panel for the LLDP flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.lldp_flooding import MAX_RATE, LldpFloodingConfig, LldpFloodingStats, run_lldp_flooding
from macabre.gui.base_panel import AttackPanel


class LldpFloodingPanel(AttackPanel):
    title = "LLDP Flooding"
    description = (
        "Sends LLDP advertisements at a high rate, each for a random chassis, name, port and address. Receivers "
        "that keep LLDP neighbors fill their table and may drop legitimate neighbors. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(100)
        self.rate_spin.setSuffix(" advertisements/s")
        self.rate_spin.setToolTip("Advertisements per second. The interval setting does not apply to this attack.")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> LldpFloodingConfig:
        del interval  # the rate sets the timing for this attack
        return LldpFloodingConfig(iface=iface, rate=float(self.rate_spin.value()), count=count, dry_run=dry_run)

    def _run_attack(
        self,
        config: LldpFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[LldpFloodingStats], None],
    ) -> LldpFloodingStats:
        return run_lldp_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: LldpFloodingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
