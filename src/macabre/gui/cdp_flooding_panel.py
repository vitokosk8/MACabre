"""Panel for the CDP flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.cdp_flooding import MAX_RATE, CdpFloodingConfig, CdpFloodingStats, run_cdp_flooding
from macabre.gui.base_panel import AttackPanel


class CdpFloodingPanel(AttackPanel):
    title = "CDP Flooding"
    description = (
        "Sends CDP advertisements at a high rate, each for a random device, port and address. Receivers that "
        "keep CDP neighbors fill their table, and a new neighbor may be refused. Use only with authorization."
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

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> CdpFloodingConfig:
        del interval  # the rate sets the timing for this attack
        return CdpFloodingConfig(iface=iface, rate=float(self.rate_spin.value()), count=count, dry_run=dry_run)

    def _run_attack(
        self,
        config: CdpFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[CdpFloodingStats], None],
    ) -> CdpFloodingStats:
        return run_cdp_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: CdpFloodingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
