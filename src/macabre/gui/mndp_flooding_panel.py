"""Panel for the MNDP flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.mndp_flooding import MAX_RATE, MndpFloodingConfig, MndpFloodingStats, run_mndp_flooding
from macabre.gui.base_panel import AttackPanel


class MndpFloodingPanel(AttackPanel):
    title = "MNDP Flooding"
    description = (
        "Sends MikroTik Neighbor Discovery announcements at a high rate, each for a random router, identity and "
        "address. RouterOS neighbor lists that hear them fill with invented devices. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(100)
        self.rate_spin.setSuffix(" announcements/s")
        self.rate_spin.setToolTip("Announcements per second. The interval setting does not apply to this attack.")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MndpFloodingConfig:
        del interval  # the rate sets the timing for this attack
        return MndpFloodingConfig(iface=iface, rate=float(self.rate_spin.value()), count=count, dry_run=dry_run)

    def _run_attack(
        self,
        config: MndpFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MndpFloodingStats], None],
    ) -> MndpFloodingStats:
        return run_mndp_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: MndpFloodingStats) -> str:
        return stats.status or f"Announcements sent: {stats.frames}"
