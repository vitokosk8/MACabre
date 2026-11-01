"""Panel for the broadcast storm attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.broadcast_storm import MAX_PAYLOAD, MAX_RATE, BroadcastStormConfig, BroadcastStormStats, run_broadcast_storm
from macabre.gui.base_panel import AttackPanel


class BroadcastStormPanel(AttackPanel):
    title = "Broadcast Storm"
    description = (
        "Sends broadcast frames at a high rate. A switch floods each one to every port of the VLAN, and a loop "
        "makes them multiply, which saturates links and hosts. Use only with authorization, and never on a "
        "production network."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(100)
        self.rate_spin.setSuffix(" frames/s")
        self.rate_spin.setToolTip("Broadcast frames per second. The interval setting does not apply to this attack.")
        form.addRow("Rate:", self.rate_spin)

        self.payload_spin = QSpinBox()
        self.payload_spin.setRange(0, MAX_PAYLOAD)
        self.payload_spin.setValue(64)
        self.payload_spin.setSuffix(" bytes")
        form.addRow("Payload:", self.payload_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)
        self.payload_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> BroadcastStormConfig:
        del interval  # the rate sets the timing for this attack
        return BroadcastStormConfig(
            iface=iface,
            rate=float(self.rate_spin.value()),
            payload_size=self.payload_spin.value(),
            count=count,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: BroadcastStormConfig,
        stop_event: threading.Event,
        on_progress: Callable[[BroadcastStormStats], None],
    ) -> BroadcastStormStats:
        return run_broadcast_storm(config, stop_event, on_progress)

    def _format_status(self, stats: BroadcastStormStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
