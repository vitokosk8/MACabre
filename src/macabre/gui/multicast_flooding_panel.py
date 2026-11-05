"""Panel for the multicast flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.multicast_flooding import MAX_PAYLOAD, MAX_RATE, MulticastFloodingConfig, MulticastFloodingStats, run_multicast_flooding
from macabre.gui.base_panel import AttackPanel


class MulticastFloodingPanel(AttackPanel):
    title = "Multicast Flooding"
    description = (
        "Sends a stream of frames to random multicast groups that nobody has joined. A switch that does not "
        "learn the groups floods them to every port. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(100)
        self.rate_spin.setSuffix(" frames/s")
        self.rate_spin.setToolTip("Frames per second. The interval setting does not apply to this attack.")
        form.addRow("Rate:", self.rate_spin)

        self.payload_spin = QSpinBox()
        self.payload_spin.setRange(0, MAX_PAYLOAD)
        self.payload_spin.setValue(64)
        self.payload_spin.setSuffix(" bytes")
        form.addRow("Payload:", self.payload_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)
        self.payload_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MulticastFloodingConfig:
        del interval  # the rate sets the timing for this attack
        return MulticastFloodingConfig(
            iface=iface,
            rate=float(self.rate_spin.value()),
            payload_size=self.payload_spin.value(),
            count=count,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MulticastFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MulticastFloodingStats], None],
    ) -> MulticastFloodingStats:
        return run_multicast_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: MulticastFloodingStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"


class UnknownMulticastFloodingPanel(MulticastFloodingPanel):
    """The same stream to groups nobody joined, presented as unknown multicast: the switch floods it to every port."""

    title = "Unknown Multicast Flooding"
    description = (
        "Sends frames to multicast groups that no host has joined. A switch that has no entry for a group floods "
        "the frames to every port. Use only with authorization."
    )
