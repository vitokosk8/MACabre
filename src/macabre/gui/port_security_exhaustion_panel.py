"""Panel for the port security exhaustion attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.port_security_exhaustion import (
    MAX_RATE,
    PortSecurityExhaustionConfig,
    PortSecurityExhaustionStats,
    run_port_security_exhaustion,
)
from macabre.gui.base_panel import AttackPanel


class PortSecurityExhaustionPanel(AttackPanel):
    title = "Port Security Exhaustion"
    description = (
        "Sends frames from one port, each with a new source MAC address, to use up the port's MAC limit. "
        "A port that reaches its limit may drop the legitimate host or shut down. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(10)
        self.rate_spin.setSuffix(" frames/s")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> PortSecurityExhaustionConfig:
        del interval  # the rate sets the timing for this attack
        return PortSecurityExhaustionConfig(
            iface=iface,
            rate=float(self.rate_spin.value()),
            count=count,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: PortSecurityExhaustionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[PortSecurityExhaustionStats], None],
    ) -> PortSecurityExhaustionStats:
        return run_port_security_exhaustion(config, stop_event, on_progress)

    def _format_status(self, stats: PortSecurityExhaustionStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
