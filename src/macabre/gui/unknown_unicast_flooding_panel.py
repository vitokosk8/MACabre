"""Panel for the unknown unicast flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.unknown_unicast_flooding import (
    MAX_DURATION,
    UnknownUnicastConfig,
    UnknownUnicastStats,
    run_unknown_unicast_flooding,
)
from macabre.gui.base_panel import AttackPanel


class UnknownUnicastFloodingPanel(AttackPanel):
    title = "Unknown Unicast Flooding"
    description = (
        "Listens on this port for unicast frames that the switch floods because it does not know their "
        "destination, and counts those addressed to other hosts. It sends nothing. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(1, int(MAX_DURATION))
        self.duration_spin.setValue(30)
        self.duration_spin.setSuffix(" s")
        form.addRow("Listen for:", self.duration_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.duration_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> UnknownUnicastConfig:
        del count, interval  # this attack captures for a set time, it does not send
        return UnknownUnicastConfig(
            iface=iface,
            duration=float(self.duration_spin.value()),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: UnknownUnicastConfig,
        stop_event: threading.Event,
        on_progress: Callable[[UnknownUnicastStats], None],
    ) -> UnknownUnicastStats:
        return run_unknown_unicast_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: UnknownUnicastStats) -> str:
        return stats.status or f"Flooded frames seen: {stats.frames}"
