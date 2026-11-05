"""Panel for the PPPoE discovery flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.pppoe_discovery_flooding import (
    MAX_FRAMES,
    PppoeDiscoveryFloodingConfig,
    PppoeDiscoveryFloodingStats,
    run_pppoe_discovery_flooding,
)
from macabre.gui.base_panel import AttackPanel


class PppoeDiscoveryFloodingPanel(AttackPanel):
    title = "PPPoE Discovery Flooding"
    description = (
        "Sends PADI discovery frames from random client MACs, with no follow-up. An access concentrator "
        "answers each one with a PADO and reserves work for it. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(10)
        self.frames_spin.setSuffix(" PADI frame(s)")
        form.addRow("Frames:", self.frames_spin)

        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Empty = random MAC for each frame")
        self.source_edit.setToolTip("A fixed sender MAC for every PADI, or leave empty for random clients.")
        form.addRow("Source MAC:", self.source_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.frames_spin.setEnabled(enabled)
        self.source_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> PppoeDiscoveryFloodingConfig:
        del count, interval  # the frame count above sets the total for this attack
        return PppoeDiscoveryFloodingConfig(
            iface=iface,
            frames=self.frames_spin.value(),
            source_mac=self.source_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: PppoeDiscoveryFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[PppoeDiscoveryFloodingStats], None],
    ) -> PppoeDiscoveryFloodingStats:
        return run_pppoe_discovery_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: PppoeDiscoveryFloodingStats) -> str:
        return stats.status or f"PADI frames sent: {stats.frames}"
