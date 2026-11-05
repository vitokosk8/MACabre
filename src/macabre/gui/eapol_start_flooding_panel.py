"""Panel for the EAPOL start flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.eapol_start_flooding import (
    MAX_FRAMES,
    EapolStartFloodingConfig,
    EapolStartFloodingStats,
    run_eapol_start_flooding,
)
from macabre.gui.base_panel import AttackPanel


class EapolStartFloodingPanel(AttackPanel):
    title = "EAPOL Start Flooding"
    description = (
        "Sends EAPOL-Start frames from random supplicant MACs to the 802.1X authenticator. Each start makes the "
        "authenticator send an identity request and keep state for that MAC. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(10)
        self.frames_spin.setSuffix(" EAPOL-Start frame(s)")
        form.addRow("Frames:", self.frames_spin)

        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Empty = random MAC for each frame")
        self.source_edit.setToolTip("A fixed supplicant MAC for every frame, or leave empty for random ones.")
        form.addRow("Source MAC:", self.source_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.frames_spin.setEnabled(enabled)
        self.source_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> EapolStartFloodingConfig:
        del count, interval  # the frame count above sets the total for this attack
        return EapolStartFloodingConfig(
            iface=iface,
            frames=self.frames_spin.value(),
            source_mac=self.source_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: EapolStartFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[EapolStartFloodingStats], None],
    ) -> EapolStartFloodingStats:
        return run_eapol_start_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: EapolStartFloodingStats) -> str:
        return stats.status or f"EAPOL-Start frames sent: {stats.frames}"
