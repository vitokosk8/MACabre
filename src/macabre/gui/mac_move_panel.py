"""Panel for the MAC move abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.mac_move import (
    MAX_FRAMES,
    MacMoveConfig,
    MacMoveStats,
    run_mac_move,
)
from macabre.gui.base_panel import AttackPanel


class MacMovePanel(AttackPanel):
    title = "MAC Move / Mobility Abuse"
    description = (
        "Sends frames that claim a host's MAC address from this port, so the switch moves the host's "
        "learned entry here. Traffic for that address then follows this port until the host sends again. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Host MAC to move, e.g. 02:00:00:00:00:50")
        form.addRow("Host MAC:", self.target_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(1)
        self.frames_spin.setSuffix(" frame(s)")
        form.addRow("Moves:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.target_edit.setEnabled(enabled)
        self.frames_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MacMoveConfig:
        del count, interval  # this attack sends its frames once
        return MacMoveConfig(
            iface=iface,
            target_mac=self.target_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MacMoveConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MacMoveStats], None],
    ) -> MacMoveStats:
        return run_mac_move(config, stop_event, on_progress)

    def _format_status(self, stats: MacMoveStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
