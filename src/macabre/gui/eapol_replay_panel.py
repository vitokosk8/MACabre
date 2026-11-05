"""Panel for the EAPOL replay attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.eapol_replay import (
    MAX_CAPTURE_SECONDS,
    MAX_REPEATS,
    EapolReplayConfig,
    EapolReplayStats,
    run_eapol_replay,
)
from macabre.gui.base_panel import AttackPanel


class EapolReplayPanel(AttackPanel):
    title = "EAPOL Replay"
    description = (
        "Captures the EAP responses a supplicant sends during a window, then sends them again. A correct "
        "authenticator does not authorize a port on a replayed response. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.victim_edit = QLineEdit()
        self.victim_edit.setPlaceholderText("Supplicant MAC to capture, e.g. 02:00:00:00:00:61")
        form.addRow("Supplicant MAC:", self.victim_edit)

        self.capture_spin = QSpinBox()
        self.capture_spin.setRange(1, MAX_CAPTURE_SECONDS)
        self.capture_spin.setValue(10)
        self.capture_spin.setSuffix(" s")
        self.capture_spin.setToolTip("How long to capture the supplicant's responses before replaying them.")
        form.addRow("Capture:", self.capture_spin)

        self.repeats_spin = QSpinBox()
        self.repeats_spin.setRange(1, MAX_REPEATS)
        self.repeats_spin.setValue(1)
        self.repeats_spin.setSuffix(" time(s)")
        form.addRow("Replays:", self.repeats_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.victim_edit.setEnabled(enabled)
        self.capture_spin.setEnabled(enabled)
        self.repeats_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> EapolReplayConfig:
        del count, interval  # the capture time and replay count above set this attack's timing
        return EapolReplayConfig(
            iface=iface,
            victim_mac=self.victim_edit.text().strip(),
            capture_seconds=self.capture_spin.value(),
            repeats=self.repeats_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: EapolReplayConfig,
        stop_event: threading.Event,
        on_progress: Callable[[EapolReplayStats], None],
    ) -> EapolReplayStats:
        return run_eapol_replay(config, stop_event, on_progress)

    def _format_status(self, stats: EapolReplayStats) -> str:
        return stats.status or f"Responses captured: {stats.captured}, replayed: {stats.replayed}"
