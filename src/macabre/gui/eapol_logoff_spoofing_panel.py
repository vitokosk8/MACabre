"""Panel for the EAPOL logoff spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.eapol_logoff_spoofing import (
    MAX_LOGOFFS,
    EapolLogoffSpoofingConfig,
    EapolLogoffSpoofingStats,
    run_eapol_logoff_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class EapolLogoffSpoofingPanel(AttackPanel):
    title = "EAPOL Logoff Spoofing"
    description = (
        "Sends EAPOL-Logoff frames that claim the MAC of an authenticated supplicant. An authenticator that trusts "
        "the source MAC removes that supplicant's access. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Supplicant MAC to log off, e.g. 02:00:00:00:00:61")
        form.addRow("Supplicant MAC:", self.source_edit)

        self.logoffs_spin = QSpinBox()
        self.logoffs_spin.setRange(1, MAX_LOGOFFS)
        self.logoffs_spin.setValue(1)
        self.logoffs_spin.setSuffix(" logoff(s)")
        form.addRow("Logoffs:", self.logoffs_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.logoffs_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> EapolLogoffSpoofingConfig:
        del count, interval  # the logoff count above sets the total for this attack
        return EapolLogoffSpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            logoffs=self.logoffs_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: EapolLogoffSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[EapolLogoffSpoofingStats], None],
    ) -> EapolLogoffSpoofingStats:
        return run_eapol_logoff_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: EapolLogoffSpoofingStats) -> str:
        return stats.status or f"EAPOL-Logoff frames sent: {stats.logoffs}"
