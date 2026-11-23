"""Panel for the PPPoE session spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.pppoe_session_spoofing import (
    MAX_SESSION_ID,
    PppoeSessionSpoofingConfig,
    PppoeSessionSpoofingStats,
    run_pppoe_session_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class PppoeSessionSpoofingPanel(AttackPanel):
    title = "PPPoE Session Spoofing"
    description = (
        "Sends PADT frames to one client, claiming the concentrator as the source and a session ID you choose. "
        "A client that accepts the PADT ends its PPPoE session and must start discovery again. "
        "Use only with authorization."
    )
    default_interval = 0.5

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_mac_edit = QLineEdit()
        self.source_mac_edit.setPlaceholderText("Concentrator MAC to claim, e.g. 02:00:00:00:00:86")
        form.addRow("Source MAC:", self.source_mac_edit)

        self.client_mac_edit = QLineEdit()
        self.client_mac_edit.setPlaceholderText("Client MAC, e.g. 02:00:00:00:00:87")
        form.addRow("Client MAC:", self.client_mac_edit)

        self.session_spin = QSpinBox()
        self.session_spin.setRange(1, MAX_SESSION_ID)
        self.session_spin.setValue(1)
        self.session_spin.setToolTip("PPPoE session ID the client uses.")
        form.addRow("Session ID:", self.session_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_mac_edit.setEnabled(enabled)
        self.client_mac_edit.setEnabled(enabled)
        self.session_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> PppoeSessionSpoofingConfig:
        return PppoeSessionSpoofingConfig(
            iface=iface,
            source_mac=self.source_mac_edit.text().strip(),
            client_mac=self.client_mac_edit.text().strip(),
            session_id=self.session_spin.value(),
            frames=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: PppoeSessionSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[PppoeSessionSpoofingStats], None],
    ) -> PppoeSessionSpoofingStats:
        return run_pppoe_session_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: PppoeSessionSpoofingStats) -> str:
        return stats.status or f"PADTs sent: {stats.frames}"
