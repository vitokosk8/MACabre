"""Panel for the LACP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.lacp_spoofing import LacpSpoofingConfig, LacpSpoofingStats, MAX_KEY, run_lacp_spoofing
from macabre.gui.base_panel import AttackPanel


class LacpSpoofingPanel(AttackPanel):
    title = "LACP Spoofing"
    description = (
        "Sends LACPDUs that claim an actor system ID and key from a port with no real partner. A switch or host "
        "that accepts them may form or change an aggregate with this port. Leave the System ID empty for a random "
        "one. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.system_edit = QLineEdit()
        self.system_edit.setPlaceholderText("Claimed system MAC (empty = random)")
        form.addRow("System ID:", self.system_edit)

        self.key_spin = QSpinBox()
        self.key_spin.setRange(1, MAX_KEY)
        self.key_spin.setValue(1)
        self.key_spin.setToolTip("Actor key claimed in the LACPDUs.")
        form.addRow("Key:", self.key_spin)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, MAX_KEY)
        self.port_spin.setValue(1)
        self.port_spin.setToolTip("Actor port number claimed in the LACPDUs.")
        form.addRow("Port number:", self.port_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.system_edit.setEnabled(enabled)
        self.key_spin.setEnabled(enabled)
        self.port_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> LacpSpoofingConfig:
        return LacpSpoofingConfig(
            iface=iface,
            system_mac=self.system_edit.text().strip(),
            key=self.key_spin.value(),
            port_number=self.port_spin.value(),
            frames=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: LacpSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[LacpSpoofingStats], None],
    ) -> LacpSpoofingStats:
        return run_lacp_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: LacpSpoofingStats) -> str:
        return stats.status or f"LACPDUs sent: {stats.frames}"
