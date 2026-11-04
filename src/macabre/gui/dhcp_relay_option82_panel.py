"""Panel for the DHCP relay option 82 abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.dhcp_relay_option82 import (
    MAX_DISCOVERS,
    RelayOption82Config,
    RelayOption82Stats,
    run_relay_option82,
)
from macabre.gui.base_panel import AttackPanel


class DhcpRelayOption82Panel(AttackPanel):
    title = "DHCP Relay / Option 82 Abuse"
    description = (
        "Sends DHCPDISCOVER messages with a forged Option 82 (circuit ID and remote ID), so a server "
        "that trusts it picks the pool for another port. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.circuit_edit = QLineEdit()
        self.circuit_edit.setPlaceholderText("Circuit ID, e.g. pool-a")
        form.addRow("Circuit ID:", self.circuit_edit)

        self.remote_edit = QLineEdit()
        self.remote_edit.setPlaceholderText("Optional remote ID, e.g. switch-1")
        form.addRow("Remote ID:", self.remote_edit)

        self.client_mac_edit = QLineEdit()
        self.client_mac_edit.setPlaceholderText("Optional client MAC; empty = random")
        form.addRow("Client MAC:", self.client_mac_edit)

        self.discovers_spin = QSpinBox()
        self.discovers_spin.setRange(1, MAX_DISCOVERS)
        self.discovers_spin.setValue(1)
        self.discovers_spin.setSuffix(" discover(s)")
        form.addRow("Discovers:", self.discovers_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.circuit_edit, self.remote_edit, self.client_mac_edit, self.discovers_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RelayOption82Config:
        del count, interval  # discovers are sent once each
        return RelayOption82Config(
            iface=iface,
            circuit_id=self.circuit_edit.text().strip(),
            remote_id=self.remote_edit.text().strip(),
            client_mac=self.client_mac_edit.text().strip(),
            discovers=self.discovers_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RelayOption82Config,
        stop_event: threading.Event,
        on_progress: Callable[[RelayOption82Stats], None],
    ) -> RelayOption82Stats:
        return run_relay_option82(config, stop_event, on_progress)

    def _format_status(self, stats: RelayOption82Stats) -> str:
        return stats.status or f"Discovers sent: {stats.discovers}"
