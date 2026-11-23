"""Panel for the LACP negotiation flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.lacp_negotiation_flooding import (
    DEFAULT_STATES,
    LacpNegotiationFloodingConfig,
    LacpNegotiationFloodingStats,
    parse_states,
    run_lacp_negotiation_flooding,
)
from macabre.attacks.lacp_spoofing import MAX_KEY
from macabre.gui.base_panel import AttackPanel


class LacpNegotiationFloodingPanel(AttackPanel):
    title = "LACP Negotiation Flooding"
    description = (
        "Sends LACPDUs at a high rate from a port with no real partner, cycling the actor state between the "
        "values below. An aggregate that processes every LACPDU changes its member state repeatedly, which can "
        "disturb its traffic. Use only with authorization."
    )
    default_interval = 0.02

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

        self.states_edit = QLineEdit(", ".join(f"0x{state:02X}" for state in DEFAULT_STATES))
        self.states_edit.setToolTip("Actor state values sent in turn, decimal or hex, separated by commas.")
        form.addRow("Actor states:", self.states_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.system_edit.setEnabled(enabled)
        self.key_spin.setEnabled(enabled)
        self.port_spin.setEnabled(enabled)
        self.states_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> LacpNegotiationFloodingConfig:
        return LacpNegotiationFloodingConfig(
            iface=iface,
            system_mac=self.system_edit.text().strip(),
            key=self.key_spin.value(),
            port_number=self.port_spin.value(),
            states=parse_states(self.states_edit.text()),
            frames=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: LacpNegotiationFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[LacpNegotiationFloodingStats], None],
    ) -> LacpNegotiationFloodingStats:
        return run_lacp_negotiation_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: LacpNegotiationFloodingStats) -> str:
        return stats.status or f"LACPDUs sent: {stats.frames}, state changes: {stats.state_changes}"
