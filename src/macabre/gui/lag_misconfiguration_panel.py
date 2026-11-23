"""Panel for the LAG misconfiguration abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QComboBox, QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.lacp_spoofing import MAX_KEY
from macabre.attacks.lag_misconfiguration_abuse import (
    TIMEOUT_MODES,
    LagMisconfigurationConfig,
    LagMisconfigurationStats,
    run_lag_misconfiguration,
)
from macabre.gui.base_panel import AttackPanel


class LagMisconfigurationPanel(AttackPanel):
    title = "LAG Misconfiguration Abuse"
    description = (
        "Sends LACPDUs that claim an LACP timeout mode. A short timeout is refreshed every second and expires "
        "after about three seconds of silence; a long timeout expires after about 90 seconds. After the last "
        "LACPDU the attacker goes silent, so the time the aggregate keeps the claimed partner shows whether it "
        "honours a timeout its link does not match. Use only with authorization."
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

        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems(TIMEOUT_MODES)
        self.timeout_combo.setToolTip("Timeout mode claimed in the LACPDUs.")
        form.addRow("Timeout:", self.timeout_combo)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.system_edit.setEnabled(enabled)
        self.key_spin.setEnabled(enabled)
        self.port_spin.setEnabled(enabled)
        self.timeout_combo.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> LagMisconfigurationConfig:
        return LagMisconfigurationConfig(
            iface=iface,
            system_mac=self.system_edit.text().strip(),
            key=self.key_spin.value(),
            port_number=self.port_spin.value(),
            timeout=self.timeout_combo.currentText(),
            frames=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: LagMisconfigurationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[LagMisconfigurationStats], None],
    ) -> LagMisconfigurationStats:
        return run_lag_misconfiguration(config, stop_event, on_progress)

    def _format_status(self, stats: LagMisconfigurationStats) -> str:
        return stats.status or f"LACPDUs sent: {stats.frames}"
