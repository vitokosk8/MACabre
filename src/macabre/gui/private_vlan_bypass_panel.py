"""Panel for the private VLAN isolation bypass attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.private_vlan_bypass import (
    MAX_PROBES,
    PrivateVlanBypassConfig,
    PrivateVlanBypassStats,
    run_private_vlan_bypass,
)
from macabre.gui.base_panel import AttackPanel


class PrivateVlanBypassPanel(AttackPanel):
    title = "Private VLAN Isolation Bypass"
    description = (
        "Sends probes to an isolated host through a promiscuous relay, such as a router on an uplink, which "
        "may forward them although the isolated ports cannot reach each other directly. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_mac_edit = QLineEdit()
        self.source_mac_edit.setPlaceholderText("Attacker MAC, e.g. 02:00:00:00:00:20")
        form.addRow("Source MAC:", self.source_mac_edit)

        self.source_ip_edit = QLineEdit()
        self.source_ip_edit.setPlaceholderText("Attacker IPv4, e.g. 10.77.0.20")
        form.addRow("Source IP:", self.source_ip_edit)

        self.target_mac_edit = QLineEdit()
        self.target_mac_edit.setPlaceholderText("Target MAC, e.g. 02:00:00:00:00:30")
        form.addRow("Target MAC:", self.target_mac_edit)

        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("Target IPv4, e.g. 10.77.0.30")
        form.addRow("Target IP:", self.target_ip_edit)

        self.relay_mac_edit = QLineEdit()
        self.relay_mac_edit.setPlaceholderText("Relay MAC, empty for a direct probe")
        form.addRow("Relay MAC:", self.relay_mac_edit)

        self.probes_spin = QSpinBox()
        self.probes_spin.setRange(1, MAX_PROBES)
        self.probes_spin.setValue(5)
        self.probes_spin.setSuffix(" probe(s)")
        form.addRow("Probes:", self.probes_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_mac_edit, self.source_ip_edit, self.target_mac_edit,
                       self.target_ip_edit, self.relay_mac_edit, self.probes_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> PrivateVlanBypassConfig:
        del count, interval  # the probe count is set in this panel
        return PrivateVlanBypassConfig(
            iface=iface,
            source_mac=self.source_mac_edit.text().strip(),
            source_ip=self.source_ip_edit.text().strip(),
            target_mac=self.target_mac_edit.text().strip(),
            target_ip=self.target_ip_edit.text().strip(),
            relay_mac=self.relay_mac_edit.text().strip(),
            probes=self.probes_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: PrivateVlanBypassConfig,
        stop_event: threading.Event,
        on_progress: Callable[[PrivateVlanBypassStats], None],
    ) -> PrivateVlanBypassStats:
        return run_private_vlan_bypass(config, stop_event, on_progress)

    def _format_status(self, stats: PrivateVlanBypassStats) -> str:
        return stats.status or f"Probes sent: {stats.probes}"
