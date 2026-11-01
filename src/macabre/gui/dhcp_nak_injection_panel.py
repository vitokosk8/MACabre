"""Panel for the DHCP NAK injection attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.dhcp_nak_injection import NakInjectionConfig, NakInjectionStats, run_nak_injection
from macabre.gui.base_panel import AttackPanel


class DhcpNakInjectionPanel(AttackPanel):
    title = "DHCP NAK Injection"
    description = (
        "Answers client lease renewals with a DHCPNAK in the legitimate server's name, so clients drop their "
        "configuration and restart. Needs the server's address and MAC. Can be limited to one client MAC. "
        "Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.server_ip_edit = QLineEdit()
        self.server_ip_edit.setPlaceholderText("Legitimate server address, e.g. 10.0.0.1")
        form.addRow("Server address:", self.server_ip_edit)

        self.server_mac_edit = QLineEdit()
        self.server_mac_edit.setPlaceholderText("Legitimate server MAC (required)")
        form.addRow("Server MAC:", self.server_mac_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Client MAC to refuse (optional; empty = all clients)")
        form.addRow("Target client:", self.target_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.server_ip_edit, self.server_mac_edit, self.target_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> NakInjectionConfig:
        del count, interval  # the attack runs until stopped, and answers as requests arrive
        return NakInjectionConfig(
            iface=iface,
            server_ip=self.server_ip_edit.text().strip(),
            server_mac=self.server_mac_edit.text().strip(),
            target_mac=self.target_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: NakInjectionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[NakInjectionStats], None],
    ) -> NakInjectionStats:
        return run_nak_injection(config, stop_event, on_progress)

    def _format_status(self, stats: NakInjectionStats) -> str:
        return stats.status or f"Requests seen: {stats.requests}, NAKs sent: {stats.naks}"
