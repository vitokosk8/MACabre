"""Panel for the DHCP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.dhcp_spoofing import DhcpSpoofingConfig, DhcpSpoofingStats, run_dhcp_spoofing
from macabre.gui.base_panel import AttackPanel


class DhcpSpoofingPanel(AttackPanel):
    title = "DHCP Spoofing"
    description = (
        "Answers DHCP clients in the name of the legitimate server, using its address and MAC, with a gateway "
        "and DNS server you choose. Can be limited to one client MAC. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.server_ip_edit = QLineEdit()
        self.server_ip_edit.setPlaceholderText("Legitimate server address, e.g. 10.0.0.1")
        form.addRow("Server address:", self.server_ip_edit)

        self.server_mac_edit = QLineEdit()
        self.server_mac_edit.setPlaceholderText("Legitimate server MAC (required)")
        form.addRow("Server MAC:", self.server_mac_edit)

        self.offer_ip_edit = QLineEdit()
        self.offer_ip_edit.setPlaceholderText("Address to offer, e.g. 10.0.0.200")
        form.addRow("Offered address:", self.offer_ip_edit)

        self.subnet_edit = QLineEdit("255.255.255.0")
        form.addRow("Subnet mask:", self.subnet_edit)

        self.router_edit = QLineEdit()
        self.router_edit.setPlaceholderText("Gateway offered (optional; empty = server address)")
        form.addRow("Router:", self.router_edit)

        self.dns_edit = QLineEdit()
        self.dns_edit.setPlaceholderText("DNS offered (optional; empty = server address)")
        form.addRow("DNS:", self.dns_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Client MAC to answer (optional; empty = all clients)")
        form.addRow("Target client:", self.target_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.server_ip_edit, self.server_mac_edit, self.offer_ip_edit,
                       self.subnet_edit, self.router_edit, self.dns_edit, self.target_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DhcpSpoofingConfig:
        del count, interval  # the spoofer runs until stopped, and answers as requests arrive
        return DhcpSpoofingConfig(
            iface=iface,
            server_ip=self.server_ip_edit.text().strip(),
            server_mac=self.server_mac_edit.text().strip(),
            offer_ip=self.offer_ip_edit.text().strip(),
            subnet_mask=self.subnet_edit.text().strip() or "255.255.255.0",
            router=self.router_edit.text().strip(),
            dns=self.dns_edit.text().strip(),
            target_mac=self.target_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: DhcpSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[DhcpSpoofingStats], None],
    ) -> DhcpSpoofingStats:
        return run_dhcp_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: DhcpSpoofingStats) -> str:
        return stats.status or f"Offers sent: {stats.offers}, acks sent: {stats.acks}"
