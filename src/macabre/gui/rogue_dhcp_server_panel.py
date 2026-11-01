"""Panel for the rogue DHCP server attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.rogue_dhcp_server import RogueDhcpConfig, RogueDhcpStats, run_rogue_dhcp
from macabre.gui.base_panel import AttackPanel


class RogueDhcpServerPanel(AttackPanel):
    title = "Rogue DHCP Server"
    description = (
        "Answers DHCP clients with an offer that names this host as gateway and DNS server, and acknowledges "
        "their requests. A client takes the first offer it receives, so this works best when the legitimate "
        "server is slow, down or out of addresses. Runs until stopped. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.server_ip_edit = QLineEdit()
        self.server_ip_edit.setPlaceholderText("This server's address, e.g. 10.0.0.250")
        form.addRow("Server address:", self.server_ip_edit)

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

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.server_ip_edit, self.offer_ip_edit, self.subnet_edit,
                       self.router_edit, self.dns_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RogueDhcpConfig:
        del count, interval  # the server runs until stopped, and answers as requests arrive
        return RogueDhcpConfig(
            iface=iface,
            server_ip=self.server_ip_edit.text().strip(),
            offer_ip=self.offer_ip_edit.text().strip(),
            subnet_mask=self.subnet_edit.text().strip() or "255.255.255.0",
            router=self.router_edit.text().strip(),
            dns=self.dns_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RogueDhcpConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RogueDhcpStats], None],
    ) -> RogueDhcpStats:
        return run_rogue_dhcp(config, stop_event, on_progress)

    def _format_status(self, stats: RogueDhcpStats) -> str:
        return stats.status or f"Offers sent: {stats.offers}, acks sent: {stats.acks}"
