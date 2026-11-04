"""Panel for the DHCP option manipulation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.dhcp_option_manipulation import (
    DhcpOptionManipulationConfig,
    run_dhcp_option_manipulation,
)
from macabre.attacks.dhcp_spoofing import DhcpSpoofingStats
from macabre.gui.base_panel import AttackPanel


class DhcpOptionManipulationPanel(AttackPanel):
    title = "DHCP Option Manipulation"
    description = (
        "Answers clients in the legitimate server's name with chosen options: proxy (WPAD), "
        "static routes, search domains, NTP and domain. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.server_ip_edit = self._line(form, "Server IP:", "Legitimate server, e.g. 10.99.0.1")
        self.server_mac_edit = self._line(form, "Server MAC:", "Legitimate server MAC")
        self.offer_ip_edit = self._line(form, "Offered IP:", "Address offered, e.g. 10.99.0.150")
        self.router_edit = self._line(form, "Router:", "Optional; empty = server IP")
        self.dns_edit = self._line(form, "DNS:", "Optional; empty = server IP")
        self.target_edit = self._line(form, "Target MAC:", "Optional; empty = every client")
        self.domain_edit = self._line(form, "Domain name (15):", "e.g. lab.example")
        self.search_edit = self._line(form, "Search domains (119):", "e.g. lab.example, corp.example")
        self.ntp_edit = self._line(form, "NTP server (42):", "e.g. 10.99.0.9")
        self.routes_edit = self._line(form, "Static routes (121):", "e.g. 198.51.100.0/24=10.99.0.254")
        self.wpad_edit = self._line(form, "WPAD URL (252):", "e.g. http://10.99.0.5/wpad.dat")

    def _line(self, form: QFormLayout, label: str, placeholder: str) -> QLineEdit:
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        form.addRow(label, edit)
        return edit

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for edit in (self.server_ip_edit, self.server_mac_edit, self.offer_ip_edit, self.router_edit,
                     self.dns_edit, self.target_edit, self.domain_edit, self.search_edit,
                     self.ntp_edit, self.routes_edit, self.wpad_edit):
            edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DhcpOptionManipulationConfig:
        del count, interval
        return DhcpOptionManipulationConfig(
            iface=iface,
            server_ip=self.server_ip_edit.text().strip(),
            server_mac=self.server_mac_edit.text().strip(),
            offer_ip=self.offer_ip_edit.text().strip(),
            router=self.router_edit.text().strip(),
            dns=self.dns_edit.text().strip(),
            target_mac=self.target_edit.text().strip(),
            domain_name=self.domain_edit.text().strip(),
            domain_search=self.search_edit.text().strip(),
            ntp_server=self.ntp_edit.text().strip(),
            classless_routes=self.routes_edit.text().strip(),
            wpad_url=self.wpad_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: DhcpOptionManipulationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[DhcpSpoofingStats], None],
    ) -> DhcpSpoofingStats:
        return run_dhcp_option_manipulation(config, stop_event, on_progress)

    def _format_status(self, stats: DhcpSpoofingStats) -> str:
        return stats.status or f"Offers: {stats.offers}, acknowledgments: {stats.acks}"
