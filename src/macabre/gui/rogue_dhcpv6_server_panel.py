"""Panel for the rogue DHCPv6 server attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.rogue_dhcpv6_server import (
    MAX_PREFERENCE,
    RogueDhcpv6Config,
    RogueDhcpv6Stats,
    run_rogue_dhcpv6,
)
from macabre.gui.base_panel import AttackPanel


class RogueDhcpv6ServerPanel(AttackPanel):
    title = "Rogue DHCPv6 Server"
    description = (
        "Answers IPv6 clients' SOLICIT and REQUEST messages with this host's DNS servers and search domains. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.server_mac_edit = self._line(form, "Server MAC:", "This host's MAC, e.g. 02:00:00:00:00:01")
        self.server_ll_edit = self._line(form, "Server link-local:", "e.g. fe80::1")
        self.offer_edit = self._line(form, "Offered IPv6:", "e.g. 2001:db8::150")
        self.dns_edit = self._line(form, "DNS servers:", "Optional, comma-separated; empty = server address")
        self.domains_edit = self._line(form, "Search domains:", "Optional, e.g. lab.example")
        self.target_edit = self._line(form, "Target MAC:", "Optional; empty = every client")

        self.preference_spin = QSpinBox()
        self.preference_spin.setRange(0, MAX_PREFERENCE)
        self.preference_spin.setValue(MAX_PREFERENCE)
        form.addRow("Preference:", self.preference_spin)

    def _line(self, form: QFormLayout, label: str, placeholder: str) -> QLineEdit:
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        form.addRow(label, edit)
        return edit

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.server_mac_edit, self.server_ll_edit, self.offer_edit,
                       self.dns_edit, self.domains_edit, self.target_edit, self.preference_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RogueDhcpv6Config:
        del count, interval
        return RogueDhcpv6Config(
            iface=iface,
            server_mac=self.server_mac_edit.text().strip(),
            server_ll=self.server_ll_edit.text().strip(),
            offer_ip6=self.offer_edit.text().strip(),
            dns=self.dns_edit.text().strip(),
            domains=self.domains_edit.text().strip(),
            preference=self.preference_spin.value(),
            target_mac=self.target_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RogueDhcpv6Config,
        stop_event: threading.Event,
        on_progress: Callable[[RogueDhcpv6Stats], None],
    ) -> RogueDhcpv6Stats:
        return run_rogue_dhcpv6(config, stop_event, on_progress)

    def _format_status(self, stats: RogueDhcpv6Stats) -> str:
        return stats.status or f"Advertises: {stats.advertises}, replies: {stats.replies}"
