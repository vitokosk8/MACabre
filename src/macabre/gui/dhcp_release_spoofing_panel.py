"""Panel for the DHCP release spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.dhcp_release_spoofing import (
    MAX_RELEASES,
    ReleaseSpoofingConfig,
    ReleaseSpoofingStats,
    run_release_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class DhcpReleaseSpoofingPanel(AttackPanel):
    title = "DHCP Release Spoofing"
    description = (
        "Sends DHCPRELEASE messages for a client's lease, in the client's name. "
        "The server frees the address, and it may be given to another host. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.client_mac_edit = QLineEdit()
        self.client_mac_edit.setPlaceholderText("Victim MAC, e.g. 02:00:00:00:00:50")
        form.addRow("Client MAC:", self.client_mac_edit)

        self.client_ip_edit = QLineEdit()
        self.client_ip_edit.setPlaceholderText("Leased address, e.g. 10.99.0.105")
        form.addRow("Client IP:", self.client_ip_edit)

        self.server_ip_edit = QLineEdit()
        self.server_ip_edit.setPlaceholderText("DHCP server, e.g. 10.99.0.1")
        form.addRow("Server IP:", self.server_ip_edit)

        self.server_mac_edit = QLineEdit()
        self.server_mac_edit.setPlaceholderText("Optional server MAC; empty = broadcast")
        form.addRow("Server MAC:", self.server_mac_edit)

        self.releases_spin = QSpinBox()
        self.releases_spin.setRange(1, MAX_RELEASES)
        self.releases_spin.setValue(1)
        self.releases_spin.setSuffix(" release(s)")
        form.addRow("Releases:", self.releases_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.client_mac_edit, self.client_ip_edit, self.server_ip_edit,
                       self.server_mac_edit, self.releases_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ReleaseSpoofingConfig:
        del count, interval  # releases are sent once each
        return ReleaseSpoofingConfig(
            iface=iface,
            client_mac=self.client_mac_edit.text().strip(),
            client_ip=self.client_ip_edit.text().strip(),
            server_ip=self.server_ip_edit.text().strip(),
            server_mac=self.server_mac_edit.text().strip(),
            releases=self.releases_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ReleaseSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ReleaseSpoofingStats], None],
    ) -> ReleaseSpoofingStats:
        return run_release_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: ReleaseSpoofingStats) -> str:
        return stats.status or f"Releases sent: {stats.releases}"
