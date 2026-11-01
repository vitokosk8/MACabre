"""Panel for the ARP-based gateway impersonation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QFormLayout, QLineEdit

from macabre.attacks.arp_gateway_impersonation import (
    GatewayImpersonationConfig,
    GatewayImpersonationStats,
    run_gateway_impersonation,
)
from macabre.gui.base_panel import AttackPanel


class ArpGatewayImpersonationPanel(AttackPanel):
    title = "ARP-based gateway impersonation"
    description = (
        "Claims the default gateway's IP for the victims you list, so their traffic leaving the "
        "subnet is sent to this host. Optionally enables IP forwarding on this host while it runs, "
        "so the traffic is passed on. Forwarding is restored when the attack stops. Use only with "
        "authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.gateway_edit = QLineEdit()
        self.gateway_edit.setPlaceholderText("Gateway IP, for example 192.168.1.1")
        self.victims_edit = QLineEdit()
        self.victims_edit.setPlaceholderText("Victim IPs, separated by commas or spaces")
        self.forwarding_check = QCheckBox("Enable IP forwarding while the attack runs")
        self.forwarding_check.setChecked(True)
        form.addRow("Gateway IP:", self.gateway_edit)
        form.addRow("Victims:", self.victims_edit)
        form.addRow("", self.forwarding_check)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.gateway_edit.setEnabled(enabled)
        self.victims_edit.setEnabled(enabled)
        self.forwarding_check.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> GatewayImpersonationConfig:
        return GatewayImpersonationConfig(
            iface=iface,
            gateway_ip=self.gateway_edit.text(),
            victims=self.victims_edit.text(),
            count=count,
            interval=interval,
            enable_forwarding=self.forwarding_check.isChecked(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: GatewayImpersonationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[GatewayImpersonationStats], None],
    ) -> GatewayImpersonationStats:
        return run_gateway_impersonation(config, stop_event, on_progress)

    def _format_status(self, stats: GatewayImpersonationStats) -> str:
        text = f"Rounds: {stats.rounds}, replies sent: {stats.frames}, victims: {stats.victims}"
        if stats.forwarding_active:
            text += ", forwarding active"
        if stats.status:
            text += f". {stats.status}"
        return text
