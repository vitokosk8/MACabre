"""Panel for the DHCPv6 prefix delegation abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.dhcpv6_prefix_delegation_abuse import (
    MAX_PLEN,
    MIN_PLEN,
    Dhcpv6PrefixDelegationAbuseConfig,
    Dhcpv6PrefixDelegationAbuseStats,
    run_dhcpv6_prefix_delegation_abuse,
)
from macabre.gui.base_panel import AttackPanel


class Dhcpv6PrefixDelegationAbusePanel(AttackPanel):
    title = "DHCPv6 Prefix Delegation Abuse"
    description = (
        "Sends DHCPv6 prefix requests (IA_PD) with random client identities and completes them, so the "
        "delegating server's prefix pool fills and legitimate requesters get none. Use only with authorization."
    )
    default_interval = 0.05
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.count_spin = QSpinBox()
        self.count_spin.setRange(0, 1_000_000)
        self.count_spin.setSpecialValueText("until stopped")
        form.addRow("Requests:", self.count_spin)

        self.plen_spin = QSpinBox()
        self.plen_spin.setRange(MIN_PLEN, MAX_PLEN)
        self.plen_spin.setValue(56)
        self.plen_spin.setPrefix("/")
        self.plen_spin.setToolTip("Prefix length asked for. The server decides what it delegates.")
        form.addRow("Prefix length:", self.plen_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.count_spin, self.plen_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> Dhcpv6PrefixDelegationAbuseConfig:
        return Dhcpv6PrefixDelegationAbuseConfig(
            iface=iface,
            count=count,
            interval=interval,
            plen=self.plen_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: Dhcpv6PrefixDelegationAbuseConfig,
        stop_event: threading.Event,
        on_progress: Callable[[Dhcpv6PrefixDelegationAbuseStats], None],
    ) -> Dhcpv6PrefixDelegationAbuseStats:
        return run_dhcpv6_prefix_delegation_abuse(config, stop_event, on_progress)

    def _format_status(self, stats: Dhcpv6PrefixDelegationAbuseStats) -> str:
        return stats.status or f"Prefixes held: {stats.bindings} (requests sent: {stats.requests})"
