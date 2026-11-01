"""Panel for the switch spoofing (DTP) attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.switch_spoofing import (
    SwitchSpoofingConfig,
    SwitchSpoofingStats,
    run_switch_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class SwitchSpoofingPanel(AttackPanel):
    title = "Switch spoofing (DTP)"
    description = (
        "Sends DTP trunk advertisements from this port. A switch port in a dynamic mode that accepts "
        "the negotiation can become a trunk, and then carries the traffic of every allowed VLAN. "
        "Whether a switch forms the trunk depends on its own configuration. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("VTP domain name (optional, up to 32 bytes)")
        form.addRow("VTP domain:", self.domain_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.domain_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> SwitchSpoofingConfig:
        return SwitchSpoofingConfig(
            iface=iface,
            domain=self.domain_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: SwitchSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[SwitchSpoofingStats], None],
    ) -> SwitchSpoofingStats:
        return run_switch_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: SwitchSpoofingStats) -> str:
        return stats.status or f"DTP frames sent: {stats.frames}"
