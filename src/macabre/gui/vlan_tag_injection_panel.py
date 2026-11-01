"""Panel for the VLAN tag injection attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.vlan_tag_injection import (
    VlanTagInjectionConfig,
    VlanTagInjectionStats,
    run_vlan_tag_injection,
)
from macabre.gui.base_panel import AttackPanel


class VlanTagInjectionPanel(AttackPanel):
    title = "VLAN tag injection"
    description = (
        "Sends frames that carry an 802.1Q tag with the VLAN ID, priority (PCP) and DEI bit you choose, "
        "from a port that should carry untagged frames. Access ports should drop them, and a port that "
        "accepts them may keep or rewrite the fields. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.vlan_edit = QLineEdit()
        self.vlan_edit.setPlaceholderText("VLAN ID, 1 to 4094")
        self.pcp_edit = QLineEdit("0")
        self.pcp_edit.setPlaceholderText("Priority (PCP), 0 to 7")
        self.dei_edit = QLineEdit("0")
        self.dei_edit.setPlaceholderText("DEI, 0 or 1")
        self.probe_edit = QLineEdit("192.0.2.1")
        form.addRow("VLAN ID:", self.vlan_edit)
        form.addRow("Priority (PCP):", self.pcp_edit)
        form.addRow("DEI:", self.dei_edit)
        form.addRow("Probe IP:", self.probe_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.vlan_edit, self.pcp_edit, self.dei_edit, self.probe_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> VlanTagInjectionConfig:
        vlan = self.vlan_edit.text().strip()
        pcp = self.pcp_edit.text().strip()
        dei = self.dei_edit.text().strip()
        if not vlan.isdigit() or not pcp.isdigit() or not dei.isdigit():
            raise ValueError("VLAN ID, priority and DEI must be whole numbers.")
        return VlanTagInjectionConfig(
            iface=iface,
            vlan=int(vlan),
            pcp=int(pcp),
            dei=int(dei),
            probe_ip=self.probe_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: VlanTagInjectionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[VlanTagInjectionStats], None],
    ) -> VlanTagInjectionStats:
        return run_vlan_tag_injection(config, stop_event, on_progress)

    def _format_status(self, stats: VlanTagInjectionStats) -> str:
        return stats.status or f"Tagged frames sent: {stats.frames}"
