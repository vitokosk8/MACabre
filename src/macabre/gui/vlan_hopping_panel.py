"""Panel for the VLAN hopping attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QFormLayout, QLineEdit

from macabre.attacks.vlan_hopping import VlanHoppingConfig, VlanHoppingStats, run_vlan_hopping
from macabre.gui.base_panel import AttackPanel


class VlanHoppingPanel(AttackPanel):
    title = "VLAN hopping"
    description = (
        "Tags probe frames with a VLAN this port should not reach. Optionally sends a DTP "
        "advertisement first, to try to negotiate a trunk. The result depends on the switch: "
        "on an access port, tagged frames should be dropped. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.vlan_edit = QLineEdit()
        self.vlan_edit.setPlaceholderText("Target VLAN, 1 to 4094")
        self.probe_edit = QLineEdit("192.0.2.1")
        self.negotiate_check = QCheckBox("Send a DTP advertisement first")
        self.negotiate_check.setChecked(True)
        form.addRow("Target VLAN:", self.vlan_edit)
        form.addRow("Probe IP:", self.probe_edit)
        form.addRow("", self.negotiate_check)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.vlan_edit.setEnabled(enabled)
        self.probe_edit.setEnabled(enabled)
        self.negotiate_check.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> VlanHoppingConfig:
        text = self.vlan_edit.text().strip()
        if not text.isdigit():
            raise ValueError("The target VLAN must be a number between 1 and 4094.")
        return VlanHoppingConfig(
            iface=iface,
            target_vlan=int(text),
            probe_ip=self.probe_edit.text(),
            negotiate=self.negotiate_check.isChecked(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: VlanHoppingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[VlanHoppingStats], None],
    ) -> VlanHoppingStats:
        return run_vlan_hopping(config, stop_event, on_progress)

    def _format_status(self, stats: VlanHoppingStats) -> str:
        return stats.status or f"DTP sent: {stats.dtp_sent}, probes sent: {stats.frames}"
