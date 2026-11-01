"""Panel for the CDP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.cdp_spoofing import CdpSpoofingConfig, CdpSpoofingStats, DEFAULT_INTERVAL, run_cdp_spoofing
from macabre.gui.base_panel import AttackPanel


class CdpSpoofingPanel(AttackPanel):
    title = "CDP Spoofing"
    description = (
        "Advertises a forged Cisco device, with the identity, port, management address and native VLAN you "
        "choose, to the CDP neighbors on the segment. Receivers that keep CDP neighbors store it. Use only "
        "with authorization."
    )
    default_interval = DEFAULT_INTERVAL

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.device_edit = QLineEdit("MACabre-SW")
        form.addRow("Device ID:", self.device_edit)

        self.port_edit = QLineEdit("FastEthernet0/1")
        form.addRow("Port ID:", self.port_edit)

        self.platform_edit = QLineEdit("cisco WS-C2960")
        form.addRow("Platform:", self.platform_edit)

        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("Management address (optional), e.g. 10.0.0.9")
        form.addRow("Address:", self.address_edit)

        self.vlan_spin = QSpinBox()
        self.vlan_spin.setRange(0, 4094)
        self.vlan_spin.setValue(0)
        self.vlan_spin.setSpecialValueText("none")
        self.vlan_spin.setToolTip("Native VLAN advertised. 'none' leaves the TLV out.")
        form.addRow("Native VLAN:", self.vlan_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.device_edit, self.port_edit, self.platform_edit, self.address_edit, self.vlan_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> CdpSpoofingConfig:
        return CdpSpoofingConfig(
            iface=iface,
            device_id=self.device_edit.text().strip(),
            port_id=self.port_edit.text().strip(),
            platform=self.platform_edit.text().strip() or "cisco",
            address=self.address_edit.text().strip(),
            native_vlan=self.vlan_spin.value(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: CdpSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[CdpSpoofingStats], None],
    ) -> CdpSpoofingStats:
        return run_cdp_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: CdpSpoofingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
