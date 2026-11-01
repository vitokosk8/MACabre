"""Panel for the native VLAN abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.native_vlan_abuse import NativeVlanConfig, NativeVlanStats, run_native_vlan_abuse
from macabre.gui.base_panel import AttackPanel


class NativeVlanPanel(AttackPanel):
    title = "Native VLAN abuse"
    description = (
        "Sends untagged probes from a port on the native VLAN of its trunk. If the two ends of the "
        "trunk disagree about the native VLAN, the far end places these frames in its own native "
        "VLAN. This panel only sends the probes; check the far end to see where they land. "
        "Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.probe_edit = QLineEdit("192.0.2.1")
        form.addRow("Probe IP:", self.probe_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.probe_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> NativeVlanConfig:
        return NativeVlanConfig(
            iface=iface,
            probe_ip=self.probe_edit.text(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: NativeVlanConfig,
        stop_event: threading.Event,
        on_progress: Callable[[NativeVlanStats], None],
    ) -> NativeVlanStats:
        return run_native_vlan_abuse(config, stop_event, on_progress)

    def _format_status(self, stats: NativeVlanStats) -> str:
        return stats.status or f"Untagged probes sent: {stats.frames}"
