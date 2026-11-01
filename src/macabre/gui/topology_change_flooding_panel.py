"""Panel for the topology change flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.bpdu_spoofing import MAX_PRIORITY, PRIORITY_STEP
from macabre.attacks.topology_change_flooding import (
    TopologyChangeFloodingConfig,
    TopologyChangeFloodingStats,
    run_topology_change_flooding,
)
from macabre.gui.base_panel import AttackPanel


class TopologyChangeFloodingPanel(AttackPanel):
    title = "Topology Change Flooding"
    description = (
        "Sends BPDUs with the real root's ID and the topology change flag set in every frame. The attacker "
        "must win the root port for the flag to count. A switch that accepts it flushes its MAC table, "
        "which floods traffic. Enter the priority and MAC of the real root. Use only with authorization."
    )
    default_interval = 0.5

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.root_priority_spin = QSpinBox()
        self.root_priority_spin.setRange(0, MAX_PRIORITY)
        self.root_priority_spin.setSingleStep(PRIORITY_STEP)
        self.root_priority_spin.setValue(32768)
        self.root_priority_spin.setToolTip("Priority of the real root (multiple of 4096).")
        form.addRow("Real root priority:", self.root_priority_spin)

        self.root_mac_edit = QLineEdit()
        self.root_mac_edit.setPlaceholderText("Real root MAC (required)")
        form.addRow("Real root MAC:", self.root_mac_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.root_priority_spin.setEnabled(enabled)
        self.root_mac_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> TopologyChangeFloodingConfig:
        return TopologyChangeFloodingConfig(
            iface=iface,
            root_priority=self.root_priority_spin.value(),
            root_mac=self.root_mac_edit.text().strip(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: TopologyChangeFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[TopologyChangeFloodingStats], None],
    ) -> TopologyChangeFloodingStats:
        return run_topology_change_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: TopologyChangeFloodingStats) -> str:
        return stats.status or f"BPDUs sent: {stats.frames}"
