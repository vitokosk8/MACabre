"""Panel for the root bridge impersonation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.bpdu_spoofing import MAX_PATH_COST, MAX_PRIORITY, PRIORITY_STEP
from macabre.attacks.root_bridge_impersonation import (
    RootBridgeImpersonationConfig,
    RootBridgeImpersonationStats,
    run_root_bridge_impersonation,
)
from macabre.gui.base_panel import AttackPanel


class RootBridgeImpersonationPanel(AttackPanel):
    title = "Root Bridge Impersonation"
    description = (
        "Sends BPDUs that carry the real root's bridge ID, copied from the root's own BPDUs. The root "
        "looks unchanged, but a switch may route toward it through this port. Enter the priority and MAC "
        "of the real root. The advertised root path cost decides whether this port becomes the root "
        "port. Use only with authorization."
    )
    default_interval = 2.0

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

        self.path_cost_spin = QSpinBox()
        self.path_cost_spin.setRange(0, min(MAX_PATH_COST, 2**31 - 1))
        self.path_cost_spin.setValue(0)
        self.path_cost_spin.setToolTip(
            "Root path cost advertised on this port. A lower cost than the real path wins the root port; "
            "a higher cost leaves the real path in place."
        )
        form.addRow("Root path cost:", self.path_cost_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.root_priority_spin.setEnabled(enabled)
        self.root_mac_edit.setEnabled(enabled)
        self.path_cost_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RootBridgeImpersonationConfig:
        return RootBridgeImpersonationConfig(
            iface=iface,
            root_priority=self.root_priority_spin.value(),
            root_mac=self.root_mac_edit.text().strip(),
            root_path_cost=self.path_cost_spin.value(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RootBridgeImpersonationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RootBridgeImpersonationStats], None],
    ) -> RootBridgeImpersonationStats:
        return run_root_bridge_impersonation(config, stop_event, on_progress)

    def _format_status(self, stats: RootBridgeImpersonationStats) -> str:
        return stats.status or f"BPDUs sent: {stats.frames}"
