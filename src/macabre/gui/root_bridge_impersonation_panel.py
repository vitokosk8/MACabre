"""Panel for the root bridge impersonation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace

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


class StpPathCostManipulationPanel(RootBridgeImpersonationPanel):
    """The same attack, presented as a path cost change: the advertised root path cost decides the root port."""

    title = "STP Path Cost Manipulation"
    description = (
        "Advertises a root path cost lower than the real path on this port, so a switch may choose this port "
        "as its root port and send traffic toward it. Uses the impersonation sender with the real root's ID; "
        "set the cost to decide the port. Use only with authorization."
    )


class StpPriorityManipulationPanel(RootBridgeImpersonationPanel):
    """The same sender, with a bridge priority that can win the designated port of a shared segment."""

    title = "STP Priority Manipulation"
    description = (
        "Advertises the real root's ID and a bridge priority lower than the other bridge on a shared segment, "
        "with the same root path cost. The lower priority can take the designated port of that segment and block "
        "the switch. Enter the priority and MAC of the real root. Use only with authorization."
    )

    def _add_extra_controls(self, form: QFormLayout) -> None:
        super()._add_extra_controls(form)
        self.bridge_priority_spin = QSpinBox()
        self.bridge_priority_spin.setRange(0, MAX_PRIORITY)
        self.bridge_priority_spin.setSingleStep(PRIORITY_STEP)
        self.bridge_priority_spin.setValue(0)
        self.bridge_priority_spin.setToolTip("Priority of this bridge's ID (multiple of 4096). Lower wins the designated port.")
        form.addRow("Bridge priority:", self.bridge_priority_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        super()._set_extra_controls_enabled(enabled)
        self.bridge_priority_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RootBridgeImpersonationConfig:
        config = super()._make_config(iface, count, interval, dry_run)
        return replace(config, bridge_priority=self.bridge_priority_spin.value())
