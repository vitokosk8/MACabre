"""Panel for the IGMP snooping table exhaustion attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.igmp_snooping_exhaustion import (
    MAX_GROUPS,
    IgmpSnoopingExhaustionConfig,
    IgmpSnoopingExhaustionStats,
    run_igmp_snooping_exhaustion,
)
from macabre.gui.base_panel import AttackPanel


class IgmpSnoopingExhaustionPanel(AttackPanel):
    title = "IGMP Snooping Table Exhaustion"
    description = (
        "Sends one IGMPv2 membership report for each group in a range, from this host. A snooping switch "
        "has a fixed group table; when reports fill it, it cannot learn legitimate groups from other ports. "
        "Use only with authorization, and expect the switch to drop groups for other hosts while it runs."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Sender MAC, e.g. 02:00:00:00:00:20")
        form.addRow("Source MAC:", self.source_edit)

        self.source_ip_edit = QLineEdit("0.0.0.0")
        self.source_ip_edit.setToolTip("Sender IPv4 address, or 0.0.0.0 for an unnumbered host.")
        form.addRow("Source IP:", self.source_ip_edit)

        self.base_edit = QLineEdit("239.100.0.1")
        self.base_edit.setToolTip("First group of the range. The range must stay inside 239.0.0.0/8.")
        form.addRow("First group:", self.base_edit)

        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, MAX_GROUPS)
        self.count_spin.setValue(4200)
        self.count_spin.setSuffix(" group(s)")
        self.count_spin.setToolTip("One report per group. The kernel default table holds 4096 groups.")
        form.addRow("Groups:", self.count_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.source_ip_edit.setEnabled(enabled)
        self.base_edit.setEnabled(enabled)
        self.count_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> IgmpSnoopingExhaustionConfig:
        del count, interval  # this attack sends one report per group in the range
        return IgmpSnoopingExhaustionConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            base_group=self.base_edit.text().strip(),
            count=self.count_spin.value(),
            source_ip=self.source_ip_edit.text().strip() or "0.0.0.0",
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: IgmpSnoopingExhaustionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[IgmpSnoopingExhaustionStats], None],
    ) -> IgmpSnoopingExhaustionStats:
        return run_igmp_snooping_exhaustion(config, stop_event, on_progress)

    def _format_status(self, stats: IgmpSnoopingExhaustionStats) -> str:
        return stats.status or f"Reports sent: {stats.reports}"
