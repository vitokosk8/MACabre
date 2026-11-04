"""Panel for the IGMP leave spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.igmp_leave_spoofing import (
    MAX_LEAVES,
    IgmpLeaveSpoofingConfig,
    IgmpLeaveSpoofingStats,
    run_igmp_leave_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class IgmpLeaveSpoofingPanel(AttackPanel):
    title = "IGMP Leave Spoofing"
    description = (
        "Sends IGMPv2 leave messages for multicast groups this host never joined. A snooping switch that trusts "
        "leaves removes the group from the port they arrive on, which can cut off the other hosts behind it. "
        "Use only with authorization."
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

        self.groups_edit = QLineEdit()
        self.groups_edit.setPlaceholderText("Groups, comma separated, e.g. 239.1.2.3, 239.9.9.9")
        form.addRow("Groups:", self.groups_edit)

        self.leaves_spin = QSpinBox()
        self.leaves_spin.setRange(1, MAX_LEAVES)
        self.leaves_spin.setValue(1)
        self.leaves_spin.setSuffix(" leave(s) per group")
        form.addRow("Leaves:", self.leaves_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.source_ip_edit.setEnabled(enabled)
        self.groups_edit.setEnabled(enabled)
        self.leaves_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> IgmpLeaveSpoofingConfig:
        del count, interval  # this attack sends its leaves once per group
        groups = tuple(g.strip() for g in self.groups_edit.text().split(",") if g.strip())
        return IgmpLeaveSpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            groups=groups,
            source_ip=self.source_ip_edit.text().strip() or "0.0.0.0",
            leaves=self.leaves_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: IgmpLeaveSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[IgmpLeaveSpoofingStats], None],
    ) -> IgmpLeaveSpoofingStats:
        return run_igmp_leave_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: IgmpLeaveSpoofingStats) -> str:
        return stats.status or f"Leaves sent: {stats.leaves}"
