"""Panel for the ARP table exhaustion attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.arp_table_exhaustion import (
    MAX_RATE,
    ArpTableExhaustionConfig,
    ArpTableExhaustionStats,
    run_arp_table_exhaustion,
)
from macabre.gui.base_panel import AttackPanel


class ArpTableExhaustionPanel(AttackPanel):
    title = "ARP Table Exhaustion"
    description = (
        "Sends ARP requests for the victim's address from many new fake senders, so the victim's neighbor "
        "table fills up. The audit then checks whether a legitimate entry, such as the gateway, survives. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.victim_edit = QLineEdit()
        self.victim_edit.setPlaceholderText("Victim IP, e.g. 10.77.0.10")
        form.addRow("Victim IP:", self.victim_edit)

        self.subnet_edit = QLineEdit()
        self.subnet_edit.setPlaceholderText("Fake sender subnet, e.g. 10.77.0.128/25")
        form.addRow("Sender subnet:", self.subnet_edit)

        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(10)
        self.rate_spin.setSuffix(" requests/s")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.victim_edit.setEnabled(enabled)
        self.subnet_edit.setEnabled(enabled)
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ArpTableExhaustionConfig:
        del interval  # the rate sets the timing for this attack
        return ArpTableExhaustionConfig(
            iface=iface,
            victim_ip=self.victim_edit.text().strip(),
            subnet=self.subnet_edit.text().strip(),
            rate=float(self.rate_spin.value()),
            count=count,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ArpTableExhaustionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ArpTableExhaustionStats], None],
    ) -> ArpTableExhaustionStats:
        return run_arp_table_exhaustion(config, stop_event, on_progress)

    def _format_status(self, stats: ArpTableExhaustionStats) -> str:
        return stats.status or f"Requests sent: {stats.requests}"
