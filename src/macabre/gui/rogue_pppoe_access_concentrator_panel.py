"""Panel for the rogue PPPoE access concentrator attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.rogue_pppoe_access_concentrator import (
    RoguePppoeAcConfig,
    RoguePppoeAcStats,
    run_rogue_pppoe_ac,
)
from macabre.gui.base_panel import AttackPanel


class RoguePppoeAccessConcentratorPanel(AttackPanel):
    title = "Rogue PPPoE Access Concentrator"
    description = (
        "Answers PPPoE discovery (PADI) with an offer from this host, and completes the session with any client "
        "that chooses it. A client takes the first offer it receives, so this works best when the legitimate "
        "concentrator is slow or down. Runs until stopped. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.ac_mac_edit = QLineEdit()
        self.ac_mac_edit.setPlaceholderText("This concentrator's MAC, e.g. 02:00:00:00:00:44")
        form.addRow("AC MAC:", self.ac_mac_edit)

        self.ac_name_edit = QLineEdit("MACabre-AC")
        self.ac_name_edit.setToolTip("AC-Name tag sent in every offer and session acknowledgement.")
        form.addRow("AC name:", self.ac_name_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.ac_mac_edit.setEnabled(enabled)
        self.ac_name_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RoguePppoeAcConfig:
        del count, interval  # the concentrator runs until stopped, and answers as discovery arrives
        return RoguePppoeAcConfig(
            iface=iface,
            ac_mac=self.ac_mac_edit.text().strip(),
            ac_name=self.ac_name_edit.text().strip() or "MACabre-AC",
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RoguePppoeAcConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RoguePppoeAcStats], None],
    ) -> RoguePppoeAcStats:
        return run_rogue_pppoe_ac(config, stop_event, on_progress)

    def _format_status(self, stats: RoguePppoeAcStats) -> str:
        return stats.status or f"PADI: {stats.padi}, PADO sent: {stats.pado}, PADR: {stats.padr}, PADS sent: {stats.pads}"
