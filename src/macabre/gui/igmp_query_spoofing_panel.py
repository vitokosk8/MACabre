"""Panel for the IGMP query spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.igmp_query_spoofing import (
    GENERAL_GROUP,
    MAX_RESPONSE,
    IgmpQuerySpoofingConfig,
    IgmpQuerySpoofingStats,
    run_igmp_query_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class IgmpQuerySpoofingPanel(AttackPanel):
    title = "IGMP Query Spoofing"
    description = (
        "Sends IGMPv2 membership queries from this port, with a source address you choose. Hosts answer with "
        "reports, and switches that elect a querier by lowest address may take this port as the querier. Leave "
        "the group at 0.0.0.0 for a general query. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_mac_edit = QLineEdit()
        self.source_mac_edit.setPlaceholderText("Sender MAC, e.g. 02:00:00:00:00:20")
        form.addRow("Source MAC:", self.source_mac_edit)

        self.source_ip_edit = QLineEdit("10.0.0.1")
        self.source_ip_edit.setToolTip("Source IPv4 address of the queries. Lower than the real querier wins the election.")
        form.addRow("Source IP:", self.source_ip_edit)

        self.group_edit = QLineEdit(GENERAL_GROUP)
        self.group_edit.setToolTip("0.0.0.0 for a general query, or a multicast group for a group-specific query.")
        form.addRow("Group:", self.group_edit)

        self.max_response_spin = QSpinBox()
        self.max_response_spin.setRange(0, MAX_RESPONSE)
        self.max_response_spin.setValue(100)
        self.max_response_spin.setSuffix(" (tenths of a second)")
        self.max_response_spin.setToolTip("IGMPv2 max response time in the query.")
        form.addRow("Max response:", self.max_response_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_mac_edit.setEnabled(enabled)
        self.source_ip_edit.setEnabled(enabled)
        self.group_edit.setEnabled(enabled)
        self.max_response_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> IgmpQuerySpoofingConfig:
        return IgmpQuerySpoofingConfig(
            iface=iface,
            source_mac=self.source_mac_edit.text().strip(),
            source_ip=self.source_ip_edit.text().strip(),
            group=self.group_edit.text().strip() or GENERAL_GROUP,
            max_response=self.max_response_spin.value(),
            queries=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: IgmpQuerySpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[IgmpQuerySpoofingStats], None],
    ) -> IgmpQuerySpoofingStats:
        return run_igmp_query_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: IgmpQuerySpoofingStats) -> str:
        return stats.status or f"IGMP queries sent: {stats.queries}"
