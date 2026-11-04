"""Panel for the proxy ARP probe."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.proxy_arp_abuse import (
    ProxyArpProbeConfig,
    ProxyArpProbeStats,
    run_proxy_arp_probe,
)
from macabre.gui.base_panel import AttackPanel


class ProxyArpAbusePanel(AttackPanel):
    title = "Proxy ARP Abuse"
    description = (
        "Asks for addresses on other subnets from this segment, and records which ones a router answers for "
        "with its own MAC. Answers mean the router proxies ARP for networks it should not. Sends requests only. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.sender_edit = QLineEdit()
        self.sender_edit.setPlaceholderText("Your IP on this segment, e.g. 10.1.0.30")
        form.addRow("Sender IP:", self.sender_edit)

        self.prefix_spin = QSpinBox()
        self.prefix_spin.setRange(1, 30)
        self.prefix_spin.setValue(24)
        self.prefix_spin.setPrefix("/")
        form.addRow("Segment prefix:", self.prefix_spin)

        self.targets_edit = QLineEdit()
        self.targets_edit.setPlaceholderText("Addresses outside the segment, comma separated, e.g. 10.2.0.50")
        form.addRow("Targets:", self.targets_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.sender_edit.setEnabled(enabled)
        self.prefix_spin.setEnabled(enabled)
        self.targets_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> ProxyArpProbeConfig:
        del count, interval  # the probe asks once per target
        targets = tuple(t.strip() for t in self.targets_edit.text().split(",") if t.strip())
        return ProxyArpProbeConfig(
            iface=iface,
            sender_ip=self.sender_edit.text().strip(),
            prefix_length=self.prefix_spin.value(),
            targets=targets,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: ProxyArpProbeConfig,
        stop_event: threading.Event,
        on_progress: Callable[[ProxyArpProbeStats], None],
    ) -> ProxyArpProbeStats:
        return run_proxy_arp_probe(config, stop_event, on_progress)

    def _format_status(self, stats: ProxyArpProbeStats) -> str:
        return stats.status or f"Answers: {len(stats.answers)}"
