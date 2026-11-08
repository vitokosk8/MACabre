"""Panel for the Router Advertisement flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.router_advertisement_flooding import (
    DEFAULT_PREFIX_BASE,
    MAX_ADVERTISEMENTS,
    RouterAdvertisementFloodingConfig,
    RouterAdvertisementFloodingStats,
    run_router_advertisement_flooding,
)
from macabre.attacks.rogue_router_advertisement import MAX_ROUTER_LIFETIME
from macabre.gui.base_panel import AttackPanel


class RouterAdvertisementFloodingPanel(AttackPanel):
    title = "Router Advertisement Flooding"
    description = (
        "Sends Router Advertisements from many made-up routers, each with its own /64 prefix. Hosts that "
        "accept them fill their router and prefix lists and spend processing on each one. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.prefix_edit = QLineEdit(DEFAULT_PREFIX_BASE)
        self.prefix_edit.setToolTip("Block the /64 prefixes are taken from (/16 to /48).")
        form.addRow("Prefix base:", self.prefix_edit)

        self.advertisements_spin = QSpinBox()
        self.advertisements_spin.setRange(1, MAX_ADVERTISEMENTS)
        self.advertisements_spin.setValue(50)
        self.advertisements_spin.setSuffix(" advertisement(s)")
        form.addRow("Advertisements:", self.advertisements_spin)

        self.lifetime_spin = QSpinBox()
        self.lifetime_spin.setRange(1, MAX_ROUTER_LIFETIME)
        self.lifetime_spin.setValue(1800)
        self.lifetime_spin.setSuffix(" s")
        form.addRow("Router lifetime:", self.lifetime_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.prefix_edit, self.advertisements_spin, self.lifetime_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RouterAdvertisementFloodingConfig:
        del count, interval  # this attack sends a fixed number of advertisements
        return RouterAdvertisementFloodingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            prefix_base=self.prefix_edit.text().strip(),
            advertisements=self.advertisements_spin.value(),
            router_lifetime=self.lifetime_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RouterAdvertisementFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RouterAdvertisementFloodingStats], None],
    ) -> RouterAdvertisementFloodingStats:
        return run_router_advertisement_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: RouterAdvertisementFloodingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.advertisements}"
