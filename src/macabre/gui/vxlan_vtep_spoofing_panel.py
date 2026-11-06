"""Panel for the VXLAN VNI / VTEP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.vxlan_vtep_spoofing import (
    MAX_FRAMES,
    MAX_VNI,
    VxlanVtepSpoofingConfig,
    VxlanVtepSpoofingStats,
    run_vxlan_vtep_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class VxlanVtepSpoofingPanel(AttackPanel):
    title = "VXLAN VNI / VTEP Spoofing"
    description = (
        "Sends VXLAN frames to a target VTEP with a chosen VNI, claiming an inner source MAC behind the "
        "address you give. A VTEP that trusts unauthenticated frames moves that MAC to the claimed address. "
        "Use only with authorization, on an overlay you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your underlay MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.outer_src_edit = QLineEdit()
        self.outer_src_edit.setPlaceholderText("VTEP address to claim, e.g. 10.0.0.3")
        form.addRow("Claimed VTEP:", self.outer_src_edit)

        self.outer_dst_edit = QLineEdit()
        self.outer_dst_edit.setPlaceholderText("Target VTEP address, e.g. 10.0.0.2")
        form.addRow("Target VTEP:", self.outer_dst_edit)

        self.outer_dst_mac_edit = QLineEdit()
        self.outer_dst_mac_edit.setPlaceholderText("Target VTEP underlay MAC")
        form.addRow("Target MAC:", self.outer_dst_mac_edit)

        self.vni_spin = QSpinBox()
        self.vni_spin.setRange(1, MAX_VNI)
        self.vni_spin.setValue(42)
        self.vni_spin.setToolTip("VXLAN network identifier of the segment under test.")
        form.addRow("VNI:", self.vni_spin)

        self.inner_edit = QLineEdit()
        self.inner_edit.setPlaceholderText("Inner source MAC to claim, e.g. 02:00:00:00:00:50")
        form.addRow("Inner MAC:", self.inner_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" frame(s)")
        form.addRow("Frames:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.outer_src_edit, self.outer_dst_edit, self.outer_dst_mac_edit,
                       self.vni_spin, self.inner_edit, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> VxlanVtepSpoofingConfig:
        del count, interval  # this attack sends a fixed number of frames
        return VxlanVtepSpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            outer_src_ip=self.outer_src_edit.text().strip(),
            outer_dst_ip=self.outer_dst_edit.text().strip(),
            outer_dst_mac=self.outer_dst_mac_edit.text().strip(),
            vni=self.vni_spin.value(),
            inner_src_mac=self.inner_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: VxlanVtepSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[VxlanVtepSpoofingStats], None],
    ) -> VxlanVtepSpoofingStats:
        return run_vxlan_vtep_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: VxlanVtepSpoofingStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
