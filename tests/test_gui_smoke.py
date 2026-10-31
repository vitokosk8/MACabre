import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")


def test_main_window_builds_and_selects_dhcp_panel(qtbot=None):
    from PySide6.QtWidgets import QApplication

    from macabre.gui.dhcp_panel import DhcpStarvationPanel
    from macabre.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    assert window.windowTitle().startswith("macabre")
    panel_types = [window._stack.widget(i) for i in range(window._stack.count())]
    assert any(isinstance(w, DhcpStarvationPanel) for w in panel_types)

    window.close()
    app.processEvents()
