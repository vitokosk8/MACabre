import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")


def test_app_icon_has_all_sizes():
    from PySide6.QtWidgets import QApplication

    from macabre.gui.icons import ICON_SIZES, app_icon

    QApplication.instance() or QApplication([])
    icon = app_icon()

    assert not icon.isNull()
    assert {s.width() for s in icon.availableSizes()} >= set(ICON_SIZES)


def test_main_window_builds_and_selects_dhcp_panel(qtbot=None):
    from PySide6.QtWidgets import QApplication

    from macabre.gui.dhcp_panel import DhcpStarvationPanel
    from macabre.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    assert window.windowTitle().startswith("MACabre")
    panel_types = [window._stack.widget(i) for i in range(window._stack.count())]
    assert any(isinstance(w, DhcpStarvationPanel) for w in panel_types)

    window.close()
    app.processEvents()


def test_menu_is_built_from_catalog():
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from macabre.catalog import FAMILIES
    from macabre.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    tree = window._tree

    assert tree.topLevelItemCount() == len(FAMILIES)
    for index, family in enumerate(FAMILIES):
        item = tree.topLevelItem(index)
        assert item.text(0) == family.name
        assert item.childCount() == len(family.techniques)

    dhcp = next(
        tree.topLevelItem(i).child(j)
        for i, f in enumerate(FAMILIES)
        for j, t in enumerate(f.techniques)
        if t.name == "DHCP Starvation"
    )
    assert not dhcp.isDisabled()
    assert dhcp.data(0, Qt.ItemDataRole.UserRole) == "DHCP Starvation"

    unimplemented = next(
        tree.topLevelItem(i).child(j)
        for i, f in enumerate(FAMILIES)
        for j, t in enumerate(f.techniques)
        if t.name == "Neighbor Advertisement Spoofing"
    )
    assert unimplemented.isDisabled()

    window.close()
    app.processEvents()
