"""Every registered attack panel builds offscreen and reports its status without a display."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")


def _panel_items():
    from macabre.gui.main_window import PANELS

    return sorted(PANELS.items())


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize("name,panel_class", _panel_items(), ids=lambda v: v if isinstance(v, str) else v.__name__)
def test_panel_builds_and_has_a_title_and_description(qapp, name, panel_class):
    panel = panel_class()
    try:
        assert panel.title, f"{name} has no title"
        assert panel.description, f"{name} has no description"
        assert panel.default_interval >= 0
    finally:
        panel.deleteLater()
        qapp.processEvents()


@pytest.mark.parametrize("name,panel_class", _panel_items(), ids=lambda v: v if isinstance(v, str) else v.__name__)
def test_panel_formats_an_empty_status_without_error(qapp, name, panel_class):
    import typing

    stats_type = typing.get_type_hints(panel_class._run_attack).get("return")
    assert stats_type is not None, f"{name} does not annotate its stats type"
    panel = panel_class()
    try:
        status = panel._format_status(stats_type())
        assert isinstance(status, str) and status.strip(), f"{name} shows an empty status"
    finally:
        panel.deleteLater()
        qapp.processEvents()
