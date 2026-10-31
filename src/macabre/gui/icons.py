"""Application icon loading."""

from __future__ import annotations

from importlib import resources

from PySide6.QtGui import QIcon

ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


def app_icon() -> QIcon:
    """Return the macabre icon with every bundled size registered."""
    icon = QIcon()
    icon_dir = resources.files("macabre") / "resources" / "icons"
    for size in ICON_SIZES:
        path = icon_dir / f"macabre-{size}.png"
        if path.is_file():
            icon.addFile(str(path))
    return icon
