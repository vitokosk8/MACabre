"""Generate the application icon set from assets/logo.png.

Outputs:
  src/macabre/resources/icons/macabre-<size>.png   runtime window/app icons
  src/macabre/resources/icons/macabre.ico          Windows / multi-size icon
  packaging/linux/icons/hicolor/<size>x<size>/apps/macabre.png
                                                   freedesktop icon theme

Requires Pillow: pip install pillow
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "assets" / "logo.png"
RUNTIME_DIR = ROOT / "src" / "macabre" / "resources" / "icons"
HICOLOR_DIR = ROOT / "packaging" / "linux" / "icons" / "hicolor"

PNG_SIZES = [16, 24, 32, 48, 64, 128, 256, 512]
ICO_SIZES = [(16, 16), (32, 32), (48, 48), (256, 256)]


def main() -> None:
    image = Image.open(SOURCE).convert("RGBA")

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    for size in PNG_SIZES:
        resized = image.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(RUNTIME_DIR / f"macabre-{size}.png", optimize=True)

    image.save(RUNTIME_DIR / "macabre.ico", sizes=ICO_SIZES)

    for size in PNG_SIZES:
        target = HICOLOR_DIR / f"{size}x{size}" / "apps"
        target.mkdir(parents=True, exist_ok=True)
        resized = image.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(target / "macabre.png", optimize=True)

    print("Icons generated.")


if __name__ == "__main__":
    main()
