# PyInstaller spec for MACabre. Build from the repository root with:
#   pyinstaller --noconfirm packaging/macabre.spec
# The same spec builds on Windows, macOS and Linux; each platform must build its own bundle.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
ICON_DIR = ROOT / "src" / "macabre" / "resources" / "icons"

block_cipher = None

analysis = Analysis(
    [str(ROOT / "src" / "macabre" / "__main__.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[(str(ROOT / "src" / "macabre" / "resources"), "macabre/resources")],
    # Scapy loads its protocol layers dynamically, so PyInstaller cannot see them.
    hiddenimports=collect_submodules("scapy"),
    excludes=[],
    noarchive=False,
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="MACabre",
    debug=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(ICON_DIR / "macabre.ico") if sys.platform == "win32" else None,
)

coll = COLLECT(
    exe,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    strip=False,
    upx=False,
    name="MACabre",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="MACabre.app",
        icon=str(ROOT / "packaging" / "macabre.icns"),
        bundle_identifier="es.lo0.macabre",
        info_plist={
            "CFBundleName": "MACabre",
            "CFBundleDisplayName": "MACabre",
            "NSHighResolutionCapable": True,
        },
    )
