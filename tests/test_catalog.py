import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_catalog", ROOT / "scripts" / "generate_catalog.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_catalog_module_is_up_to_date():
    gen = _load_generator()
    families = gen.parse((ROOT / "docs" / "attack-catalog.md").read_text(encoding="utf-8"))
    expected = gen.render(families)
    actual = (ROOT / "src" / "macabre" / "catalog.py").read_text(encoding="utf-8")
    assert actual == expected, "run scripts/generate_catalog.py"


def test_catalog_has_expected_size():
    from macabre.catalog import FAMILIES

    techniques = [t for f in FAMILIES for t in f.techniques]
    assert len(FAMILIES) == 13
    assert len(techniques) == 128
    assert len({t.name for t in techniques}) == 128


def test_status_matches_available_panels():
    from macabre.catalog import FAMILIES, Status
    from macabre.gui.main_window import PANELS

    with_code = {
        t.name for f in FAMILIES for t in f.techniques if t.status is not Status.TO_IMPLEMENT
    }
    assert with_code == set(PANELS)
