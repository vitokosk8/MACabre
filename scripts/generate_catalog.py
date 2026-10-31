"""Generate src/macabre/catalog.py from docs/attack-catalog.md.

The catalog markdown is the single source of truth for the attack families and
techniques shown in the GUI menu. Run after editing the catalog:

    .venv/bin/python scripts/generate_catalog.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "attack-catalog.md"
OUTPUT = ROOT / "src" / "macabre" / "catalog.py"

FAMILY_RE = re.compile(r"^### (.+?) \((\d+)\)$")
ROW_HEADER = "| Technique | Description | Priority | Status |"


def parse(text: str) -> list[tuple[str, list[tuple[str, str, str, bool]]]]:
    families: list[tuple[str, list[tuple[str, str, str, bool]]]] = []
    in_table = False
    for line in text.splitlines():
        match = FAMILY_RE.match(line)
        if match:
            families.append((match.group(1), []))
            in_table = False
            continue
        if line == ROW_HEADER:
            in_table = True
            continue
        if in_table and line.startswith("| ") and not line.startswith("| ---"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            name, description, priority, status = cells
            families[-1][1].append((name, description, priority, status.startswith("✅")))
        elif in_table and not line.startswith("|"):
            in_table = False
    return families


def render(families) -> str:
    out = [
        '"""Attack families and techniques, generated from docs/attack-catalog.md.',
        "",
        "Do not edit by hand. Run scripts/generate_catalog.py after changing the catalog.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass",
        "",
        "",
        "@dataclass(frozen=True)",
        "class Technique:",
        "    name: str",
        "    description: str",
        "    priority: str",
        "    implemented: bool",
        "",
        "",
        "@dataclass(frozen=True)",
        "class Family:",
        "    name: str",
        "    techniques: tuple[Technique, ...]",
        "",
        "",
        "FAMILIES: tuple[Family, ...] = (",
    ]
    for family_name, techniques in families:
        out.append("    Family(")
        out.append(f"        name={family_name!r},")
        out.append("        techniques=(")
        for name, description, priority, implemented in techniques:
            out.append(
                "            Technique("
                f"name={name!r}, description={description!r}, "
                f"priority={priority!r}, implemented={implemented!r}),"
            )
        out.append("        ),")
        out.append("    ),")
    out.append(")")
    return "\n".join(out) + "\n"


def main() -> None:
    families = parse(CATALOG.read_text(encoding="utf-8"))
    OUTPUT.write_text(render(families), encoding="utf-8")
    total = sum(len(t) for _, t in families)
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(families)} families, {total} techniques")


if __name__ == "__main__":
    main()
