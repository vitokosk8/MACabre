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

# Status labels used in docs/attack-catalog.md, mapped to Status members.
STATUS_LABELS = {
    "📋 To implement": "TO_IMPLEMENT",
    "🔨 Implemented": "IMPLEMENTED",
    "🧪 Tested": "TESTED",
    "🖥 Tested in GUI": "TESTED_IN_GUI",
    "❌ Tested, not working yet": "NOT_WORKING",
}


def parse(text: str) -> list[tuple[str, list[tuple[str, str, str, str]]]]:
    families: list[tuple[str, list[tuple[str, str, str, str]]]] = []
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
            if status not in STATUS_LABELS:
                raise ValueError(f"Unknown status for {name!r}: {status!r}")
            families[-1][1].append((name, description, priority, STATUS_LABELS[status]))
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
        "from enum import Enum",
        "",
        "",
        "class Status(Enum):",
        '    """How far a technique has come. Labels match docs/attack-catalog.md."""',
        "",
        "    TO_IMPLEMENT = 'To implement'",
        "    IMPLEMENTED = 'Implemented'",
        "    TESTED = 'Tested'",
        "    TESTED_IN_GUI = 'Tested in GUI'",
        "    NOT_WORKING = 'Tested, not working yet'",
        "",
        "",
        "@dataclass(frozen=True)",
        "class Technique:",
        "    name: str",
        "    description: str",
        "    priority: str",
        "    status: Status",
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
        for name, description, priority, status in techniques:
            out.append(
                "            Technique("
                f"name={name!r}, description={description!r}, "
                f"priority={priority!r}, status=Status.{status}),"
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
