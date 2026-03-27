from __future__ import annotations

from pathlib import Path
from typing import Any


def write_amcache_pdf(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write a placeholder PDF report payload.

    This project currently stores a plain-text placeholder with a `.pdf`
    extension until a full renderer is integrated.

    Args:
        path: Destination PDF path.
        rows: Flattened Amcache records.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "Amcache PDF Report Placeholder\n"
        "A full PDF renderer will be integrated in a future version.\n"
        f"Record count: {len(rows)}\n"
    )
    with path.open("w", encoding="utf-8") as file_obj:
        file_obj.write(content)
