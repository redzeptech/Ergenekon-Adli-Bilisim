from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def write_jsonl(path: Path, records: Iterable[dict[str, Any]], *, ensure_ascii: bool = False) -> None:
    """Write iterable records as JSON Lines.

    Args:
        path: Destination file path.
        records: Iterable object producing dict rows.
        ensure_ascii: Keep unicode characters if False.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file_obj:
        for row in records:
            file_obj.write(json.dumps(row, ensure_ascii=ensure_ascii) + "\n")
