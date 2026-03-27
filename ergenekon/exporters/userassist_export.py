"""UserAssist export helpers for JSON and CSV outputs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ergenekon.core.userassist_engine import UserAssistRow


def userassist_rows_to_records(rows: list[UserAssistRow]) -> list[dict[str, Any]]:
    """Convert UserAssist rows into serializable dictionaries.

    Args:
        rows: Parsed userassist rows.

    Returns:
        JSON/CSV serializable list.
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        rec = row.record
        out.append(
            {
                "User": row.windows_user,
                "Artifact": rec.artifact,
                "RunCount": rec.run_count,
                "LastRun": rec.last_run.isoformat() if rec.last_run else "",
                "FocusCount": rec.focus_count,
                "FocusTimeMs": rec.focus_time_ms,
            }
        )
    return out


def write_userassist_json(path: Path, records: list[dict[str, Any]], *, indent: int = 2) -> None:
    """Write userassist records as UTF-8 JSON.

    Args:
        path: Output JSON file path.
        records: Record list.
        indent: JSON indentation level.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(records, ensure_ascii=False, indent=indent, default=str),
        encoding="utf-8",
    )


def write_userassist_csv(path: Path, records: list[dict[str, Any]]) -> None:
    """Write userassist records as CSV.

    Args:
        path: Output CSV file path.
        records: Record list.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = list(records[0].keys())
    with path.open("w", newline="", encoding="utf-8") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
