from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def flatten_amcache_data(
    data: dict[str, dict[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Flatten nested Amcache data to a record list.

    Args:
        data: Category -> record name -> field map.

    Returns:
        Flat list of records with category and record metadata.
    """
    rows: list[dict[str, Any]] = []
    for category, records in data.items():
        for record_name, values in records.items():
            row: dict[str, Any] = dict(values)
            row["_category"] = category
            row["_record_name"] = record_name
            rows.append(row)
    return rows


def write_amcache_json(
    path: Path,
    data: dict[str, dict[str, dict[str, Any]]],
    *,
    forensic_header: dict[str, Any] | None = None,
    analysis_metadata: dict[str, Any] | None = None,
    execution_timeline: list[dict[str, Any]] | None = None,
) -> None:
    """Write flattened Amcache records as JSON payload.

    Args:
        path: Destination JSON file path.
        data: Category -> record name -> field map.
        forensic_header: Forensic header metadata.
        analysis_metadata: Additional analysis metadata.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = flatten_amcache_data(data)
    header = forensic_header or {}
    payload: dict[str, Any] = {
        "Case ID": header.get("Case ID", "ERGENEKON-2026-001"),
        "Evidence Hash": header.get("Evidence Hash", "N/A"),
        "Analyst ID": header.get("Analyst ID", "N/A"),
        "Analysis Timestamp": header.get("Analysis Timestamp", "N/A"),
        "Tool Version": header.get("Tool Version", "N/A"),
        "Tool Build Date": header.get("Tool Build Date", "unknown"),
        "Python Runtime": header.get("Python Runtime", "N/A"),
        "Analysis Metadata": analysis_metadata or {},
        "Execution Timeline": execution_timeline or [],
        "Records": rows,
    }
    with path.open("w", encoding="utf-8") as file_obj:
        json.dump(payload, file_obj, ensure_ascii=False, indent=2, default=str)
