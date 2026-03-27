from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def _collect_headers(rows: list[dict[str, Any]]) -> list[str]:
    """Collect deterministic CSV headers from rows.

    Args:
        rows: Flat row list.

    Returns:
        Stable header order.
    """
    priority = ["_category", "_record_name", "Name", "FilePath", "SHA-1", "RecordDate"]
    seen: set[str] = set()
    dynamic: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in seen and key not in priority:
                seen.add(key)
                dynamic.append(key)
    return [*priority, *sorted(dynamic)]


def write_amcache_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    forensic_header: dict[str, Any] | None = None,
    analysis_metadata: dict[str, Any] | None = None,
) -> None:
    """Write flat Amcache rows to CSV.

    Args:
        path: Destination CSV file path.
        rows: Flat row list.
        forensic_header: Forensic header metadata.
        analysis_metadata: Additional analysis metadata.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    header = forensic_header or {}
    header_rows = [
        ["Case ID", header.get("Case ID", "ERGENEKON-2026-001")],
        ["Evidence Hash", header.get("Evidence Hash", "N/A")],
        ["Analyst ID", header.get("Analyst ID", "N/A")],
        ["Analysis Timestamp", header.get("Analysis Timestamp", "N/A")],
        ["Tool Version", header.get("Tool Version", "N/A")],
        ["Tool Build Date", header.get("Tool Build Date", "unknown")],
        ["Python Runtime", header.get("Python Runtime", "N/A")],
    ]
    if not rows:
        with path.open("w", newline="", encoding="utf-8") as file_obj:
            writer = csv.writer(file_obj)
            writer.writerows(header_rows)
            if analysis_metadata:
                writer.writerow(["Analysis Metadata", str(analysis_metadata)])
            writer.writerow(["_category", "_record_name"])
        return

    headers = _collect_headers(rows)
    with path.open("w", newline="", encoding="utf-8") as file_obj:
        metadata_writer = csv.writer(file_obj)
        metadata_writer.writerows(header_rows)
        if analysis_metadata:
            metadata_writer.writerow(["Analysis Metadata", str(analysis_metadata)])
        metadata_writer.writerow([])
        writer = csv.DictWriter(file_obj, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
