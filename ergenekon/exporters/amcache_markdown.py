from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def write_amcache_markdown_report(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    examined_file: Path | str | None = None,
    forensic_header: dict[str, Any] | None = None,
    analysis_metadata: dict[str, Any] | None = None,
    execution_timeline: list[dict[str, Any]] | None = None,
) -> None:
    """Write a professional Markdown forensic report.

    Args:
        path: Destination Markdown path.
        rows: Flat row list.
        examined_file: Input evidence file path used in analysis.
        forensic_header: Forensic header metadata.
        analysis_metadata: Analysis metadata block values.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    generation_time = datetime.now().isoformat(timespec="seconds")
    total_records = len(rows)
    os_component_count = sum(1 for row in rows if bool(row.get("IsOsComponent")))
    non_os_count = total_records - os_component_count
    examined_file_text = str(examined_file) if examined_file else "N/A"
    header = forensic_header or {}

    publisher_counter = Counter(
        str(row.get("Publisher", "")).strip() or "Unknown" for row in rows
    )
    top_publishers = publisher_counter.most_common(10)
    sigma_rows = [
        row
        for row in rows
        if row.get("SigmaAlert") or row.get("SigmaLevel") or row.get("SigmaRuleId")
    ]
    verified_rows = [row for row in rows if str(row.get("ExecutionStatus", "")).upper() == "VERIFIED"]

    first_rows = rows[:25]
    lines: list[str] = [
        "ERGENEKON ADLI BILISIM - ANALIZ RAPORU",
        "",
        f"Case ID: {header.get('Case ID', 'ERGENEKON-2026-001')}",
        f"Evidence Hash: {header.get('Evidence Hash', 'N/A')}",
        f"Analyst ID: {header.get('Analyst ID', 'N/A')}",
        f"Analysis Timestamp: {header.get('Analysis Timestamp', 'N/A')}",
        f"Tool Version: {header.get('Tool Version', 'N/A')}",
        f"Tool Build Date: {header.get('Tool Build Date', 'unknown')}",
        f"Python Runtime: {header.get('Python Runtime', 'N/A')}",
        "",
        f"Analiz Tarihi: {current_date}",
        f"Incelenen Dosya: {examined_file_text}",
        "Hukuki Statu: KVKK Uyumlu / Maskelenmis Veri",
        "Sorumluluk Reddi: Bu rapor otomatik olusturulmustur. TCK 243-246 maddeleri uyarinca yetkisiz paylasimi suc teskil edebilir.",
        "",
        "## Analysis Metadata",
    ]
    for key, value in (analysis_metadata or {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(
        [
        "",
        "# Amcache Forensics Report",
        "",
        f"- GeneratedAt: `{generation_time}`",
        f"- TotalRecords: `{total_records}`",
        f"- OsComponentRecords: `{os_component_count}`",
        f"- NonOsRecords: `{non_os_count}`",
        "",
        "## Publisher Distribution (Top 10)",
        "",
        "| Publisher | Count |",
        "|---|---:|",
    ])
    for publisher, count in top_publishers:
        lines.append(f"| {publisher} | {count} |")

    if sigma_rows:
        lines.extend(
            [
                "",
                "## Supheli Bulgular (Threat Hunting)",
                "",
                "_Not: Bu bolumdeki bulgular kesin zararlidir anlami tasimaz; yanlis pozitif olasiligi vardir._",
                "",
                "| RuleId | Level | Alert | FilePath | SHA-1 |",
                "|---|---|---|---|---|",
            ]
        )
        for row in sigma_rows[:50]:
            rule_id = str(row.get("SigmaRuleId", ""))
            level = str(row.get("SigmaLevel", ""))
            alert = str(row.get("SigmaAlert", ""))
            file_path = str(row.get("FilePath", ""))
            sha1 = str(row.get("SHA-1", ""))
            # Markdown tables have no native color, use inline HTML span for emphasis.
            level_cell = (
                f"<span style='color:red; font-weight:700'>{level.upper()}</span>"
                if level.lower() in {"high", "critical"}
                else level
            )
            lines.append(f"| {rule_id} | {level_cell} | {alert} | {file_path} | {sha1} |")
        if len(sigma_rows) > 50:
            lines.extend(
                ["", f"_Note: {len(sigma_rows) - 50} sigma alert kaydi bu tabloda gosterilmedi._"]
            )

    if execution_timeline:
        lines.extend(
            [
                "",
                "## Execution Timeline",
                "",
                "| Timestamp | Source | Path | SHA-1 | Status |",
                "|---|---|---|---|---|",
            ]
        )
        for item in execution_timeline:
            lines.append(
                "| {timestamp} | {source} | {path} | {sha1} | {status} |".format(
                    timestamp=str(item.get("timestamp", "")),
                    source=str(item.get("source", "")),
                    path=str(item.get("path", "")),
                    sha1=str(item.get("sha1", "")),
                    status=str(item.get("status", "")),
                )
            )

    if verified_rows:
        lines.extend(
            [
                "",
                "## Verified Executions",
                "",
                "| Name | SHA-1 | FilePath | RecordDate | ShimcacheLastModified |",
                "|---|---|---|---|---|",
            ]
        )
        for row in verified_rows[:100]:
            lines.append(
                "| {name} | {sha1} | {path} | {record_date} | {shim_lm} |".format(
                    name=str(row.get("Name", "")),
                    sha1=str(row.get("SHA-1", "")),
                    path=str(row.get("FilePath", "")),
                    record_date=str(row.get("RecordDate", "")),
                    shim_lm=str(row.get("ShimcacheLastModified", "")),
                )
            )
        if len(verified_rows) > 100:
            lines.extend(
                [
                    "",
                    f"_Note: {len(verified_rows) - 100} verified execution kaydi bu tabloda gosterilmedi._",
                ]
            )

    lines.extend(
        [
            "",
            "## Sample Records (First 25)",
            "",
            "| Category | Record | Name | SHA-1 | FilePath | RecordDate | ExecutionStatus | ShimcacheLastModified |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in first_rows:
        category = str(row.get("_category", ""))
        record = str(row.get("_record_name", ""))
        name = str(row.get("Name", ""))
        sha1 = str(row.get("SHA-1", ""))
        file_path = str(row.get("FilePath", ""))
        record_date = str(row.get("RecordDate", ""))
        execution_status = str(row.get("ExecutionStatus", ""))
        shimcache_last_modified = str(row.get("ShimcacheLastModified", ""))
        lines.append(
            f"| {category} | {record} | {name} | {sha1} | {file_path} | {record_date} | {execution_status} | {shimcache_last_modified} |"
        )

    if total_records > len(first_rows):
        lines.extend(["", f"_Note: {total_records - len(first_rows)} records omitted in sample table._"])

    with path.open("w", encoding="utf-8") as file_obj:
        file_obj.write("\n".join(lines))
