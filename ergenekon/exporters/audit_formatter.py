"""Professional audit finding formatter utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_FINDING_ID_RE = re.compile(r"^ERG-\d{4}$")


@dataclass(frozen=True)
class AuditFinding:
    """Normalized audit finding model."""

    finding_id: str
    title: str
    area: str
    risk_score: int
    status: str
    evidence: str
    recommendation: str


def _normalize_finding_id(value: str) -> str:
    """Normalize finding id to ERG-XXXX format."""
    candidate = (value or "").strip().upper()
    if _FINDING_ID_RE.match(candidate):
        return candidate
    digits = "".join(ch for ch in candidate if ch.isdigit())[-4:]
    if not digits:
        digits = "0000"
    return f"ERG-{digits.zfill(4)}"


def _normalize_risk_score(value: int) -> int:
    """Clamp risk score to the 1-10 range."""
    return max(1, min(10, int(value)))


def normalize_finding(
    *,
    finding_id: str,
    title: str,
    area: str,
    risk_score: int,
    status: str,
    evidence: str,
    recommendation: str,
) -> AuditFinding:
    """Create a normalized `AuditFinding` object."""
    return AuditFinding(
        finding_id=_normalize_finding_id(finding_id),
        title=(title or "").strip(),
        area=(area or "").strip(),
        risk_score=_normalize_risk_score(risk_score),
        status=(status or "").strip(),
        evidence=(evidence or "").strip(),
        recommendation=(recommendation or "").strip(),
    )


def findings_to_markdown_table(findings: Iterable[AuditFinding]) -> str:
    """Render findings as a professional markdown table."""
    rows = list(findings)
    header = (
        "| Bulgu ID | Alan | Bulgu | Risk Skoru (1-10) | Durum | Kanit | Oneri |\n"
        "|---|---|---|---:|---|---|---|"
    )
    if not rows:
        return header + "\n| ERG-0000 | Genel | Bulgu yok | 1 | N/A | N/A | N/A |"

    line_rows = []
    for row in rows:
        line_rows.append(
            "| {finding_id} | {area} | {title} | {risk_score} | {status} | {evidence} | {recommendation} |".format(
                finding_id=row.finding_id,
                area=row.area,
                title=row.title,
                risk_score=row.risk_score,
                status=row.status,
                evidence=row.evidence,
                recommendation=row.recommendation,
            )
        )
    return header + "\n" + "\n".join(line_rows)


__all__ = [
    "AuditFinding",
    "findings_to_markdown_table",
    "normalize_finding",
]
