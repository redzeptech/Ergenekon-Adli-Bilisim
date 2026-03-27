"""
SYSTEM hive icindeki AppCompatCache (Shimcache) kayitlarini parse eder.

Not:
- Shimcache binary formati Windows surumlerine gore degisir.
- Bu parser, yaygin path girdilerini cikarmak ve kayit cevresinden olasi
  LastModifiedTime / ExecutionFlag alanlarini en iyi gayretle tespit etmek
  icin heuristik kullanir.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from ergenekon.core.registry_reader import RegistryReader
from ergenekon.utils.privacy import mask_path, mask_pii

ShimcacheData = dict[str, dict[str, dict[str, Any]]]
AmcacheData = dict[str, dict[str, dict[str, Any]]]

_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:\\|\\\\)[^\x00\r\n|<>*?]{3,}\.(?:exe|dll|sys|com|bat|cmd|ps1|js|vbs)"
)
_SID_RE = re.compile(r"(?i)\bS-\d-\d+(?:-\d+){1,14}\b")
_UNC_HOST_RE = re.compile(r"^\\\\([^\\]+)\\")


def _normalize_sha1(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip().lower()
    if text.startswith("0000"):
        text = text[4:]
    return text


def _normalize_path(path: str | None) -> str:
    if not path:
        return ""
    return str(path).strip().lower().replace("/", "\\")


def _sanitize_shimcache_path(path: str) -> str:
    """
    KVKK/TCK odakli varsayilan sanitizasyon:
    - Users profil adini maskele
    - SID kaliplarini maskele
    - UNC host adini maskele
    """
    sanitized = mask_path(path, active=True)
    sanitized = _SID_RE.sub(lambda m: f"SID_{mask_pii(m.group(0), active=True)}", sanitized)
    unc_match = _UNC_HOST_RE.match(sanitized)
    if unc_match:
        host = unc_match.group(1)
        sanitized = sanitized.replace(
            f"\\\\{host}\\",
            f"\\\\HOST_{mask_pii(host, active=True)}\\",
            1,
        )
    return sanitized


def _filetime_to_iso(raw: int) -> str | None:
    if raw <= 0:
        return None
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=raw // 10)
    except (OverflowError, ValueError):
        return None
    if dt.year < 1990 or dt.year > 2100:
        return None
    return dt.isoformat()


def _scan_last_modified_near(blob: bytes, pivot: int, window: int = 96) -> str | None:
    start = max(0, pivot - window)
    end = min(len(blob), pivot + window)
    area = blob[start:end]
    for idx in range(0, max(0, len(area) - 8)):
        ft_raw = int.from_bytes(area[idx : idx + 8], "little", signed=False)
        iso = _filetime_to_iso(ft_raw)
        if iso:
            return iso
    return None


def _scan_exec_flag_near(blob: bytes, pivot: int, window: int = 64) -> bool | None:
    start = max(0, pivot - window)
    end = min(len(blob), pivot + window)
    area = blob[start:end]
    for idx in range(0, max(0, len(area) - 4), 4):
        value = int.from_bytes(area[idx : idx + 4], "little", signed=False)
        if value in (0, 1):
            return bool(value)
    return None


def _find_appcompatcache_blob(registry_reader: RegistryReader) -> bytes:
    reg = registry_reader.registry
    select_key = reg.open("Select")
    current = 1
    try:
        current = int(select_key.value("Current").value())
    except Exception:
        pass

    candidates: list[str] = [
        f"ControlSet{current:03d}\\Control\\Session Manager\\AppCompatCache",
        "ControlSet001\\Control\\Session Manager\\AppCompatCache",
        "ControlSet002\\Control\\Session Manager\\AppCompatCache",
    ]
    for candidate in candidates:
        try:
            key = reg.open(candidate)
        except Exception:
            continue
        values = list(key.values())
        if not values:
            continue
        preferred = None
        for val in values:
            if str(val.name()).lower() == "appcompatcache":
                preferred = val
                break
        value_obj = preferred or max(values, key=lambda v: len(v.raw_data()))
        raw = value_obj.raw_data()
        if raw:
            return raw
    raise KeyError("SYSTEM hive icinde AppCompatCache kaydi bulunamadi.")


class ShimcacheParser:
    """SYSTEM hive icindeki Shimcache kayitlarini ayrıştırir."""

    def __init__(self, system_hive_path: str) -> None:
        self._reader = RegistryReader(system_hive_path)

    def parse(self) -> ShimcacheData:
        blob = _find_appcompatcache_blob(self._reader)
        text = blob.decode("utf-16le", errors="ignore")

        records: dict[str, dict[str, Any]] = {}
        seen_paths: set[str] = set()
        index = 0
        for match in _PATH_RE.finditer(text):
            path = match.group(0).strip()
            norm_path = _normalize_path(path)
            if not norm_path or norm_path in seen_paths:
                continue
            seen_paths.add(norm_path)

            path_bytes = path.encode("utf-16le", errors="ignore")
            pivot = blob.find(path_bytes)
            if pivot < 0:
                pivot = int((match.start() * 2))

            last_modified = _scan_last_modified_near(blob, pivot)
            exec_flag = _scan_exec_flag_near(blob, pivot)
            sanitized_path = _sanitize_shimcache_path(path)

            records[f"shimcache_{index:04d}"] = {
                "Path": sanitized_path,
                "LastModifiedTime": last_modified,
                "ExecutionFlag": exec_flag,
            }
            index += 1

        return {"Shimcache": records}


def correlate_amcache_shimcache(
    amcache_data: AmcacheData,
    shimcache_data: ShimcacheData,
) -> list[dict[str, Any]]:
    """
    Amcache ve Shimcache arasinda ortak girdileri bulur.

    Eslesme:
    - Amcache FilePath/Path <-> Shimcache Path (normalize edilmis)
    """
    amcache_path_index: dict[str, dict[str, Any]] = {}
    for records in amcache_data.values():
        for values in records.values():
            path = _normalize_path(values.get("FilePath") or values.get("Path"))
            if path:
                amcache_path_index.setdefault(path, values)

    matches: list[dict[str, Any]] = []
    for records in shimcache_data.values():
        for values in records.values():
            shim_path = _normalize_path(values.get("Path") or values.get("FilePath"))
            amcache_match = amcache_path_index.get(shim_path) if shim_path else None

            if not amcache_match:
                continue

            last_modified = values.get("LastModifiedTime")
            values["ExecutionStatus"] = "VERIFIED"
            amcache_match["ExecutionStatus"] = "VERIFIED"
            amcache_match["ShimcacheLastModified"] = last_modified
            matches.append(
                {
                    "status": "VERIFIED",
                    "match_basis": "PATH",
                    "path": values.get("Path") or values.get("FilePath") or "",
                    "sha1": _normalize_sha1(amcache_match.get("SHA-1")),
                    "amcache_record_date": amcache_match.get("RecordDate"),
                    "shimcache_last_modified": last_modified,
                }
            )
    return matches


def build_execution_timeline(
    amcache_data: AmcacheData,
    shimcache_data: ShimcacheData,
) -> list[dict[str, Any]]:
    """Amcache RecordDate ve Shimcache LastModifiedTime alanlarini kronolojik siralar."""
    timeline: list[dict[str, Any]] = []
    for records in amcache_data.values():
        for values in records.values():
            ts = values.get("RecordDate")
            if ts:
                timeline.append(
                    {
                        "timestamp": str(ts),
                        "source": "Amcache",
                        "path": values.get("FilePath") or values.get("Path") or "",
                        "sha1": values.get("SHA-1", ""),
                        "status": values.get("ExecutionStatus", ""),
                    }
                )
    for records in shimcache_data.values():
        for values in records.values():
            ts = values.get("LastModifiedTime")
            if ts:
                timeline.append(
                    {
                        "timestamp": str(ts),
                        "source": "Shimcache",
                        "path": values.get("Path") or values.get("FilePath") or "",
                        "sha1": values.get("SHA-1", ""),
                        "status": values.get("ExecutionStatus", ""),
                    }
                )
    timeline.sort(key=lambda item: item.get("timestamp", ""))
    return timeline
