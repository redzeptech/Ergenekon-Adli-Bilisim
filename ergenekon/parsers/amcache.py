"""
Amcache.hve (Windows Application Compatibility Cache) çevrimdışı ayrıştırma.

Çıktı yapısı: ``{ kategori: { kayıt_adı: { alan: değer } } }`` — tipik olarak tek
kategori ``Amcache`` altında alt anahtarlar bulunur.
"""

from __future__ import annotations

import re
from logging import getLogger
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ergenekon.core.registry_reader import RegistryReader

AmcacheData = dict[str, dict[str, dict[str, Any]]]
logger = getLogger("ergenekon.amcache")

KEEP_FIELDS = frozenset(
    {
        "ProgramId",
        "ProgramInstanceId",
        "Name",
        "Version",
        "Publisher",
        "Language",
        "InstallDate",
        "Source",
        "RootDirPath",
        "HiddenArp",
        "UninstallString",
        "RegistryKeyPath",
        "MsiPackageCode",
        "MsiProductCode",
        "MsiInstallDate",
        "(default)",
        "FilePath",
        "SHA-1",
        "LowerCaseLongPath",
        "OriginalFileName",
        "BinFileVersion",
        "BinaryType",
        "ProductName",
        "ProductVersion",
        "LinkDate",
        "BinProductVersion",
        "Size",
        "Usn",
        "IsOsComponent",
        "RecordDate",
    }
)


class AmcacheParser:
    """
    Çevrimdışı ``Amcache.hve`` hive dosyasını okur ve kayıt sözlüğü üretir.

    Tarih süzgeci ``start`` / ``end`` (gün çözünürlüğü) isteğe bağlıdır.
    """

    def __init__(
        self,
        hive_path: Path,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> None:
        self._reader = RegistryReader(hive_path)
        self.start = start
        self.end = end

    def compute_record_date(self, vals: dict[str, Any], rec_key: Any) -> datetime:
        """Compute a record timestamp from known FILETIME fields.

        Args:
            vals: Registry value map.
            rec_key: Registry key object for timestamp fallback.

        Returns:
            Parsed datetime object.
        """
        def filetime_to_dt(ft_raw: bytes | int | None) -> datetime | None:
            try:
                if isinstance(ft_raw, bytes):
                    ft_int = int.from_bytes(ft_raw, "little", signed=False)
                elif isinstance(ft_raw, int):
                    ft_int = ft_raw
                else:
                    return None
                return datetime(1601, 1, 1) + timedelta(microseconds=ft_int // 10)
            except (TypeError, ValueError):
                return None

        for fname in ("LastModifiedTime", "LastWriteTime", "ModifiedTime", "CreationTime"):
            dt = filetime_to_dt(vals.get(fname))
            if dt:
                return dt
        return rec_key.timestamp()

    def parse(self) -> AmcacheData:
        """Parse the Amcache hive and return normalized nested records.

        Returns:
            Parsed structure as category -> record -> fields.
        """
        reg = self._reader.registry
        root = reg.open("Root")
        subs = {k.name(): k for k in root.subkeys()}
        parent = subs.get("InventoryApplicationFile") or subs.get("File") or root

        data: dict[str, dict[str, dict[str, Any]]] = {"Amcache": {}}
        for rec in parent.subkeys():
            try:
                vals = {v.name(): v.value() for v in rec.values()}
                vals["FilePath"] = vals.get("LowerCaseLongPath", rec.name())

                record_dt = self.compute_record_date(vals, rec)
                vals["RecordDate"] = record_dt.isoformat()

                if "FileId" in vals:
                    vals["SHA-1"] = vals.pop("FileId")

                rd = record_dt.date()
                if self.start and rd < self.start.date():
                    continue
                if self.end and rd > self.end.date():
                    continue

                data["Amcache"][rec.name()] = vals
            except Exception as exc:
                logger.warning(
                    "Record parse failed and skipped. record=%s error=%s",
                    rec.name(),
                    exc,
                )
                continue

        return data


def normalize_data(data: AmcacheData) -> None:
    """
    Tüm dizelerde boşluk kırpma; ``SHA-1`` / ``SHA1`` önündeki ``0000`` önekini kaldırma.

    ``data`` yerinde güncellenir.
    """
    for recs in data.values():
        for vals in recs.values():
            for k, v in list(vals.items()):
                if isinstance(v, str):
                    nv = v.strip()
                    if k in ("SHA-1", "SHA1") and nv.startswith("0000"):
                        nv = nv[4:]
                    vals[k] = nv


def find_suspicious(data: AmcacheData) -> AmcacheData:
    """
    Bilinen kötü amaçlı yazılım ad kalıplarına uyan ``.exe`` kayıtlarını süzer.
    """
    suspicious_patterns = {
        "lb3",
        "lockbit",
        "ryuk",
        "darkside",
        "conti",
        "maze",
        "emotet",
        "trickbot",
        "qbot",
        "cerber",
        "svchost",
        "scvhost",
        "svch0st",
        "svhost",
        "rundll32",
        "rundll",
        "explorer",
        "expl0rer",
        "expiorer",
        "csrss",
        "csrs",
        "winlogon",
        "winlog0n",
        "winlogin",
        "lsass",
        "lsas",
        "isass",
        "services",
        "service",
        "svces",
        "dllhost",
        "dihost",
        "dllhst",
        "conhost",
        "conhost1",
        "conhost64",
        "spoolsv",
        "splsv",
        "spools",
        "taskhostw",
        "taskhost",
        "taskhost64",
        "taskhostw1",
        "wmiprvse",
        "mshta",
        "mshta32",
        "wscript",
        "wscript1",
        "cscript",
        "cscript5",
        "regsvr32",
        "regsvr321",
    }
    hex_re = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)

    filtered: dict[str, dict[str, dict[str, Any]]] = {}
    for cat, recs in data.items():
        keep: dict[str, dict[str, Any]] = {}
        for rec, vals in recs.items():
            fp = vals.get("Name", "")
            name = Path(fp).name.lower()
            if not name.endswith(".exe"):
                continue
            stem = name[:-4]
            if (
                stem in suspicious_patterns
                or len(stem) == 1
                or stem.isdigit()
                or hex_re.match(stem)
            ):
                keep[rec] = vals
        if keep:
            filtered[cat] = keep
    return filtered


def missing_publisher(data: AmcacheData) -> AmcacheData:
    """``Publisher`` alanı boş olan kayıtları döndürür."""
    filtered: dict[str, dict[str, dict[str, Any]]] = {}
    for cat, recs in data.items():
        keep = {rec: vals for rec, vals in recs.items() if not vals.get("Publisher")}
        if keep:
            filtered[cat] = keep
    return filtered
