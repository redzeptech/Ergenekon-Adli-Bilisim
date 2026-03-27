"""
UserAssist (NTUSER.DAT) artefaktı ayrıştırması.

Windows, `UserAssist` altında ROT-13 kodlu çalıştırma kayıtları tutar.
Bu modül çevrimdışı hive dosyasından kayıtları çıkarır.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from Registry.Registry import Registry
from Registry.RegistryParse import ParseException

_USERASSIST_REL_PATH: Final[str] = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
)


@dataclass(frozen=True, slots=True)
class UserAssistRecord:
    """Tek bir UserAssist Count değeri için ayrıştırılmış alanlar."""

    artifact: str
    run_count: int
    last_run: datetime | None
    focus_count: int
    focus_time_ms: int


def decode_rot13(value: str) -> str:
    """
    Registry değer adlarında kullanılan ROT-13 kodlamasını çözer.

    Args:
        value: Ham değer adı (genellikle ROT-13 ile kodlu).

    Returns:
        Çözülmüş metin; hata durumunda orijinal metin.
    """
    try:
        return str(codecs.decode(value, "rot_13"))
    except Exception:
        return value


def filetime_to_datetime(filetime: int) -> datetime | None:
    """
    Windows FILETIME (100 ns aralıkları, 1601-01-01 epoch) değerini UTC yakın datetime'a çevirir.

    Args:
        filetime: 64-bit FILETIME tamsayısı; 0 geçersiz kabul edilir.

    Returns:
        Dönüştürülmüş `datetime` veya `filetime == 0` ise ``None``.
    """
    if filetime == 0:
        return None
    microseconds = filetime / 10
    return datetime(1601, 1, 1) + timedelta(microseconds=microseconds)


def parse_userassist_hive(hive_path: Path) -> list[UserAssistRecord]:
    """
    Tek bir NTUSER.DAT (veya benzeri) hive dosyasından UserAssist kayıtlarını okur.

    Args:
        hive_path: Çevrimdışı hive dosya yolu.

    Returns:
        Bulunan kayıtların listesi; hive açılamazsa veya anahtar yoksa boş liste.

    Raises:
        FileNotFoundError: Dosya yoksa.
    """
    path = Path(hive_path)
    if not path.is_file():
        raise FileNotFoundError(f"Hive bulunamadı: {path}")

    records: list[UserAssistRecord] = []

    try:
        hive = Registry(str(path))
        root_key = hive.open(_USERASSIST_REL_PATH)
    except (RegistryParseException, OSError, KeyError):
        return records

    for guid_key in root_key.subkeys():
        try:
            count_key = guid_key.subkey("Count")
        except Exception:
            continue

        for v in count_key.values():
            raw_name = v.name()
            decoded_name = decode_rot13(raw_name)

            raw_data = v.value()
            if not isinstance(raw_data, (bytes, bytearray)) or len(raw_data) < 68:
                continue

            run_count = int.from_bytes(raw_data[4:8], "little")
            focus_count = int.from_bytes(raw_data[8:12], "little")
            focus_time = int.from_bytes(raw_data[12:16], "little")

            last_run_ft = int.from_bytes(raw_data[60:68], "little")
            last_run_dt = filetime_to_datetime(last_run_ft)

            records.append(
                UserAssistRecord(
                    artifact=decoded_name,
                    run_count=run_count,
                    last_run=last_run_dt,
                    focus_count=focus_count,
                    focus_time_ms=focus_time,
                )
            )

    return records
