"""
UserAssist toplu analiz motoru: dizin ağacında NTUSER.DAT arar.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ergenekon.core.engine import AnalysisEngine
from ergenekon.parsers.userassist import UserAssistRecord, parse_userassist_hive


@dataclass(frozen=True, slots=True)
class UserAssistRow:
    """Kullanıcı klasörü + hive'den gelen tek satır (raporlama için)."""

    windows_user: str
    record: UserAssistRecord


class UserAssistEngine(AnalysisEngine):
    """
    Verilen kök dizinde `NTUSER.DAT` dosyalarını bularak UserAssist kayıtlarını toplar.

    Varsayılan olarak her kullanıcı klasörünün adı `windows_user` alanına yazılır
    (klasör yapısı: ``.../KullaniciAdi/NTUSER.DAT``).
    """

    def __init__(
        self,
        root_directory: Path,
        *,
        user_filter: str | None = None,
    ) -> None:
        super().__init__(Path(root_directory))
        self._user_filter = user_filter.lower() if user_filter else None

    def run(self) -> list[UserAssistRow]:
        """
        Dizini dolaşır ve eşleşen hive'ler için kayıtları birleştirir.

        Returns:
            Sıralı `UserAssistRow` listesi (sıra dosya sistemi gezintisine bağlıdır).
        """
        rows: list[UserAssistRow] = []
        root = self.source.resolve()

        if not root.is_dir():
            return rows

        for hive_path in root.rglob("*"):
            if not hive_path.is_file() or hive_path.name.lower() != "ntuser.dat":
                continue
            user_folder = hive_path.parent.name
            if self._user_filter and user_folder.lower() != self._user_filter:
                continue
            try:
                parsed = parse_userassist_hive(hive_path)
            except FileNotFoundError:
                continue
            for rec in parsed:
                rows.append(UserAssistRow(windows_user=user_folder, record=rec))

        return rows
