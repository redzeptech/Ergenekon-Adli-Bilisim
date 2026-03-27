from __future__ import annotations

from pathlib import Path

from Registry.Registry import Registry
from Registry.RegistryParse import ParseException

from ergenekon.core.exceptions import HiveParseError


class RegistryReader:
    """
    Çevrimdışı Windows registry hive dosyasını güvenli biçimde açar.

    ``python-registry`` kütüphanesini kullanır; açılış başarısızsa
    :class:`HiveParseError` veya ``FileNotFoundError`` fırlatır.
    """

    def __init__(self, hive_path: Path | str) -> None:
        self.path = Path(hive_path)
        if not self.path.exists():
            raise FileNotFoundError(f"Hive bulunamadı: {self.path}")
        try:
            self._registry: Registry = Registry(str(self.path))
        except ParseException as exc:
            raise HiveParseError(f"Geçersiz veya bozuk hive: {self.path}") from exc

    @property
    def registry(self) -> Registry:
        """Açılmış hive nesnesi (alt anahtar gezintisi için)."""
        return self._registry
