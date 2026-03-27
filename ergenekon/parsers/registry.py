from __future__ import annotations

from pathlib import Path
from typing import Any

from ergenekon.core.registry_reader import RegistryReader


class GenericRegistryParser:
    """
    Genel hive gezinti iskeleti; alt anahtar / değer çıkarımı ileride genişletilebilir.
    Şimdilik yalnızca kök açılışı doğrular.
    """

    def __init__(self, hive_path: Path) -> None:
        self._reader = RegistryReader(hive_path)

    def open(self) -> Any:
        return self._reader.registry
