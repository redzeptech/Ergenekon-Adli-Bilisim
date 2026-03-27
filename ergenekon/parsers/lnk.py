from __future__ import annotations

from pathlib import Path
from typing import Any


class LnkParser:
    """Windows .lnk kısayol ayrıştırıcısı (iskelet — ileride pylnk / özel binary parser)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def parse(self) -> dict[str, Any]:
        raise NotImplementedError(
            "LNK ayrıştırma henüz uygulanmadı; gelecek sürümde eklenecek."
        )
