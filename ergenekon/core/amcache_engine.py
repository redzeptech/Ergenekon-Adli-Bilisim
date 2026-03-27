from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ergenekon.core.engine import AnalysisEngine
from ergenekon.parsers.amcache import AmcacheParser, normalize_data


class AmcacheEngine(AnalysisEngine):
    """
    ``Amcache.hve`` için analiz motoru: ayrıştırma ve isteğe bağlı alan normalizasyonu.

    Tarih aralığı ``start`` / ``end`` ile gün bazında süzülür. Ek süzgeçler
    (metin arama, şüpheli desen, yayıncı boş vb.) üst katmanda uygulanır.
    """

    def __init__(
        self,
        source: Path | str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        normalize: bool = True,
    ) -> None:
        """Initialize the Amcache analysis engine.

        Args:
            source: Path to the `Amcache.hve` hive file.
            start: Optional start date filter.
            end: Optional end date filter.
            normalize: Enables post-parse field normalization.
        """
        super().__init__(Path(source))
        self.start = start
        self.end = end
        self.normalize = normalize

    def run(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Run parsing pipeline and optionally normalize parsed records.

        Returns:
            Category -> record name -> field map.
        """
        parser = AmcacheParser(self.source, self.start, self.end)
        data = parser.parse()
        if self.normalize:
            normalize_data(data)
        return data
