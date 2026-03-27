from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class AnalysisEngine(ABC):
    """Gelecekteki analiz motorları için ortak arayüz."""

    def __init__(self, source: Path) -> None:
        self.source = Path(source)

    @abstractmethod
    def run(self) -> Any:
        """Analizi yürütür ve yapılandırılmış sonuç döner."""
