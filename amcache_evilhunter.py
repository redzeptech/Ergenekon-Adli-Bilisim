#!/usr/bin/env python3
"""
Geriye dönük uyumluluk: bu dosya yerine ``amcache-evilhunter`` (PATH) veya
``python -m ergenekon.cli.amcache_cli`` kullanın.

Özgün proje: Cristian Souza — Ergenekon modüler paketi: ``ergenekon``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if (_ROOT / "ergenekon").is_dir() and str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ergenekon.cli.amcache_cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nİptal edildi.", file=sys.stderr)
        sys.exit(130)
