from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from pathlib import Path


def configure_logging(level: int = logging.INFO, name: str = "ergenekon") -> logging.Logger:
    """Configure a shared logger with file and stderr handlers.

    Args:
        level: Logging level for all handlers.
        name: Logger namespace name.

    Returns:
        Configured logger instance.
    """
    log = logging.getLogger(name)
    if log.handlers:
        return log

    log.setLevel(level)
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "forensics.log"

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )

    log.addHandler(file_handler)
    log.addHandler(stream_handler)
    log.propagate = False
    log.info("Logging initialized. file=%s", log_file)
    computer_name = os.getenv("COMPUTERNAME", "UNKNOWN_HOST")
    log.info(
        "Analiz Baslatildi | bilgisayar=%s | zaman=%s",
        computer_name,
        datetime.now().isoformat(timespec="seconds"),
    )
    return log
