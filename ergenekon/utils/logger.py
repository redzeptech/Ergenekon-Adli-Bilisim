"""Backward-friendly logger helper module."""

from __future__ import annotations

import logging

from ergenekon.utils.logging_config import configure_logging


def get_logger(name: str = "ergenekon", level: int = logging.INFO) -> logging.Logger:
    """Create or return a configured logger instance.

    Args:
        name: Logger namespace.
        level: Logging level.

    Returns:
        Configured logger object.
    """
    return configure_logging(level=level, name=name)
