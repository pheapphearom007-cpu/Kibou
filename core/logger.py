"""
Logging infrastructure for Kibuo Reconnaissance Toolkit.

Sets up structured file and stream logging, suppresses sensitive data,
and provides per-assessment logging capabilities.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional

# Secret patterns to mask from logs
SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key[\"']?\s*[:=]\s*[\"']?)([a-zA-Z0-9_\-\.]{12,})([\"']?)", re.IGNORECASE),
    re.compile(r"(token[\"']?\s*[:=]\s*[\"']?)([a-zA-Z0-9_\-\.]{12,})([\"']?)", re.IGNORECASE),
    re.compile(r"(password[\"']?\s*[:=]\s*[\"']?)([^\s\"';&]{3,})([\"']?)", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)([a-zA-Z0-9_\-\.]{12,})()", re.IGNORECASE),
]


class SanitizedFormatter(logging.Formatter):
    """Formatter that strips out potential tokens, secrets, and credentials."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in SECRET_PATTERNS:
            msg = pattern.sub(r"\1[REDACTED]\3", msg)
        return msg


def setup_logger(
    name: str = "kibuo",
    log_dir: str = "logs",
    level: int = logging.INFO
) -> logging.Logger:
    """
    Configure and return a sanitized logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers if re-called
    if logger.handlers:
        return logger

    # Ensure log directory exists
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.FileHandler(log_path / "kibuo_general.log", encoding="utf-8")
    file_handler.setLevel(level)
    
    formatter = SanitizedFormatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(funcName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "kibuo") -> logging.Logger:
    """Retrieve existing logger or initialize default."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger
