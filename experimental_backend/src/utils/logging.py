"""
Logging Configuration
Structured logging setup with proper formatting and configuration.
"""

import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from ..config import config


def setup_logging() -> None:
    """Set up structured logging configuration."""

    # Create logs directory if it doesn't exist
    log_dir = Path("./logs")
    log_dir.mkdir(exist_ok=True)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.settings.LOG_LEVEL))

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, config.settings.LOG_LEVEL))

    # File handler (if configured)
    file_handler = None
    if config.settings.LOG_FILE:
        log_file_path = Path(config.settings.LOG_FILE)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=config.settings.LOG_MAX_SIZE,
            backupCount=config.settings.LOG_BACKUP_COUNT
        )
        file_handler.setLevel(getattr(logging, config.settings.LOG_LEVEL))

    # Create formatter
    formatter = logging.Formatter(
        fmt=config.settings.LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Set formatter for handlers
    console_handler.setFormatter(formatter)
    if file_handler:
        file_handler.setFormatter(formatter)

    # Add handlers to root logger
    root_logger.addHandler(console_handler)
    if file_handler:
        root_logger.addHandler(file_handler)


class StructuredLogger:
    """Logger with structured logging capabilities."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def info(self, message: str, **kwargs) -> None:
        """Log info message with structured data."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with structured data."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        """Log error message with structured data."""
        self._log(logging.ERROR, message, **kwargs)

    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with structured data."""
        self._log(logging.DEBUG, message, **kwargs)

    def _log(self, level: int, message: str, **kwargs) -> None:
        """Internal logging method with structured data."""
        # Add timestamp if not present
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.utcnow().isoformat()

        # Log with structured data
        self.logger.log(level, message, extra=kwargs)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)
