"""
utils/logger.py

Configures structured logging for the pipeline.
Outputs to both console (coloured) and a rotating log file.
"""

import logging
import logging.handlers
import os
from pathlib import Path


class ColouredFormatter(logging.Formatter):
    """Add ANSI colour codes to log level names for terminal readability."""

    COLOURS = {
        logging.DEBUG:    "\033[36m",   # Cyan
        logging.INFO:     "\033[32m",   # Green
        logging.WARNING:  "\033[33m",   # Yellow
        logging.ERROR:    "\033[31m",   # Red
        logging.CRITICAL: "\033[35m",   # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        colour = self.COLOURS.get(record.levelno, "")
        record.levelname = f"{colour}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with:
      - Coloured console output
      - Rotating file handler (tpot_pipeline.log, 5MB x 3 backups)
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger  # Already configured

    fmt = "%(asctime)s  %(levelname)s %(name)s: %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(ColouredFormatter(fmt, datefmt=date_fmt))
    logger.addHandler(ch)

    # File handler (plain, no colours)
    log_file = Path("tpot_pipeline.log")
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)  # File always gets DEBUG
    fh.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
    logger.addHandler(fh)

    return logger
