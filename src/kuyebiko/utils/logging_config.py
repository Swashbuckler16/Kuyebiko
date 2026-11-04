import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from kuyebiko.core.config import get_settings


def configure_logging(
    log_directory: Path | str = Path("logs"),
) -> logging.Logger:
    """Configure Kuyebiko's centralized logging system."""

    settings = get_settings()

    logger = logging.getLogger("kuyebiko")

    # Avoid duplicate handlers if configuration is called again.
    if getattr(logger, "_kuyebiko_configured", False):
        return logger

    logger.setLevel(settings.log_level)
    logger.propagate = False

    log_directory = Path(log_directory)
    log_directory.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt=("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(settings.log_level)
    console_handler.setFormatter(formatter)

    # Rotating file handler
    file_handler = RotatingFileHandler(
        filename=log_directory / "kuyebiko.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )

    file_handler.setLevel(settings.log_level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger._kuyebiko_configured = True

    return logger


def shutdown_logging() -> None:
    """Flush and close Kuyebiko logging handlers."""

    logger = logging.getLogger("kuyebiko")

    for handler in logger.handlers[:]:
        handler.flush()
        handler.close()
        logger.removeHandler(handler)

    logger._kuyebiko_configured = False
