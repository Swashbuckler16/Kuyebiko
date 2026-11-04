import logging

from kuyebiko.utils.logging_config import (
    configure_logging,
    shutdown_logging,
)


def test_logging_creates_log_directory(tmp_path):
    log_directory = tmp_path / "logs"

    try:
        logger = configure_logging(log_directory)

        assert log_directory.exists()
        assert logger.name == "kuyebiko"
    finally:
        shutdown_logging()


def test_logging_creates_log_file(tmp_path):
    log_directory = tmp_path / "logs"

    try:
        logger = configure_logging(log_directory)

        logger.info("Kuyebiko test message")

        for handler in logger.handlers:
            handler.flush()

        log_file = log_directory / "kuyebiko.log"

        assert log_file.exists()
        assert "Kuyebiko test message" in log_file.read_text(encoding="utf-8")
    finally:
        shutdown_logging()


def test_logging_has_console_and_file_handlers(tmp_path):
    try:
        logger = configure_logging(tmp_path / "logs")

        handler_types = [type(handler) for handler in logger.handlers]

        assert any(
            issubclass(handler_type, logging.StreamHandler)
            for handler_type in handler_types
        )

        assert any(
            "RotatingFileHandler" in handler_type.__name__
            for handler_type in handler_types
        )
    finally:
        shutdown_logging()


def test_logging_does_not_duplicate_handlers(tmp_path):
    import logging
    from logging.handlers import RotatingFileHandler

    try:
        first = configure_logging(tmp_path / "logs")
        second = configure_logging(tmp_path / "logs")

        assert first is second

        file_handlers = [
            handler
            for handler in first.handlers
            if isinstance(handler, RotatingFileHandler)
        ]

        console_handlers = [
            handler
            for handler in first.handlers
            if type(handler) is logging.StreamHandler
        ]

        assert len(file_handlers) == 1
        assert len(console_handlers) == 1

    finally:
        shutdown_logging()


def test_logging_shutdown_removes_handlers(tmp_path):
    logger = configure_logging(tmp_path / "logs")

    shutdown_logging()

    assert len(logger.handlers) == 0
