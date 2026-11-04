from pathlib import Path

import pytest
from pydantic import ValidationError

from kuyebiko.core.config import KuyebikoSettings, get_settings


def test_default_configuration():
    settings = KuyebikoSettings(_env_file=None)

    assert settings.app_name == "Kuyebiko"
    assert settings.app_version == "0.1.0"
    assert settings.monitoring_enabled is False
    assert settings.event_queue_size == 10000


def test_default_database_path():
    settings = KuyebikoSettings(_env_file=None)

    assert settings.database_path == Path("data/kuyebiko.db")


def test_environment_variable_override(monkeypatch):
    monkeypatch.setenv("KUYEBIKO_APP_NAME", "Kuyebiko-Test")
    monkeypatch.setenv("KUYEBIKO_MONITORING_ENABLED", "true")

    settings = KuyebikoSettings(_env_file=None)

    assert settings.app_name == "Kuyebiko-Test"
    assert settings.monitoring_enabled is True


def test_invalid_queue_size_rejected():
    with pytest.raises(ValidationError):
        KuyebikoSettings(
            _env_file=None,
            event_queue_size=10,
        )


def test_invalid_retention_period_rejected():
    with pytest.raises(ValidationError):
        KuyebikoSettings(
            _env_file=None,
            raw_event_retention_days=0,
        )


def test_invalid_log_level_rejected():
    with pytest.raises(ValidationError):
        KuyebikoSettings(
            _env_file=None,
            log_level="INVALID",
        )


def test_settings_are_cached():
    get_settings.cache_clear()

    first = get_settings()
    second = get_settings()

    assert first is second

    get_settings.cache_clear()
