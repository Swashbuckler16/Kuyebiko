from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class KuyebikoSettings(BaseSettings):
    """Central application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="KUYEBIKO_",
        extra="ignore",
    )

    # Application
    app_name: str = "Kuyebiko"
    app_version: str = "0.1.0"
    debug: bool = False

    # Database
    database_path: Path = Path("data/kuyebiko.db")

    # Monitoring
    monitoring_enabled: bool = False
    event_queue_size: int = Field(default=10000, ge=100, le=1000000)

    # Data retention
    raw_event_retention_days: int = Field(default=14, ge=1)
    incident_retention_days: int = Field(default=90, ge=1)

    # Logging
    log_level: Literal[
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ] = "INFO"


@lru_cache
def get_settings() -> KuyebikoSettings:
    """Return a cached application settings instance."""
    return KuyebikoSettings()
