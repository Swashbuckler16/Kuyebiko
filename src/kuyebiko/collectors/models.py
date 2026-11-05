from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kuyebiko.models.events import (
    EventSource,
    EventType,
    FileEvent,
    TelemetryQuality,
)


class WindowsFileAction(IntEnum):
    """Windows filesystem notification actions from FILE_NOTIFY_INFORMATION."""

    ADDED = 1
    REMOVED = 2
    MODIFIED = 3
    RENAMED_OLD_NAME = 4
    RENAMED_NEW_NAME = 5


class MonitoredRoot(BaseModel):
    """Configuration for a monitored filesystem root directory."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    root_id: str = Field(min_length=1)
    path: Path
    recursive: bool = True
    enabled: bool = True

    @field_validator("path", mode="before")
    @classmethod
    def validate_path(cls, value: str | Path) -> Path:
        raw_path = Path(value)
        expanded = raw_path.expanduser()

        if not expanded.is_absolute():
            raise ValueError(f"Monitored root path must be absolute: '{value}'")

        if not expanded.exists():
            raise ValueError(f"Monitored root path does not exist: '{expanded}'")

        if not expanded.is_dir():
            raise ValueError(f"Monitored root path must be a directory: '{expanded}'")

        return expanded

    def resolved_path(self) -> Path:
        """Return the resolved canonical path for the monitored directory."""
        return self.path.resolve()

    def resolve_and_validate(self) -> Path:
        """Resolve and verify that the monitored directory remains valid."""
        resolved = self.resolved_path()
        if not resolved.exists():
            raise ValueError(
                f"Monitored directory was removed or is inaccessible: '{resolved}'"
            )
        if not resolved.is_dir():
            raise ValueError(f"Monitored path is no longer a directory: '{resolved}'")
        return resolved


class RawFileNotification(BaseModel):
    """Raw notification event emitted directly by a filesystem watcher."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    root_id: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)
    action: WindowsFileAction
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    monotonic_ns: int = Field(ge=0)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Relative path cannot be empty")

        normalized = value.replace("\\", "/").strip()

        if not normalized:
            raise ValueError("Relative path cannot be empty")

        if normalized.startswith("/") or normalized.startswith("//"):
            raise ValueError(f"Path must be relative to the monitored root: '{value}'")

        if len(normalized) >= 2 and normalized[1] == ":":
            raise ValueError(f"Drive-qualified paths are not allowed: '{value}'")

        if any(part == ".." for part in normalized.split("/")):
            raise ValueError(
                f"Path traversal sequences ('..') are not allowed: '{value}'"
            )

        return normalized

    @field_validator("observed_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include timezone information")
        return value.astimezone(UTC)

    def to_file_event(
        self,
        sequence_number: int = 0,
        quality: TelemetryQuality = TelemetryQuality.NORMAL,
        old_path: str | None = None,
        new_path: str | None = None,
    ) -> FileEvent:
        """Convert raw notification to a Phase 1 FileEvent domain model.

        Raises:
            ValueError: If attempting to convert a rename action without both
                old_path and new_path correlated.
        """
        action_mapping = {
            WindowsFileAction.ADDED: EventType.CREATED,
            WindowsFileAction.MODIFIED: EventType.MODIFIED,
            WindowsFileAction.REMOVED: EventType.DELETED,
        }

        if self.action in (
            WindowsFileAction.RENAMED_OLD_NAME,
            WindowsFileAction.RENAMED_NEW_NAME,
        ):
            if not old_path or not new_path:
                msg = (
                    f"Cannot convert raw rename notification ({self.action.name}) "
                    "to FileEvent without both old_path and new_path; raw rename "
                    "notifications must be preserved until correlated by normalizer."
                )
                raise ValueError(msg)
            event_type = EventType.RENAMED
            event_path = new_path
            event_old_path = old_path
            event_new_path = new_path
        else:
            event_type = action_mapping[self.action]
            event_path = self.relative_path
            event_old_path = old_path
            event_new_path = new_path

        return FileEvent(
            root_id=self.root_id,
            file_path=event_path,
            event_type=event_type,
            old_path=event_old_path,
            new_path=event_new_path,
            timestamp_utc=self.observed_at,
            monotonic_ns=self.monotonic_ns,
            source=EventSource.WINDOWS_WATCHER,
            sequence_number=sequence_number,
            quality=quality,
        )
