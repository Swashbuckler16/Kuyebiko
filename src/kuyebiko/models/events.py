from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EventType(StrEnum):
    CREATED = "created"
    MODIFIED = "modified"
    RENAMED = "renamed"
    DELETED = "deleted"


class CorrelationProvenanceType(StrEnum):
    """Origin classification for rename correlation evidence."""

    PHASE3_CORRELATOR = "phase3_correlator"
    RENAME_CORRELATOR = "rename_correlator"  # Backward-compatible alias
    SIMULATOR = "simulator"
    EXPLICIT_PAIR = "explicit_pair"
    UNTRUSTED = "untrusted"


def is_approved_rename_provenance(provenance: str | None) -> bool:
    """Return True if provenance originates from a trusted correlator or simulator."""
    if not provenance:
        return False
    return provenance.startswith(
        (
            f"{CorrelationProvenanceType.PHASE3_CORRELATOR}:",
            f"{CorrelationProvenanceType.RENAME_CORRELATOR}:",
            f"{CorrelationProvenanceType.SIMULATOR}:",
        )
    )


class EventSource(StrEnum):
    WINDOWS_WATCHER = "windows_watcher"
    SYSMON = "sysmon"
    ETW = "etw"
    SIMULATOR = "simulator"


class TelemetryQuality(StrEnum):
    NORMAL = "normal"
    DELAYED = "delayed"
    DEGRADED = "degraded"
    RECOVERED = "recovered"


class FileEvent(BaseModel):
    """Normalized filesystem event collected by Kuyebiko."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    event_id: str = Field(default_factory=lambda: str(uuid4()))

    root_id: str = Field(min_length=1)
    file_path: str = Field(min_length=1)

    event_type: EventType

    old_path: str | None = None
    new_path: str | None = None
    is_directory: bool | None = None
    correlation_provenance: str | None = None

    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))

    monotonic_ns: int = Field(ge=0)

    source: EventSource

    sequence_number: int = Field(default=0, ge=0)

    quality: TelemetryQuality = TelemetryQuality.NORMAL

    @field_validator("timestamp_utc")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp_utc must include timezone information")

        return value.astimezone(UTC)

    @field_validator("file_path", "old_path", "new_path")
    @classmethod
    def validate_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.replace("\\", "/")

        if normalized.startswith("/") or normalized.startswith("//"):
            raise ValueError("File paths must be relative to the monitored root")

        if len(normalized) >= 2 and normalized[1] == ":":
            raise ValueError("Absolute Windows paths are not allowed")

        if any(part == ".." for part in normalized.split("/")):
            raise ValueError("Path traversal is not allowed")

        if not normalized:
            raise ValueError("File path cannot be empty")

        return normalized

    @field_validator("correlation_provenance")
    @classmethod
    def validate_correlation_provenance(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if ":" not in value:
            raise ValueError(
                "correlation_provenance must follow the format "
                "'<provenance_type>:<details>'"
            )
        prefix, _ = value.split(":", 1)
        valid_prefixes = {t.value for t in CorrelationProvenanceType}
        if prefix not in valid_prefixes:
            allowed = sorted(valid_prefixes)
            msg = (
                f"Invalid correlation_provenance type '{prefix}'. "
                f"Must be one of {allowed}"
            )
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def validate_rename_paths(self):
        if self.event_type == EventType.RENAMED:
            if not self.old_path or not self.new_path:
                raise ValueError("Rename events require both old_path and new_path")

            if self.file_path != self.new_path:
                raise ValueError("file_path must match new_path for rename events")

        elif self.old_path is not None or self.new_path is not None:
            raise ValueError("old_path and new_path are only valid for rename events")

        return self
