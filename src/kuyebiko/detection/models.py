"""Domain models for the Kuyebiko behaviour detection engine.

Defines signal classifications, evaluation outcomes, structured signal results,
window aggregate statistics, and complete multi-signal detection evaluation results.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SignalFamily(StrEnum):
    """Categorisation of behaviour signals for independent evidence accounting."""

    FILESYSTEM_ACTIVITY = "filesystem_activity"
    RENAME_DELETION = "rename_deletion"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    FILE_TRANSFORMATION = "file_transformation"
    RECOVERY_INTERFERENCE = "recovery_interference"
    CANARY_INTERACTION = "canary_interaction"
    PROCESS_ATTRIBUTION = "process_attribution"
    DATA_DESTRUCTION = "data_destruction"
    FILESYSTEM_DISCOVERY = "filesystem_discovery"
    INDICATOR_REMOVAL = "indicator_removal"


class DetectionOutcome(StrEnum):
    """Overall outcome of a detection evaluation cycle."""

    NO_DETECTION = "no_detection"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DETECTION = "detection"
    INSUFFICIENT_TELEMETRY = "insufficient_telemetry"
    EVALUATION_ERROR = "evaluation_error"


class SignalResult(BaseModel):
    """Structured result returned by an individual SignalEvaluator."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    signal_id: str = Field(min_length=1)
    signal_name: str = Field(min_length=1)
    family: SignalFamily
    triggered: bool
    severity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    observed_metric: float = Field(ge=0.0)
    threshold: float = Field(ge=0.0)
    explanation: str = Field(min_length=1)
    evidence_event_ids: list[str] = Field(default_factory=list)
    evaluated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evaluated_at_utc")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluated_at_utc must be timezone-aware")
        return value.astimezone(UTC)


class WindowAggregateStats(BaseModel):
    """Aggregated filesystem statistics within a single correlation window."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    total_events: int = Field(default=0, ge=0)
    created_count: int = Field(default=0, ge=0)
    modified_count: int = Field(default=0, ge=0)
    deleted_count: int = Field(default=0, ge=0)
    renamed_count: int = Field(default=0, ge=0)
    directory_operations_count: int = Field(default=0, ge=0)
    unique_extensions: list[str] = Field(default_factory=list)
    unique_directories: list[str] = Field(default_factory=list)
    unique_relative_paths: list[str] = Field(default_factory=list)
    rename_pairs_count: int = Field(default=0, ge=0)
    events_per_second: float = Field(default=0.0, ge=0.0)
    window_duration_seconds: float = Field(default=0.0, ge=0.0)


class DetectionResult(BaseModel):
    """Structured evaluation result produced across all evaluators for a window."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    evaluation_id: str = Field(default_factory=lambda: str(uuid4()))
    root_id: str = Field(min_length=1)
    outcome: DetectionOutcome
    evaluated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    window_start_utc: datetime
    window_end_utc: datetime
    window_duration_seconds: float = Field(ge=0.0)
    total_events_evaluated: int = Field(ge=0)
    signal_results: list[SignalResult] = Field(default_factory=list)
    triggered_signal_ids: list[str] = Field(default_factory=list)
    triggered_signal_families: list[SignalFamily] = Field(default_factory=list)
    evaluation_errors: list[str] = Field(default_factory=list)
    is_telemetry_degraded: bool = False
    degradation_reasons: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evaluated_at_utc", "window_start_utc", "window_end_utc")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamps must be timezone-aware")
        return value.astimezone(UTC)
