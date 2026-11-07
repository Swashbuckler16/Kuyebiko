"""Evaluation context supplied to behaviour signal evaluators.

Encapsulates root identity, filtered window events, aggregate metrics,
evaluation timestamps, and telemetry quality state without permitting
file modifications or outside I/O.
"""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kuyebiko.detection.models import WindowAggregateStats
from kuyebiko.models.events import FileEvent, TelemetryQuality


class DetectionContext(BaseModel):
    """Immutable evaluation context provided to SignalEvaluator instances."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    root_id: str = Field(min_length=1)
    events: list[FileEvent] = Field(default_factory=list)
    stats: WindowAggregateStats
    evaluated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evaluated_monotonic_ns: int = Field(ge=0)
    window_start_utc: datetime
    window_end_utc: datetime
    window_duration_seconds: float = Field(ge=0.0)
    quality: TelemetryQuality = TelemetryQuality.NORMAL
    is_telemetry_degraded: bool = False
    degradation_reason: str | None = None
    uncounted_kernel_loss: bool = False
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evaluated_at_utc", "window_start_utc", "window_end_utc")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamps must be timezone-aware")
        return value.astimezone(UTC)
