from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class MonitoringStatus(StrEnum):
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    ERROR = "error"


class CollectorStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    ERROR = "error"


class TelemetrySnapshot(BaseModel):
    """Represents the operational health of Kuyebiko monitoring."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))

    collector_id: str = Field(min_length=1)
    root_id: str = Field(min_length=1)

    monitoring_status: MonitoringStatus = MonitoringStatus.STOPPED
    collector_status: CollectorStatus = CollectorStatus.INACTIVE

    events_received: int = Field(default=0, ge=0)
    events_dropped: int = Field(default=0, ge=0)

    # Uncertainty and gap quantification
    uncounted_event_loss: bool = False
    gap_count: int = Field(default=0, ge=0)
    overflow_count: int = Field(default=0, ge=0)

    queue_capacity: int = Field(default=10000, ge=1)
    queue_depth: int = Field(default=0, ge=0)

    collection_errors: int = Field(default=0, ge=0)

    last_heartbeat: datetime | None = None
    last_event_at: datetime | None = None

    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    degradation_reasons: list[str] = Field(default_factory=list)

    @field_validator(
        "last_heartbeat",
        "last_event_at",
        "observed_at",
    )
    @classmethod
    def ensure_utc(cls, value):
        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Telemetry timestamps must include timezone information")

        return value.astimezone(UTC)

    @field_validator("degradation_reasons")
    @classmethod
    def validate_reasons(cls, values):
        if any(not value.strip() for value in values):
            raise ValueError("Degradation reasons cannot be empty")

        if len(values) != len(set(values)):
            raise ValueError("Duplicate degradation reasons are not allowed")

        return values

    @model_validator(mode="after")
    def validate_queue(self):
        if self.queue_depth > self.queue_capacity:
            raise ValueError("Queue depth cannot exceed queue capacity")

        return self
