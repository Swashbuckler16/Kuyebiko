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


class IncidentSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentConfidence(StrEnum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INSUFFICIENT = "insufficient"


class IncidentStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class SecurityIncident(BaseModel):
    """Represents a security incident detected by Kuyebiko."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    incident_id: str = Field(default_factory=lambda: str(uuid4()))

    root_id: str = Field(min_length=1)

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)

    severity: IncidentSeverity
    confidence: IncidentConfidence

    risk_score: int = Field(ge=0, le=100)

    status: IncidentStatus = IncidentStatus.OPEN

    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    evidence_event_ids: list[str] = Field(default_factory=list)

    signal_families: list[str] = Field(default_factory=list)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Incident timestamps must be timezone-aware")

        return value.astimezone(UTC)

    @field_validator("evidence_event_ids", "signal_families")
    @classmethod
    def validate_unique_entries(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("Entries cannot be empty")

        if len(values) != len(set(values)):
            raise ValueError("Duplicate entries are not allowed")

        return values

    @model_validator(mode="after")
    def validate_timeline(self):
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot be earlier than first_seen")

        return self
