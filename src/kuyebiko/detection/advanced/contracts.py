"""Advanced detection contracts, capability definitions, and metadata models.

Establishes the capability requirement framework separating what Kuyebiko can
observe from what it attempts to detect, ensuring missing telemetry produces
explicit capability limitations rather than fabricated positive/negative claims.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.contracts import BaseSignalEvaluator
from kuyebiko.detection.models import SignalFamily, SignalResult


class TelemetryCapability(StrEnum):
    """Observable telemetry capabilities available from collection sources."""

    FILESYSTEM_METADATA = "filesystem_metadata"
    PROCESS_EXECUTION = "process_execution"
    EVENT_LOG = "event_log"
    FILESYSTEM_READ_ACCESS = "filesystem_read_access"


class SignalMetadata(BaseModel):
    """Metadata describing capabilities, evidence requirements, and limitations."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    signal_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    family: SignalFamily
    mitre_technique: str | None = None
    description: str = Field(min_length=1)
    required_capabilities: list[TelemetryCapability] = Field(
        default_factory=lambda: [TelemetryCapability.FILESYSTEM_METADATA]
    )
    evidence_requirements: str = Field(min_length=1)
    confidence_limitations: str = Field(min_length=1)
    threshold: float = Field(ge=0.0)
    default_threshold: float = Field(ge=0.0)
    min_events: int = Field(default=1, ge=1)


class ProcessTelemetryEvent(BaseModel):
    """Telemetry representation of a process execution / creation event."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    root_id: str = Field(min_length=1)
    process_id: int = Field(ge=0)
    process_name: str = Field(min_length=1)
    command_line: str = Field(min_length=1)
    parent_process_id: int | None = None
    parent_process_name: str | None = None
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    monotonic_ns: int = Field(ge=0)
    user_sid: str | None = None


class EventLogTelemetryEvent(BaseModel):
    """Telemetry representation of a Windows Event Log record."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    root_id: str = Field(min_length=1)
    provider_name: str = Field(min_length=1)
    channel: str = Field(min_length=1)
    event_code: int = Field(ge=0)
    message: str = ""
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    monotonic_ns: int = Field(ge=0)


class DiscoveryTelemetryEvent(BaseModel):
    """Telemetry representation of a directory read or enumeration access."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    root_id: str = Field(min_length=1)
    target_directory: str = Field(min_length=1)
    operation: str = Field(default="enumerate_directory")
    process_id: int | None = None
    process_name: str | None = None
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    monotonic_ns: int = Field(ge=0)


class AdvancedSignalEvaluator(BaseSignalEvaluator, ABC):
    """Base class for advanced behavioural signal evaluators with telemetry checks."""

    def __init__(
        self,
        metadata: SignalMetadata,
        is_enabled: bool = True,
    ) -> None:
        super().__init__(
            signal_id=metadata.signal_id,
            name=metadata.name,
            family=metadata.family,
            threshold=metadata.threshold,
            is_enabled=is_enabled,
            min_events=metadata.min_events,
        )
        self._metadata = metadata

    @property
    def metadata(self) -> SignalMetadata:
        """Comprehensive metadata describing signal requirements and boundaries."""
        return self._metadata

    def evaluate(self, context: DetectionContext) -> SignalResult:
        """Evaluate behavioural criteria with explicit telemetry capability checks."""
        if not self._is_enabled:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=f"Signal {self._signal_id} is disabled",
                severity_score=0.0,
                metadata={"disabled": True},
            )

        # Check telemetry capabilities provided by context
        missing = self.get_missing_capabilities(context)
        if missing:
            missing_names = [c.value for c in missing]
            req_names = [c.value for c in self._metadata.required_capabilities]
            limitation_msg = (
                f"Missing required telemetry capabilities: {', '.join(missing_names)}"
            )
            tech = self._metadata.mitre_technique or "Advanced"
            req_str = ", ".join(req_names)
            explanation = (
                f"Signal {self._signal_id} ({tech}) cannot be evaluated: "
                f"{limitation_msg} (requires {req_str})"
            )
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=explanation,
                severity_score=0.0,
                metadata={
                    "capability_limitation": limitation_msg,
                    "missing_capabilities": missing_names,
                    "required_capabilities": req_names,
                    "mitre_technique": self._metadata.mitre_technique,
                },
            )

        return self.evaluate_advanced(context)

    def get_missing_capabilities(
        self, context: DetectionContext
    ) -> list[TelemetryCapability]:
        """Determine which required capabilities are unavailable in the context."""
        raw_caps = context.config.get("available_capabilities")
        if raw_caps is None:
            # Default collector environment capability is FILESYSTEM_METADATA
            available = {TelemetryCapability.FILESYSTEM_METADATA}
        elif isinstance(raw_caps, (set, list, tuple)):
            available = {
                c if isinstance(c, TelemetryCapability) else TelemetryCapability(c)
                for c in raw_caps
            }
        else:
            available = {TelemetryCapability.FILESYSTEM_METADATA}

        return [
            cap for cap in self._metadata.required_capabilities if cap not in available
        ]

    @abstractmethod
    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Execute domain-specific behavioural detection assuming capabilities exist."""
        ...
