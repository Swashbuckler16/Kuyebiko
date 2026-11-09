"""Advanced detection contracts, capability definitions, and metadata models.

Establishes the capability requirement framework separating what Kuyebiko can
observe from what it attempts to detect, ensuring missing telemetry produces
explicit capability limitations rather than fabricated positive/negative claims.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TypeVar
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
    optional_capabilities: list[TelemetryCapability] = Field(default_factory=list)
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


T_AuxiliaryEvent = TypeVar(
    "T_AuxiliaryEvent",
    ProcessTelemetryEvent,
    EventLogTelemetryEvent,
    DiscoveryTelemetryEvent,
)


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

    def get_available_capabilities(
        self, context: DetectionContext
    ) -> set[TelemetryCapability]:
        """Extract available telemetry capabilities declared in the context."""
        raw_caps = context.config.get("available_capabilities")
        if raw_caps is None:
            return {TelemetryCapability.FILESYSTEM_METADATA}
        if isinstance(raw_caps, (set, list, tuple)):
            available: set[TelemetryCapability] = set()
            for c in raw_caps:
                if isinstance(c, TelemetryCapability):
                    available.add(c)
                else:
                    try:
                        available.add(TelemetryCapability(str(c)))
                    except ValueError:
                        continue
            return available
        return {TelemetryCapability.FILESYSTEM_METADATA}

    def is_capability_available(
        self, capability: TelemetryCapability, context: DetectionContext
    ) -> bool:
        """Check if a specific telemetry capability is available in context."""
        return capability in self.get_available_capabilities(context)

    def scope_auxiliary_telemetry(
        self,
        events: list[T_AuxiliaryEvent],
        context: DetectionContext,
    ) -> tuple[list[T_AuxiliaryEvent], list[dict[str, Any]]]:
        """Scope auxiliary telemetry events to the context root and time horizon.

        Filters events to ensure root identity matches and event timestamp falls
        within the active evaluation window.

        Returns:
            A tuple of (valid_scoped_events, rejected_events_metadata).
        """
        scoped: list[T_AuxiliaryEvent] = []
        rejected: list[dict[str, Any]] = []

        window_duration_ns = int(
            max(0.0, context.window_duration_seconds) * 1_000_000_000
        )
        window_start_ns = max(0, context.evaluated_monotonic_ns - window_duration_ns)

        for ev in events:
            if ev.root_id != context.root_id:
                rejected.append(
                    {
                        "event_id": ev.event_id,
                        "reason": "cross_root",
                        "root_id": ev.root_id,
                        "expected_root_id": context.root_id,
                    }
                )
                continue

            in_window = True
            if ev.monotonic_ns > 0 and context.evaluated_monotonic_ns > 0:
                if (
                    ev.monotonic_ns < window_start_ns
                    or ev.monotonic_ns > context.evaluated_monotonic_ns
                ):
                    in_window = False
            else:
                if (
                    ev.timestamp_utc < context.window_start_utc
                    or ev.timestamp_utc > context.window_end_utc
                ):
                    in_window = False

            if not in_window:
                rejected.append(
                    {
                        "event_id": ev.event_id,
                        "reason": "out_of_window",
                        "monotonic_ns": ev.monotonic_ns,
                        "window_start_ns": window_start_ns,
                        "window_end_ns": context.evaluated_monotonic_ns,
                    }
                )
                continue

            scoped.append(ev)

        return scoped, rejected

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
        available = self.get_available_capabilities(context)
        return [
            cap for cap in self._metadata.required_capabilities if cap not in available
        ]

    @abstractmethod
    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Execute domain-specific behavioural detection assuming capabilities exist."""
        ...
