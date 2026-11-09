"""Architectural interfaces and protocols for behaviour detection.

Defines the SignalEvaluator protocol, engine consumer interface, and contract
specifications for ransomware behaviour evaluation.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import DetectionResult, SignalFamily, SignalResult
from kuyebiko.models.events import FileEvent
from kuyebiko.processing.ordering import EventOrderingMetadata


@runtime_checkable
class SignalEvaluator(Protocol):
    """Interface for independent, deterministic behaviour signal evaluators."""

    @property
    def signal_id(self) -> str:
        """Unique identifier for the behaviour signal."""
        ...

    @property
    def name(self) -> str:
        """Human-readable display name for the behaviour signal."""
        ...

    @property
    def family(self) -> SignalFamily:
        """Categorical signal family for multi-factor correlation."""
        ...

    @property
    def is_enabled(self) -> bool:
        """Whether this signal evaluator is currently enabled."""
        ...

    @property
    def threshold(self) -> float:
        """Configured triggering threshold."""
        ...

    def evaluate(self, context: DetectionContext) -> SignalResult:
        """Evaluate behavioural criteria against the provided detection context.

        Must be deterministic, side-effect free, and read-only.
        """
        ...


@runtime_checkable
class DetectionEngineProtocol(Protocol):
    """Protocol for the top-level behaviour detection engine."""

    def process_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
    ) -> DetectionResult | None:
        """Ingest a normalized event, update root window, and evaluate."""
        ...

    def evaluate_root(
        self,
        root_id: str,
        now_monotonic_ns: int | None = None,
    ) -> DetectionResult:
        """Perform an explicit evaluation cycle for a specific monitored root."""
        ...


class BaseSignalEvaluator(ABC):
    """Abstract base class for all Kuyebiko behaviour signal evaluators."""

    def __init__(
        self,
        signal_id: str,
        name: str,
        family: SignalFamily,
        threshold: float,
        is_enabled: bool = True,
        min_events: int = 1,
    ) -> None:
        if not signal_id.strip():
            raise ValueError("signal_id cannot be empty")
        if not name.strip():
            raise ValueError("name cannot be empty")
        if threshold < 0.0:
            raise ValueError(f"threshold must be non-negative, got {threshold}")
        if min_events < 0:
            raise ValueError(f"min_events must be non-negative, got {min_events}")

        self._signal_id = signal_id
        self._name = name
        self._family = family
        self._threshold = threshold
        self._is_enabled = is_enabled
        self._min_events = min_events

    @property
    def signal_id(self) -> str:
        return self._signal_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def family(self) -> SignalFamily:
        return self._family

    @property
    def threshold(self) -> float:
        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        if value < 0.0:
            raise ValueError(f"threshold must be non-negative, got {value}")
        self._threshold = value

    @property
    def is_enabled(self) -> bool:
        return self._is_enabled

    @is_enabled.setter
    def is_enabled(self, value: bool) -> None:
        self._is_enabled = bool(value)

    @property
    def min_events(self) -> int:
        return self._min_events

    @min_events.setter
    def min_events(self, value: int) -> None:
        if value < 0:
            raise ValueError(f"min_events must be non-negative, got {value}")
        self._min_events = value

    @abstractmethod
    def evaluate(self, context: DetectionContext) -> SignalResult:
        """Evaluate behavioural criteria against the provided detection context."""
        ...

    def _create_result(
        self,
        triggered: bool,
        observed_metric: float,
        explanation: str,
        severity_score: float = 0.0,
        evidence_event_ids: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        evaluated_at_utc: datetime | None = None,
    ) -> SignalResult:
        """Helper to construct a validated, immutable SignalResult."""
        return SignalResult(
            signal_id=self._signal_id,
            signal_name=self._name,
            family=self._family,
            triggered=triggered,
            severity_score=max(0.0, min(1.0, severity_score)),
            observed_metric=float(observed_metric),
            threshold=float(self._threshold),
            explanation=explanation,
            evidence_event_ids=evidence_event_ids or [],
            evaluated_at_utc=evaluated_at_utc or datetime.now(UTC),
            metadata=metadata or {},
        )
