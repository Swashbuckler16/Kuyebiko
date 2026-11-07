"""Architectural interfaces and protocols for behaviour detection.

Defines the SignalEvaluator protocol, engine consumer interface, and contract
specifications for ransomware behaviour evaluation.
"""

from typing import Protocol, runtime_checkable

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
