"""Filesystem event processing and normalization for Kuyebiko.

Decouples filesystem watcher event ingestion from normalization, backpressure
management, ordering tracking, conservative deduplication, and downstream correlation.
"""

from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.processing.contracts import (
    CallbackEventConsumer,
    EventConsumer,
    IngestionOutcome,
    InMemoryEventConsumer,
)
from kuyebiko.processing.deduplication import (
    DeduplicationMetrics,
    EventDeduplicator,
    EventFingerprint,
)
from kuyebiko.processing.ingestion import EventIngestor, IngestionMetrics
from kuyebiko.processing.ordering import (
    EventOrderingMetadata,
    EventOrderingTracker,
    OrderingMetrics,
)
from kuyebiko.processing.queue import BoundedEventQueue, EventQueueMetrics
from kuyebiko.processing.telemetry import (
    PipelineTelemetryAggregator,
    PipelineTelemetrySnapshot,
)
from kuyebiko.processing.worker import (
    EventProcessingWorker,
    WorkerLifecycleState,
    WorkerMetrics,
)

__all__ = [
    "BoundedEventQueue",
    "CallbackEventConsumer",
    "DeduplicationMetrics",
    "EventConsumer",
    "EventDeduplicator",
    "EventFingerprint",
    "EventIngestor",
    "EventNormalizer",
    "EventOrderingMetadata",
    "EventOrderingTracker",
    "EventProcessingWorker",
    "EventQueueMetrics",
    "IngestionMetrics",
    "IngestionOutcome",
    "InMemoryEventConsumer",
    "OrderingMetrics",
    "PipelineTelemetryAggregator",
    "PipelineTelemetrySnapshot",
    "WorkerLifecycleState",
    "WorkerMetrics",
]
