"""Filesystem event processing and normalization for Kuyebiko.

Decouples filesystem watcher event ingestion from normalization, backpressure
management, ordering tracking, conservative deduplication, and downstream correlation.
"""

from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.processing.contracts import (
    CallbackEventConsumer,
    EventConsumer,
    EventEnvelope,
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
from kuyebiko.processing.pipeline import (
    EventPipeline,
    PipelineLifecycleState,
)
from kuyebiko.processing.queue import BoundedEventQueue, EventQueueMetrics
from kuyebiko.processing.telemetry import (
    PipelineHealth,
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
    "EventEnvelope",
    "EventFingerprint",
    "EventIngestor",
    "EventNormalizer",
    "EventOrderingMetadata",
    "EventOrderingTracker",
    "EventPipeline",
    "EventProcessingWorker",
    "EventQueueMetrics",
    "IngestionMetrics",
    "IngestionOutcome",
    "InMemoryEventConsumer",
    "OrderingMetrics",
    "PipelineHealth",
    "PipelineLifecycleState",
    "PipelineTelemetryAggregator",
    "PipelineTelemetrySnapshot",
    "WorkerLifecycleState",
    "WorkerMetrics",
]
