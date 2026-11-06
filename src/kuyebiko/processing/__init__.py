"""Filesystem event processing and normalization for Kuyebiko.

Decouples filesystem watcher event ingestion from normalization, backpressure
management, and downstream incident correlation.
"""

from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.processing.contracts import (
    CallbackEventConsumer,
    EventConsumer,
    IngestionOutcome,
    InMemoryEventConsumer,
)
from kuyebiko.processing.ingestion import EventIngestor, IngestionMetrics
from kuyebiko.processing.queue import BoundedEventQueue, EventQueueMetrics
from kuyebiko.processing.worker import (
    EventProcessingWorker,
    WorkerLifecycleState,
    WorkerMetrics,
)

__all__ = [
    "BoundedEventQueue",
    "CallbackEventConsumer",
    "EventConsumer",
    "EventIngestor",
    "EventNormalizer",
    "EventProcessingWorker",
    "EventQueueMetrics",
    "IngestionMetrics",
    "IngestionOutcome",
    "InMemoryEventConsumer",
    "WorkerLifecycleState",
    "WorkerMetrics",
]
