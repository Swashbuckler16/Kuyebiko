"""Event ingestion interface for Kuyebiko filesystem watchers.

Accepts RawFileNotification objects from directory watchers, enforces type safety
and pipeline state checks, tracks per-root ingestion counters, and submits items
to the bounded processing queue.
"""

import logging
import threading
from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.models import RawFileNotification
from kuyebiko.processing.contracts import IngestionOutcome
from kuyebiko.processing.queue import BoundedEventQueue

logger = logging.getLogger("kuyebiko.processing.ingestion")


class IngestionMetrics(BaseModel):
    """Immutable snapshot of ingestion pipeline metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_received: int = Field(ge=0)
    total_accepted: int = Field(ge=0)
    total_rejected: int = Field(ge=0)
    total_dropped_queue_full: int = Field(ge=0)
    total_shutting_down: int = Field(ge=0)
    events_by_root: dict[str, int] = Field(default_factory=dict)
    is_active: bool


class EventIngestor:
    """Thread-safe ingestion interface connecting filesystem watchers to the pipeline.

    Provides a fast, non-blocking ingestion callback that filesystem watchers can
    safely invoke from their monitoring threads without risking deadlocks or blocking
    on disk or database I/O.
    """

    def __init__(self, queue: BoundedEventQueue) -> None:
        if not isinstance(queue, BoundedEventQueue):
            raise TypeError(
                f"queue must be an instance of BoundedEventQueue, "
                f"got {type(queue).__name__}"
            )
        self._queue = queue
        self._lock = threading.Lock()
        self._is_active = True

        # Ingestion metrics
        self._total_received = 0
        self._total_accepted = 0
        self._total_rejected = 0
        self._total_dropped_queue_full = 0
        self._total_shutting_down = 0
        self._events_by_root: dict[str, int] = defaultdict(int)

    @property
    def queue(self) -> BoundedEventQueue:
        return self._queue

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._is_active

    def ingest(self, notification: RawFileNotification) -> IngestionOutcome:
        """Submit a raw notification to the processing pipeline.

        Args:
            notification: The raw notification event from a directory watcher.

        Returns:
            IngestionOutcome indicating acceptance, rejection, saturation, or shutdown.
        """
        with self._lock:
            self._total_received += 1

            if not self._is_active:
                self._total_shutting_down += 1
                return IngestionOutcome.SHUTTING_DOWN

        # Validate input type
        if not isinstance(notification, RawFileNotification):
            with self._lock:
                self._total_rejected += 1
            logger.warning(
                "Rejected non-RawFileNotification object of type '%s'",
                type(notification).__name__,
            )
            return IngestionOutcome.REJECTED

        # Submit to bounded queue (non-blocking)
        outcome = self._queue.put_notification(notification)

        with self._lock:
            if outcome == IngestionOutcome.ACCEPTED:
                self._total_accepted += 1
                self._events_by_root[notification.root_id] += 1
            elif outcome == IngestionOutcome.QUEUE_FULL:
                self._total_dropped_queue_full += 1
            elif outcome == IngestionOutcome.SHUTTING_DOWN:
                self._total_shutting_down += 1
            elif outcome == IngestionOutcome.REJECTED:
                self._total_rejected += 1

        return outcome

    def ingest_callback(self, notification: RawFileNotification) -> None:
        """Convenience callback method matching the NotificationCallback protocol."""
        self.ingest(notification)

    def __call__(self, notification: RawFileNotification) -> IngestionOutcome:
        """Allow EventIngestor to be used directly as a NotificationCallback."""
        return self.ingest(notification)

    def shutdown(self) -> None:
        """Stop accepting new notifications and instruct the queue to stop accepting."""
        with self._lock:
            self._is_active = False
        self._queue.stop_accepting()
        logger.info("EventIngestor shutdown complete; rejecting subsequent submissions")

    def get_metrics(self) -> IngestionMetrics:
        """Return a thread-safe snapshot of ingestion metrics."""
        with self._lock:
            return IngestionMetrics(
                total_received=self._total_received,
                total_accepted=self._total_accepted,
                total_rejected=self._total_rejected,
                total_dropped_queue_full=self._total_dropped_queue_full,
                total_shutting_down=self._total_shutting_down,
                events_by_root=dict(self._events_by_root),
                is_active=self._is_active,
            )
