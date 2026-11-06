"""Bounded thread-safe event queue for buffering filesystem notifications.

Provides non-blocking submission semantics for filesystem watcher producer threads,
explicit capacity bounds, queue-full drop accounting, and telemetry degradation
tracking.
"""

import logging
import threading
from datetime import UTC, datetime
from queue import Empty, Full, Queue
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.models import RawFileNotification
from kuyebiko.core.config import get_settings
from kuyebiko.processing.contracts import IngestionOutcome

logger = logging.getLogger("kuyebiko.processing.queue")


class EventQueueMetrics(BaseModel):
    """Immutable snapshot of event queue operational metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    capacity: int = Field(ge=1)
    size: int = Field(ge=0)
    high_watermark: int = Field(ge=0)
    total_submitted: int = Field(ge=0)
    total_accepted: int = Field(ge=0)
    total_rejected: int = Field(ge=0)
    total_dropped_queue_full: int = Field(ge=0)
    degraded: bool
    degradation_reason: str | None = None
    last_overflow_at: datetime | None = None
    last_recovered_at: datetime | None = None


class BoundedEventQueue:
    """Thread-safe bounded queue buffering RawFileNotification objects.

    Uses standard-library queue.Queue. Guarantees non-blocking submission so
    watcher threads never stall on consumer latency or backpressure. Tracks
    overflow metrics and pipeline degradation when capacity is exhausted.
    """

    def __init__(
        self,
        capacity: int | None = None,
        recovery_threshold_ratio: float = 0.5,
    ) -> None:
        """Initialize the bounded queue.

        Args:
            capacity: Maximum number of raw notifications permitted in the queue.
                If None, defaults to KuyebikoSettings.event_queue_size.
            recovery_threshold_ratio: Ratio of capacity below which a degraded queue
                recovers to healthy status on dequeue (default 0.5 = 50% capacity).
        """
        if capacity is None:
            capacity = get_settings().event_queue_size

        if capacity < 1:
            raise ValueError(f"Queue capacity must be at least 1, got {capacity}")

        if not 0.0 < recovery_threshold_ratio <= 1.0:
            raise ValueError("recovery_threshold_ratio must be between 0.0 and 1.0")

        self._capacity = capacity
        self._recovery_threshold = int(capacity * recovery_threshold_ratio)
        self._queue: Queue[Any] = Queue(maxsize=capacity)
        self._lock = threading.Lock()

        # Operational counters
        self._total_submitted = 0
        self._total_accepted = 0
        self._total_rejected = 0
        self._total_dropped_queue_full = 0
        self._high_watermark = 0

        # Health & degradation state
        self._degraded = False
        self._degradation_reason: str | None = None
        self._last_overflow_at: datetime | None = None
        self._last_recovered_at: datetime | None = None

        # State flags
        self._is_accepting = True

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def is_degraded(self) -> bool:
        with self._lock:
            return self._degraded

    def is_empty(self) -> bool:
        return self._queue.empty()

    def is_full(self) -> bool:
        return self._queue.full()

    def qsize(self) -> int:
        return self._queue.qsize()

    def stop_accepting(self) -> None:
        """Mark the queue as shutting down to reject subsequent submissions."""
        with self._lock:
            self._is_accepting = False

    def is_accepting(self) -> bool:
        with self._lock:
            return self._is_accepting

    def put_notification(self, notification: RawFileNotification) -> IngestionOutcome:
        """Submit a RawFileNotification in a non-blocking manner.

        Args:
            notification: The raw notification to enqueue.

        Returns:
            IngestionOutcome.ACCEPTED if enqueued.
            IngestionOutcome.QUEUE_FULL if capacity is exceeded.
            IngestionOutcome.SHUTTING_DOWN if queue is no longer accepting.
            IngestionOutcome.REJECTED if item is not a RawFileNotification.
        """
        if not isinstance(notification, RawFileNotification):
            with self._lock:
                self._total_submitted += 1
                self._total_rejected += 1
            logger.warning(
                "Rejected item of invalid type '%s' submitted to event queue",
                type(notification).__name__,
            )
            return IngestionOutcome.REJECTED

        with self._lock:
            self._total_submitted += 1
            if not self._is_accepting:
                self._total_rejected += 1
                return IngestionOutcome.SHUTTING_DOWN

        try:
            self._queue.put_nowait(notification)
        except Full:
            now = datetime.now(UTC)
            with self._lock:
                self._total_dropped_queue_full += 1
                self._degraded = True
                self._degradation_reason = (
                    f"Event queue capacity ({self._capacity}) exhausted; "
                    "backpressure caused notification drops."
                )
                self._last_overflow_at = now
            logger.warning(
                "Event queue full (capacity %d); dropped notification for '%s' "
                "in root '%s'",
                self._capacity,
                notification.relative_path,
                notification.root_id,
            )
            return IngestionOutcome.QUEUE_FULL

        with self._lock:
            self._total_accepted += 1
            current_size = self._queue.qsize()
            if current_size > self._high_watermark:
                self._high_watermark = current_size

        return IngestionOutcome.ACCEPTED

    def put_raw(self, item: Any) -> None:
        """Enqueues an arbitrary item (e.g. shutdown sentinel) directly.

        Bypasses type validation. Used internally for worker control signalling.
        """
        self._queue.put(item)

    def get(self, timeout: float | None = None) -> Any:
        """Retrieve the next notification or item from the queue.

        Updates degradation state if the queue size drops below the recovery threshold.

        Args:
            timeout: Maximum seconds to block waiting for an item.

        Returns:
            The enqueued notification or control item.

        Raises:
            queue.Empty: If no item is available within the specified timeout.
        """
        item = self._queue.get(timeout=timeout)

        # Check for recovery from degraded status
        current_size = self._queue.qsize()
        with self._lock:
            if self._degraded and current_size <= self._recovery_threshold:
                self._degraded = False
                self._degradation_reason = None
                self._last_recovered_at = datetime.now(UTC)
                logger.info(
                    "Event queue recovered to healthy state "
                    "(current size %d <= threshold %d)",
                    current_size,
                    self._recovery_threshold,
                )

        return item

    def task_done(self) -> None:
        """Indicate that a formerly enqueued task is complete."""
        self._queue.task_done()

    def clear(self) -> int:
        """Purge all pending items from the queue. Returns count of purged items."""
        count = 0
        while True:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                count += 1
            except Empty:
                break
        return count

    def get_metrics(self) -> EventQueueMetrics:
        """Return a thread-safe snapshot of queue operational metrics."""
        with self._lock:
            return EventQueueMetrics(
                capacity=self._capacity,
                size=self._queue.qsize(),
                high_watermark=self._high_watermark,
                total_submitted=self._total_submitted,
                total_accepted=self._total_accepted,
                total_rejected=self._total_rejected,
                total_dropped_queue_full=self._total_dropped_queue_full,
                degraded=self._degraded,
                degradation_reason=self._degradation_reason,
                last_overflow_at=self._last_overflow_at,
                last_recovered_at=self._last_recovered_at,
            )
