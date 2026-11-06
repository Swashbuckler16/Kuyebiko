"""Event processing background worker for Kuyebiko.

Consumes RawFileNotification objects from the bounded event queue, converts them
into validated FileEvent instances using EventNormalizer and RenameCorrelator, and
dispatches them to registered downstream EventConsumer components with ordering
tracking, conservative deduplication, and isolated bounded retries.
"""

import logging
import threading
from enum import StrEnum
from queue import Empty
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.models import RawFileNotification
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.core.exceptions import NormalizationError, WorkerLifecycleError
from kuyebiko.models.events import FileEvent
from kuyebiko.processing.contracts import (
    CallbackEventConsumer,
    EventConsumer,
    InMemoryEventConsumer,
)
from kuyebiko.processing.deduplication import EventDeduplicator
from kuyebiko.processing.ordering import EventOrderingTracker
from kuyebiko.processing.queue import BoundedEventQueue

logger = logging.getLogger("kuyebiko.processing.worker")

_SHUTDOWN_SENTINEL = object()


class WorkerLifecycleState(StrEnum):
    """Lifecycle states of the event processing worker."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class WorkerMetrics(BaseModel):
    """Immutable snapshot of processing worker operational metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    notifications_received: int = Field(ge=0)
    notifications_normalized: int = Field(ge=0)
    renames_pending: int = Field(ge=0)
    normalization_errors: int = Field(ge=0)
    events_delivered: int = Field(ge=0)
    consumer_errors: int = Field(ge=0)
    unexpected_errors: int = Field(ge=0)

    # Extended Step 3.9 error and lifecycle metrics
    invalid_notifications: int = Field(default=0, ge=0)
    normalization_failures: int = Field(default=0, ge=0)
    rename_correlation_failures: int = Field(default=0, ge=0)
    consumer_delivery_failures: int = Field(default=0, ge=0)
    retry_attempts: int = Field(default=0, ge=0)
    permanently_failed_events: int = Field(default=0, ge=0)
    unexpected_processing_errors: int = Field(default=0, ge=0)
    worker_failures: int = Field(default=0, ge=0)
    duplicates_suppressed: int = Field(default=0, ge=0)

    state: WorkerLifecycleState


class EventProcessingWorker:
    """Dedicated background worker thread for event normalization and dispatch.

    Decouples raw notification ingestion from downstream event consumers. Guarantees
    strict sequential processing, deterministic lifecycle transitions, error isolation,
    and non-blocking graceful shutdown.
    """

    def __init__(
        self,
        queue: BoundedEventQueue,
        consumer: EventConsumer | Any | None = None,
        normalizer: EventNormalizer | None = None,
        deduplicator: EventDeduplicator | None = None,
        ordering_tracker: EventOrderingTracker | None = None,
        poll_timeout: float = 0.1,
        max_consumer_retries: int = 1,
    ) -> None:
        """Initialize the processing worker.

        Args:
            queue: Bounded queue containing raw filesystem notifications.
            consumer: Downstream consumer implementing EventConsumer, a callable,
                or None (defaults to an InMemoryEventConsumer).
            normalizer: EventNormalizer instance (defaults to normalizer
                with RenameCorrelator).
            deduplicator: Optional conservative EventDeduplicator instance.
            ordering_tracker: Optional EventOrderingTracker instance.
            poll_timeout: Queue polling interval in seconds for checking stop signals.
            max_consumer_retries: Maximum immediate retries for downstream
                consumer failures.
        """
        if not isinstance(queue, BoundedEventQueue):
            raise TypeError(
                f"queue must be a BoundedEventQueue, got {type(queue).__name__}"
            )

        self._queue = queue

        if consumer is None:
            self._consumer: EventConsumer = InMemoryEventConsumer()
        elif isinstance(consumer, EventConsumer):
            self._consumer = consumer
        elif callable(consumer):
            self._consumer = CallbackEventConsumer(consumer)
        else:
            raise TypeError(
                f"consumer must implement EventConsumer or be callable, "
                f"got {type(consumer).__name__}"
            )

        self._normalizer = normalizer or EventNormalizer(
            rename_correlator=RenameCorrelator()
        )
        self._deduplicator = deduplicator
        self._ordering_tracker = ordering_tracker or EventOrderingTracker()
        self._poll_timeout = max(0.01, poll_timeout)
        self._max_consumer_retries = max(0, max_consumer_retries)

        self._thread: threading.Thread | None = None
        self._state = WorkerLifecycleState.STOPPED
        self._stop_requested = threading.Event()
        self._lock = threading.Lock()

        # Operational metrics
        self._notifications_received = 0
        self._notifications_normalized = 0
        self._renames_pending = 0
        self._events_delivered = 0

        # Extended error and retry metrics
        self._invalid_notifications = 0
        self._normalization_failures = 0
        self._rename_correlation_failures = 0
        self._consumer_delivery_failures = 0
        self._retry_attempts = 0
        self._permanently_failed_events = 0
        self._unexpected_processing_errors = 0
        self._worker_failures = 0
        self._duplicates_suppressed = 0

    @property
    def state(self) -> WorkerLifecycleState:
        with self._lock:
            return self._state

    @property
    def ordering_tracker(self) -> EventOrderingTracker:
        return self._ordering_tracker

    @property
    def deduplicator(self) -> EventDeduplicator | None:
        return self._deduplicator

    def is_running(self) -> bool:
        with self._lock:
            return self._state == WorkerLifecycleState.RUNNING

    def start(self) -> None:
        """Start the background worker thread.

        Raises:
            WorkerLifecycleError: If the worker is already running or starting.
        """
        with self._lock:
            if self._state in (
                WorkerLifecycleState.RUNNING,
                WorkerLifecycleState.STARTING,
            ):
                raise WorkerLifecycleError(
                    f"Cannot start worker: already in state '{self._state}'"
                )

            self._state = WorkerLifecycleState.STARTING
            self._stop_requested.clear()

            try:
                self._thread = threading.Thread(
                    target=self._run_loop,
                    name="KuyebikoEventProcessor",
                    daemon=True,
                )
                self._thread.start()
                self._state = WorkerLifecycleState.RUNNING
                logger.info("EventProcessingWorker started successfully")
            except Exception as err:
                self._state = WorkerLifecycleState.ERROR
                self._worker_failures += 1
                logger.critical("Failed to start EventProcessingWorker thread: %s", err)
                raise WorkerLifecycleError(
                    f"Failed to start worker thread: {err}"
                ) from err

    def stop(self, timeout: float = 5.0, drain: bool = True) -> None:
        """Stop the background worker thread gracefully.

        Args:
            timeout: Maximum seconds to wait for worker termination.
            drain: If True, consumes remaining queued events before exiting.

        Raises:
            WorkerLifecycleError: If worker fails to stop within the specified timeout.
        """
        with self._lock:
            if self._state == WorkerLifecycleState.STOPPED:
                return
            if self._state == WorkerLifecycleState.STOPPING:
                return

            self._state = WorkerLifecycleState.STOPPING
            self._stop_requested.set()
            thread = self._thread

        logger.info(
            "Stopping EventProcessingWorker (timeout=%.1fs, drain=%s)...",
            timeout,
            drain,
        )

        if not drain:
            # Enqueue sentinel to wake up worker immediately if blocked in get()
            try:
                self._queue.put_raw(_SHUTDOWN_SENTINEL)
            except Exception as err:
                logger.debug("Could not put sentinel into queue: %s", err)

        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

            if thread.is_alive():
                with self._lock:
                    self._state = WorkerLifecycleState.ERROR
                    self._worker_failures += 1
                msg = (
                    f"EventProcessingWorker thread failed to terminate within "
                    f"{timeout}s timeout"
                )
                logger.error(msg)
                raise WorkerLifecycleError(msg)

        with self._lock:
            self._state = WorkerLifecycleState.STOPPED
            self._thread = None

        logger.info("EventProcessingWorker stopped cleanly")

    def restart(self, timeout: float = 5.0) -> None:
        """Safely stop and restart the worker thread."""
        self.stop(timeout=timeout, drain=False)
        self.start()

    def _run_loop(self) -> None:
        """Main processing loop executed on the worker thread."""
        logger.debug("EventProcessingWorker worker loop entered")

        while True:
            # Check stop condition when queue is empty
            if self._stop_requested.is_set() and self._queue.is_empty():
                break

            try:
                item = self._queue.get(timeout=self._poll_timeout)
            except Empty:
                if self._stop_requested.is_set():
                    break
                continue

            try:
                if item is _SHUTDOWN_SENTINEL:
                    break

                self._process_single_item(item)
            except Exception as err:
                with self._lock:
                    self._unexpected_processing_errors += 1
                logger.exception("Unexpected error in event processing loop: %s", err)
            finally:
                self._queue.task_done()

        logger.debug("EventProcessingWorker worker loop exited")

    def _process_single_item(self, item: Any) -> None:
        """Process a single item retrieved from the queue."""
        with self._lock:
            self._notifications_received += 1

        if not isinstance(item, RawFileNotification):
            with self._lock:
                self._invalid_notifications += 1
                self._normalization_failures += 1
            logger.warning(
                "Skipping non-RawFileNotification item of type '%s'",
                type(item).__name__,
            )
            return

        # Track event chronology and latency
        self._ordering_tracker.track(item)

        # Check conservative deduplication if enabled
        if self._deduplicator is not None and self._deduplicator.is_duplicate(item):
            with self._lock:
                self._duplicates_suppressed += 1
            return

        # Normalize notification into a validated FileEvent
        try:
            event: FileEvent | None = self._normalizer.normalize_notification(item)
        except NormalizationError as err:
            with self._lock:
                self._normalization_failures += 1
            logger.warning(
                "Normalization failed for notification in root '%s': %s",
                item.root_id,
                err,
            )
            return
        except Exception as err:
            with self._lock:
                self._normalization_failures += 1
                self._unexpected_processing_errors += 1
            logger.error(
                "Unexpected exception normalizing notification in root '%s': %s",
                item.root_id,
                err,
            )
            return

        # If normalization produced None (e.g. rename pending correlation)
        if event is None:
            with self._lock:
                self._renames_pending += 1
            logger.debug(
                "Notification for root '%s' path '%s' pending correlation",
                item.root_id,
                item.relative_path,
            )
            return

        with self._lock:
            self._notifications_normalized += 1

        # Deliver to downstream consumer with bounded retry
        delivered = False
        attempts = self._max_consumer_retries + 1

        for attempt in range(attempts):
            try:
                self._consumer.handle_event(event)
                delivered = True
                break
            except Exception as err:
                with self._lock:
                    self._consumer_delivery_failures += 1
                    if attempt < self._max_consumer_retries:
                        self._retry_attempts += 1
                logger.warning(
                    "Consumer '%s' failed handling event '%s' (attempt %d/%d): %s",
                    type(self._consumer).__name__,
                    event.event_id,
                    attempt + 1,
                    attempts,
                    err,
                )

        if delivered:
            with self._lock:
                self._events_delivered += 1
        else:
            with self._lock:
                self._permanently_failed_events += 1
            logger.error(
                "Event '%s' permanently failed downstream delivery after %d attempts",
                event.event_id,
                attempts,
            )

    def get_metrics(self) -> WorkerMetrics:
        """Return a thread-safe snapshot of worker operational metrics."""
        with self._lock:
            return WorkerMetrics(
                notifications_received=self._notifications_received,
                notifications_normalized=self._notifications_normalized,
                renames_pending=self._renames_pending,
                normalization_errors=self._normalization_failures,
                events_delivered=self._events_delivered,
                consumer_errors=self._consumer_delivery_failures,
                unexpected_errors=self._unexpected_processing_errors,
                invalid_notifications=self._invalid_notifications,
                normalization_failures=self._normalization_failures,
                rename_correlation_failures=self._rename_correlation_failures,
                consumer_delivery_failures=self._consumer_delivery_failures,
                retry_attempts=self._retry_attempts,
                permanently_failed_events=self._permanently_failed_events,
                unexpected_processing_errors=self._unexpected_processing_errors,
                worker_failures=self._worker_failures,
                duplicates_suppressed=self._duplicates_suppressed,
                state=self._state,
            )
