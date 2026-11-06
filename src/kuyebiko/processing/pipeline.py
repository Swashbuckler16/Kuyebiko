"""Central pipeline lifecycle coordinator for Kuyebiko filesystem monitoring.

Orchestrates MonitoredRootRegistry, EventIngestor, BoundedEventQueue,
EventProcessingWorker, and PipelineTelemetryAggregator. Guarantees deterministic
startup sequence with automatic rollback on partial failures, deterministic
graceful shutdown with configurable draining, safe restart without resource leaks,
and thread-safe lifecycle state management.
"""

import logging
import threading
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from kuyebiko.collectors.base import NotificationCallback
from kuyebiko.collectors.models import MonitoredRoot
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.registry import MonitoredRootRegistry
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.core.exceptions import (
    PipelineLifecycleError,
    RegistryError,
)
from kuyebiko.processing.contracts import (
    EventConsumer,
    InMemoryEventConsumer,
)
from kuyebiko.processing.deduplication import EventDeduplicator
from kuyebiko.processing.ingestion import EventIngestor
from kuyebiko.processing.ordering import EventOrderingTracker
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.telemetry import (
    PipelineTelemetryAggregator,
    PipelineTelemetrySnapshot,
)
from kuyebiko.processing.worker import (
    EventProcessingWorker,
)

logger = logging.getLogger("kuyebiko.processing.pipeline")


class PipelineLifecycleState(StrEnum):
    """Lifecycle states of the complete event processing pipeline."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class EventPipeline:
    """Coordinates lifecycle, ingestion, queuing, normalization, and telemetry."""

    def __init__(
        self,
        registry: MonitoredRootRegistry | None = None,
        queue: BoundedEventQueue | None = None,
        queue_capacity: int = 10_000,
        consumer: EventConsumer | None = None,
        normalizer: EventNormalizer | None = None,
        deduplicator: EventDeduplicator | None = None,
        ordering_tracker: EventOrderingTracker | None = None,
        poll_timeout: float = 0.05,
        max_consumer_retries: int = 1,
    ) -> None:
        self._lock = threading.RLock()
        self._state = PipelineLifecycleState.STOPPED

        self._queue_capacity = max(1, queue_capacity)
        self._poll_timeout = poll_timeout
        self._max_consumer_retries = max_consumer_retries

        self._queue = (
            queue
            if queue is not None
            else BoundedEventQueue(capacity=self._queue_capacity)
        )
        self._ingestor = EventIngestor(self._queue)
        self._registry = (
            registry
            if registry is not None
            else MonitoredRootRegistry(default_callback=self._ingestor.ingest_callback)
        )
        self._consumer = consumer if consumer is not None else InMemoryEventConsumer()
        self._normalizer = (
            normalizer
            if normalizer is not None
            else EventNormalizer(rename_correlator=RenameCorrelator())
        )
        self._deduplicator = deduplicator
        self._ordering_tracker = (
            ordering_tracker if ordering_tracker is not None else EventOrderingTracker()
        )

        self._worker = EventProcessingWorker(
            queue=self._queue,
            consumer=self._consumer,
            normalizer=self._normalizer,
            deduplicator=self._deduplicator,
            ordering_tracker=self._ordering_tracker,
            poll_timeout=self._poll_timeout,
            max_consumer_retries=self._max_consumer_retries,
        )

        self._telemetry = PipelineTelemetryAggregator(
            queue=self._queue,
            ingestor=self._ingestor,
            worker=self._worker,
            watchers=self._registry.list_watchers,
            deduplicator=self._deduplicator,
            ordering_tracker=self._ordering_tracker,
        )

    @property
    def state(self) -> PipelineLifecycleState:
        """Current operational lifecycle state of the pipeline."""
        with self._lock:
            return self._state

    @property
    def is_running(self) -> bool:
        """True if pipeline is currently active and processing events."""
        with self._lock:
            return self._state == PipelineLifecycleState.RUNNING

    @property
    def registry(self) -> MonitoredRootRegistry:
        return self._registry

    @property
    def queue(self) -> BoundedEventQueue:
        return self._queue

    @property
    def ingestor(self) -> EventIngestor:
        return self._ingestor

    @property
    def worker(self) -> EventProcessingWorker:
        return self._worker

    @property
    def consumer(self) -> EventConsumer:
        return self._consumer

    @property
    def normalizer(self) -> EventNormalizer:
        return self._normalizer

    @property
    def deduplicator(self) -> EventDeduplicator | None:
        return self._deduplicator

    @property
    def ordering_tracker(self) -> EventOrderingTracker:
        return self._ordering_tracker

    @property
    def telemetry(self) -> PipelineTelemetryAggregator:
        return self._telemetry

    def register_root(
        self,
        root: MonitoredRoot,
        callback: NotificationCallback | None = None,
    ) -> None:
        """Register a monitored root with the pipeline registry."""
        with self._lock:
            effective_cb = callback or self._ingestor.ingest_callback
            self._registry.register(root, callback=effective_cb)

    def start(self) -> None:
        """Execute deterministic pipeline startup with automatic rollback on error.

        Startup sequence:
        1. State validation & transition to STARTING.
        2. Validate monitored root configuration.
        3. Start processing worker.
        4. Start registered filesystem watchers.
        5. Enable ingestion callback.
        6. Transition to RUNNING.

        Raises:
            PipelineLifecycleError: If pipeline is not STOPPED or startup fails.
        """
        with self._lock:
            if self._state != PipelineLifecycleState.STOPPED:
                raise PipelineLifecycleError(
                    f"Cannot start pipeline from state '{self._state.value}'; "
                    "pipeline must be in 'stopped' state."
                )
            self._state = PipelineLifecycleState.STARTING

        logger.info("Starting Kuyebiko event processing pipeline...")

        # 1. Validate root configuration
        try:
            for root in self._registry.list_roots():
                if not Path(root.path).exists():
                    raise RegistryError(
                        f"Monitored root path does not exist: {root.path}"
                    )
        except Exception as err:
            with self._lock:
                self._state = PipelineLifecycleState.ERROR
            raise PipelineLifecycleError(
                f"Root configuration validation failed: {err}"
            ) from err

        # 2. Start worker thread
        try:
            self._worker.start()
        except Exception as err:
            with self._lock:
                self._state = PipelineLifecycleState.ERROR
            logger.error("Failed to start processing worker: %s", err)
            raise PipelineLifecycleError(
                f"Failed to start processing worker: {err}"
            ) from err

        # 3. Start registered watchers with rollback protection
        try:
            startup_results = self._registry.start_all()
            failed_roots = [
                root_id for root_id, success in startup_results.items() if not success
            ]
            if failed_roots:
                raise RegistryError(
                    f"Watchers failed to start for roots: {', '.join(failed_roots)}"
                )
        except Exception as err:
            logger.error(
                "Watcher startup failure detected during pipeline start: %s; "
                "rolling back components...",
                err,
            )
            self._rollback_startup()
            raise PipelineLifecycleError(
                f"Pipeline startup aborted during watcher startup: {err}"
            ) from err

        # 4. Enable normal ingestion
        self._registry.set_default_callback(self._ingestor.ingest_callback)

        with self._lock:
            self._state = PipelineLifecycleState.RUNNING

        logger.info("Kuyebiko event processing pipeline started successfully.")

    def _rollback_startup(self) -> None:
        """Rollback successfully started components after a startup failure."""
        logger.warning("Rolling back pipeline startup sequence...")
        # Disable ingestion
        try:
            self._registry.set_default_callback(None)
        except Exception as err:
            logger.warning("Error disabling ingestion during rollback: %s", err)

        # Stop watchers
        try:
            self._registry.stop_all()
        except Exception as err:
            logger.warning("Error stopping watchers during rollback: %s", err)

        # Stop worker without draining
        try:
            self._worker.stop(timeout=2.0, drain=False)
        except Exception as err:
            logger.warning("Error stopping worker during rollback: %s", err)

        with self._lock:
            self._state = PipelineLifecycleState.ERROR

    def stop(self, timeout: float = 5.0, drain: bool = True) -> None:
        """Execute deterministic shutdown with optional queue draining.

        Shutdown sequence:
        1. Stop accepting new notifications.
        2. Stop registered filesystem watchers.
        3. Drain already accepted queue entries (if drain=True).
        4. Stop processing worker.
        5. Verify resource cleanup.

        Args:
            timeout: Maximum seconds to wait for worker termination.
            drain: Whether to wait for queued events to finish processing.

        Raises:
            PipelineLifecycleError: If shutdown times out or components fail.
        """
        with self._lock:
            if self._state == PipelineLifecycleState.STOPPED:
                logger.debug("Pipeline already stopped; no-op.")
                return
            if self._state == PipelineLifecycleState.STOPPING:
                logger.debug("Pipeline shutdown already in progress.")
                return
            self._state = PipelineLifecycleState.STOPPING

        logger.info(
            "Stopping Kuyebiko event processing pipeline (drain=%s, timeout=%.2fs)...",
            drain,
            timeout,
        )

        # 1. Stop accepting notifications
        self._registry.set_default_callback(None)
        self._queue.stop_accepting()

        # 2. Stop watchers
        watcher_error: Exception | None = None
        try:
            self._registry.stop_all()
        except Exception as err:
            watcher_error = err
            logger.error("Error stopping registered watchers: %s", err)

        # 3. Stop worker (drains queue if requested)
        worker_error: Exception | None = None
        try:
            self._worker.stop(timeout=timeout, drain=drain)
        except Exception as err:
            worker_error = err
            logger.error("Error stopping processing worker: %s", err)

        # 4. Verify no alive threads or resources remain
        if self._worker.is_running():
            with self._lock:
                self._state = PipelineLifecycleState.ERROR
            raise PipelineLifecycleError(
                f"Worker thread remained alive after {timeout}s shutdown timeout"
            )

        if watcher_error or worker_error:
            with self._lock:
                self._state = PipelineLifecycleState.ERROR
            error_details = []
            if watcher_error:
                error_details.append(f"watcher error: {watcher_error}")
            if worker_error:
                error_details.append(f"worker error: {worker_error}")
            raise PipelineLifecycleError(
                f"Pipeline stopped with errors: {'; '.join(error_details)}"
            )

        with self._lock:
            self._state = PipelineLifecycleState.STOPPED

        logger.info("Kuyebiko event processing pipeline stopped cleanly.")

    def restart(self, timeout: float = 5.0, drain: bool = True) -> None:
        """Safely stop and restart the pipeline with fresh queue and worker state.

        Args:
            timeout: Shutdown timeout in seconds.
            drain: Whether to drain queued events during shutdown.
        """
        logger.info("Restarting Kuyebiko event processing pipeline...")
        self.stop(timeout=timeout, drain=drain)

        # Re-initialize queue and worker to prevent stale thread or drain state
        with self._lock:
            self._queue = BoundedEventQueue(capacity=self._queue_capacity)
            self._ingestor = EventIngestor(self._queue)
            self._worker = EventProcessingWorker(
                queue=self._queue,
                consumer=self._consumer,
                normalizer=self._normalizer,
                deduplicator=self._deduplicator,
                ordering_tracker=self._ordering_tracker,
                poll_timeout=self._poll_timeout,
                max_consumer_retries=self._max_consumer_retries,
            )
            self._telemetry = PipelineTelemetryAggregator(
                queue=self._queue,
                ingestor=self._ingestor,
                worker=self._worker,
                watchers=self._registry.list_watchers,
                deduplicator=self._deduplicator,
                ordering_tracker=self._ordering_tracker,
            )
            self._state = PipelineLifecycleState.STOPPED

        self.start()
        logger.info("Kuyebiko event processing pipeline restarted successfully.")

    def snapshot(
        self,
        external_kernel_overflow_count: int = 0,
        extra_degradation_reasons: Sequence[str] | None = None,
    ) -> PipelineTelemetrySnapshot:
        """Generate an aggregated operational telemetry snapshot of the pipeline."""
        return self._telemetry.snapshot(
            external_kernel_overflow_count=external_kernel_overflow_count,
            extra_degradation_reasons=extra_degradation_reasons,
        )
