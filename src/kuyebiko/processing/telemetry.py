"""Pipeline telemetry aggregation and backpressure metrics for Kuyebiko.

Provides structured telemetry snapshots distinguishing between Windows kernel
buffer overflows (ERROR_NOTIFY_ENUM_DIR occurrences with unquantified loss) and
known exact application queue drops, ensuring clear root-cause isolation, component
health aggregation, and degradation visibility.
"""

import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.base import BaseWatcher, WatcherHealth
from kuyebiko.processing.deduplication import (
    DeduplicationMetrics,
    EventDeduplicator,
)
from kuyebiko.processing.ingestion import EventIngestor, IngestionMetrics
from kuyebiko.processing.ordering import (
    EventOrderingTracker,
    OrderingMetrics,
)
from kuyebiko.processing.queue import BoundedEventQueue, EventQueueMetrics
from kuyebiko.processing.worker import (
    EventProcessingWorker,
    WorkerLifecycleState,
    WorkerMetrics,
)

logger = logging.getLogger("kuyebiko.processing.telemetry")


class PipelineHealth(StrEnum):
    """Overall operational health state of the event processing pipeline."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    STOPPED = "stopped"


class PipelineTelemetrySnapshot(BaseModel):
    """Unified telemetry snapshot capturing throughput, health, and loss metrics."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    health: PipelineHealth

    # Collector summary
    registered_watchers: int = Field(default=0, ge=0)
    active_watchers: int = Field(default=0, ge=0)
    degraded_watchers: int = Field(default=0, ge=0)
    failed_watchers: int = Field(default=0, ge=0)
    collector_events_observed: int = Field(default=0, ge=0)
    worker_state: str = "stopped"

    # Queue bounds & depth
    queue_capacity: int = Field(ge=1)
    current_queue_depth: int = Field(ge=0)
    peak_queue_depth: int = Field(ge=0)

    # Ingestion & worker throughput
    total_submitted: int = Field(ge=0)
    total_processed: int = Field(ge=0)
    total_rejected: int = Field(ge=0)

    # Subsystem snapshots
    ingestion: IngestionMetrics | None = None
    queue: EventQueueMetrics | None = None
    worker: WorkerMetrics | None = None
    ordering: OrderingMetrics | None = None
    deduplication: DeduplicationMetrics | None = None

    # Event loss metrics - strictly separated
    known_application_dropped: int = Field(
        ge=0,
        description="Exact count of notifications dropped due to queue saturation",
    )
    total_dropped: int = Field(
        ge=0,
        description="Known exact application drops (alias for backward compatibility)",
    )
    application_queue_overflow_count: int = Field(
        ge=0,
        description="Number of times queue saturation caused notification drops",
    )
    queue_full_count: int = Field(ge=0)

    # Kernel loss metrics - unquantified loss occurrences
    kernel_overflow_count: int = Field(
        ge=0,
        description="Number of times ERROR_NOTIFY_ENUM_DIR was returned",
    )
    kernel_overflow_occurrences: int = Field(
        ge=0,
        description="Alias for kernel_overflow_count representing overflow events",
    )
    uncounted_kernel_loss: bool = Field(
        default=False,
        description="True if kernel buffer overflows occurred with unknown event loss",
    )

    # Error and failure metrics
    permanently_failed_events: int = Field(default=0, ge=0)
    telemetry_degraded: bool
    degradation_reasons: list[str] = Field(default_factory=list)


class PipelineTelemetryAggregator:
    """Aggregates telemetry metrics across ingestor, queue, worker, and watchers."""

    def __init__(
        self,
        queue: BoundedEventQueue,
        ingestor: EventIngestor | None = None,
        worker: EventProcessingWorker | None = None,
        watchers: (
            Sequence[BaseWatcher] | Callable[[], Sequence[BaseWatcher]] | None
        ) = None,
        deduplicator: EventDeduplicator | None = None,
        ordering_tracker: EventOrderingTracker | None = None,
    ) -> None:
        self._queue = queue
        self._ingestor = ingestor
        self._worker = worker
        self._watchers = watchers
        self._deduplicator = deduplicator
        self._ordering_tracker = ordering_tracker

    def snapshot(
        self,
        external_kernel_overflow_count: int = 0,
        extra_degradation_reasons: Sequence[str] | None = None,
    ) -> PipelineTelemetrySnapshot:
        """Generate an aggregated snapshot of pipeline operational metrics.

        Args:
            external_kernel_overflow_count: Optional count of kernel buffer drops.
            extra_degradation_reasons: Optional list of additional degradation notes.

        Returns:
            PipelineTelemetrySnapshot with distinct kernel vs app overflow metrics.
        """
        q_metrics = self._queue.get_metrics()
        ing_metrics = self._ingestor.get_metrics() if self._ingestor else None
        wrk_metrics = self._worker.get_metrics() if self._worker else None

        # Resolve watcher list (supports callable or sequence)
        if callable(self._watchers):
            watchers_list = list(self._watchers())
        elif self._watchers is not None:
            watchers_list = list(self._watchers)
        else:
            watchers_list = []

        # Collector statistics
        registered_watchers = len(watchers_list)
        active_watchers = 0
        degraded_watchers = 0
        failed_watchers = 0
        collector_events_observed = 0
        kernel_overflows = external_kernel_overflow_count
        reasons: list[str] = []

        for watcher in watchers_list:
            collector_events_observed += getattr(watcher, "events_observed", 0)
            overflow = getattr(watcher, "overflow_count", 0)
            kernel_overflows += overflow
            watcher_health = getattr(watcher, "health", None)
            if watcher_health == WatcherHealth.ERROR:
                failed_watchers += 1
                root_id = getattr(watcher, "root_id", "unknown")
                reasons.append(f"Watcher for root '{root_id}' is in ERROR state.")
            elif watcher_health == WatcherHealth.DEGRADED:
                degraded_watchers += 1
                deg_reason = getattr(watcher, "degradation_reason", None)
                if deg_reason:
                    reasons.append(deg_reason)
                deg_reasons = getattr(watcher, "degradation_reasons", None)
                if deg_reasons:
                    reasons.extend(deg_reasons)
            elif hasattr(watcher, "is_running") and watcher.is_running():
                active_watchers += 1

        # Application queue backpressure drops
        app_overflows = q_metrics.total_dropped_queue_full
        known_app_dropped = app_overflows

        # Worker state and permanently failed events
        worker_state_str = wrk_metrics.state.value if wrk_metrics else "stopped"
        perm_failed = wrk_metrics.permanently_failed_events if wrk_metrics else 0
        if perm_failed > 0:
            reasons.append(
                f"{perm_failed} events permanently failed downstream consumer delivery."
            )

        if q_metrics.degraded and q_metrics.degradation_reason:
            reasons.append(q_metrics.degradation_reason)

        if kernel_overflows > 0:
            reasons.append(
                f"{kernel_overflows} Windows kernel notification buffer overflow(s) "
                "detected (ERROR_NOTIFY_ENUM_DIR); unknown filesystem events lost."
            )

        if extra_degradation_reasons:
            reasons.extend(extra_degradation_reasons)

        # Deduplicate degradation reasons
        dedup_reasons = list(dict.fromkeys(r.strip() for r in reasons if r.strip()))

        # Overall pipeline health determination
        worker_is_error = wrk_metrics and (
            wrk_metrics.state == WorkerLifecycleState.ERROR
        )
        if failed_watchers > 0 or worker_is_error:
            health = PipelineHealth.ERROR
        elif (
            degraded_watchers > 0
            or q_metrics.degraded
            or kernel_overflows > 0
            or perm_failed > 0
        ):
            health = PipelineHealth.DEGRADED
        elif active_watchers == 0 and (
            wrk_metrics is None or wrk_metrics.state == WorkerLifecycleState.STOPPED
        ):
            health = PipelineHealth.STOPPED
        else:
            health = PipelineHealth.HEALTHY

        is_degraded = (
            health == PipelineHealth.DEGRADED
            or len(dedup_reasons) > 0
            or kernel_overflows > 0
            or q_metrics.degraded
        )

        total_submitted = (
            ing_metrics.total_received if ing_metrics else q_metrics.total_submitted
        )
        total_rejected = (
            ing_metrics.total_rejected if ing_metrics else q_metrics.total_rejected
        )
        total_processed = wrk_metrics.events_delivered if wrk_metrics else 0

        # Subsystem ordering and deduplication metrics
        ord_tracker = self._ordering_tracker or (
            self._worker.ordering_tracker if self._worker else None
        )
        ord_metrics = ord_tracker.get_metrics() if ord_tracker else None

        dedup_obj = self._deduplicator or (
            self._worker.deduplicator if self._worker else None
        )
        dedup_metrics = dedup_obj.get_metrics() if dedup_obj else None

        return PipelineTelemetrySnapshot(
            health=health,
            registered_watchers=registered_watchers,
            active_watchers=active_watchers,
            degraded_watchers=degraded_watchers,
            failed_watchers=failed_watchers,
            collector_events_observed=collector_events_observed,
            worker_state=worker_state_str,
            queue_capacity=q_metrics.capacity,
            current_queue_depth=q_metrics.size,
            peak_queue_depth=q_metrics.high_watermark,
            total_submitted=total_submitted,
            total_processed=total_processed,
            total_rejected=total_rejected,
            ingestion=ing_metrics,
            queue=q_metrics,
            worker=wrk_metrics,
            ordering=ord_metrics,
            deduplication=dedup_metrics,
            known_application_dropped=known_app_dropped,
            total_dropped=known_app_dropped,
            application_queue_overflow_count=app_overflows,
            queue_full_count=app_overflows,
            kernel_overflow_count=kernel_overflows,
            kernel_overflow_occurrences=kernel_overflows,
            uncounted_kernel_loss=(kernel_overflows > 0),
            permanently_failed_events=perm_failed,
            telemetry_degraded=is_degraded,
            degradation_reasons=dedup_reasons,
        )
