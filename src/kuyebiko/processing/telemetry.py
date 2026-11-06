"""Pipeline telemetry aggregation and backpressure metrics for Kuyebiko.

Provides structured telemetry snapshots distinguishing between Windows kernel
buffer overflows (ERROR_NOTIFY_ENUM_DIR) and application queue backpressure overflows,
ensuring clear root-cause isolation and degradation visibility.
"""

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.base import BaseWatcher, WatcherHealth
from kuyebiko.processing.ingestion import EventIngestor
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.worker import EventProcessingWorker

logger = logging.getLogger("kuyebiko.processing.telemetry")


class PipelineTelemetrySnapshot(BaseModel):
    """Unified telemetry snapshot capturing pipeline throughput and backpressure."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    queue_capacity: int = Field(ge=1)
    current_queue_depth: int = Field(ge=0)
    peak_queue_depth: int = Field(ge=0)

    total_submitted: int = Field(ge=0)
    total_processed: int = Field(ge=0)
    total_rejected: int = Field(ge=0)
    total_dropped: int = Field(ge=0)

    queue_full_count: int = Field(ge=0)
    kernel_overflow_count: int = Field(ge=0)
    application_queue_overflow_count: int = Field(ge=0)

    telemetry_degraded: bool
    degradation_reasons: list[str] = Field(default_factory=list)


class PipelineTelemetryAggregator:
    """Aggregates telemetry metrics across ingestor, queue, worker, and watchers."""

    def __init__(
        self,
        queue: BoundedEventQueue,
        ingestor: EventIngestor | None = None,
        worker: EventProcessingWorker | None = None,
        watchers: Sequence[BaseWatcher] | None = None,
    ) -> None:
        self._queue = queue
        self._ingestor = ingestor
        self._worker = worker
        self._watchers = watchers or []

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

        # Calculate kernel buffer overflows across registered watchers
        kernel_overflows = external_kernel_overflow_count
        watcher_degraded = False
        reasons: list[str] = []

        for watcher in self._watchers:
            if hasattr(watcher, "_overflow_count"):
                kernel_overflows += getattr(watcher, "_overflow_count", 0)
            if hasattr(watcher, "health") and watcher.health == WatcherHealth.DEGRADED:
                watcher_degraded = True
                if hasattr(watcher, "degradation_reasons"):
                    reasons.extend(getattr(watcher, "degradation_reasons", []))

        # Application queue backpressure drops
        app_overflows = q_metrics.total_dropped_queue_full
        total_dropped = kernel_overflows + app_overflows

        is_degraded = q_metrics.degraded or watcher_degraded

        if q_metrics.degraded and q_metrics.degradation_reason:
            reasons.append(q_metrics.degradation_reason)

        if extra_degradation_reasons:
            reasons.extend(extra_degradation_reasons)

        # Deduplicate reasons while preserving order
        dedup_reasons = list(dict.fromkeys(r.strip() for r in reasons if r.strip()))

        total_submitted = (
            ing_metrics.total_received if ing_metrics else q_metrics.total_submitted
        )
        total_rejected = (
            ing_metrics.total_rejected if ing_metrics else q_metrics.total_rejected
        )
        total_processed = wrk_metrics.events_delivered if wrk_metrics else 0

        return PipelineTelemetrySnapshot(
            queue_capacity=q_metrics.capacity,
            current_queue_depth=q_metrics.size,
            peak_queue_depth=q_metrics.high_watermark,
            total_submitted=total_submitted,
            total_processed=total_processed,
            total_rejected=total_rejected,
            total_dropped=total_dropped,
            queue_full_count=app_overflows,
            kernel_overflow_count=kernel_overflows,
            application_queue_overflow_count=app_overflows,
            telemetry_degraded=is_degraded,
            degradation_reasons=dedup_reasons,
        )
