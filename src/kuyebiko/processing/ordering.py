"""Event chronology and ordering tracking for Kuyebiko event processing.

Preserves filesystem observation timestamps, tracks processing latency via
monotonic clock deltas, detects out-of-order event arrivals per monitored root,
and isolates chronological metrics across independent directory roots.
"""

import logging
import threading
import time
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.models import RawFileNotification

logger = logging.getLogger("kuyebiko.processing.ordering")


class EventOrderingMetadata(BaseModel):
    """Chronology and latency metadata for a processed event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    root_id: str
    observed_at_utc: datetime
    observed_monotonic_ns: int
    processed_at_utc: datetime
    processed_monotonic_ns: int
    latency_ns: int
    latency_ms: float
    is_out_of_order: bool


class OrderingMetrics(BaseModel):
    """Snapshot of event ordering and latency metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_tracked: int = Field(ge=0)
    total_out_of_order: int = Field(ge=0)
    out_of_order_by_root: dict[str, int] = Field(default_factory=dict)
    avg_latency_ms: float = Field(ge=0.0)
    max_latency_ms: float = Field(ge=0.0)
    min_latency_ms: float = Field(ge=0.0)
    last_seen_monotonic_by_root: dict[str, int] = Field(default_factory=dict)


class EventOrderingTracker:
    """Thread-safe tracker for filesystem notification chronology and latency.

    Monitors arrival order per root_id using monotonic_ns timestamps. Detects
    out-of-order events caused by kernel dispatch, multi-threading or buffer
    delays without rewriting original timestamps or stalling the pipeline with
    unbounded reordering buffers.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_seen_monotonic: dict[str, int] = {}
        self._out_of_order_by_root: dict[str, int] = {}
        self._total_tracked = 0
        self._total_out_of_order = 0

        # Latency statistics
        self._total_latency_ns = 0
        self._min_latency_ns: int | None = None
        self._max_latency_ns = 0

    def track(
        self,
        notification: RawFileNotification,
        processed_at_utc: datetime | None = None,
        processed_monotonic_ns: int | None = None,
    ) -> EventOrderingMetadata:
        """Analyze a raw notification's chronology and compute processing latency.

        Args:
            notification: The RawFileNotification being processed.
            processed_at_utc: Optional processing wall-clock time (defaults to now UTC).
            processed_monotonic_ns: Optional processing monotonic time
                (defaults to time.monotonic_ns()).

        Returns:
            EventOrderingMetadata containing latency and out-of-order status.
        """
        now_utc = processed_at_utc or datetime.now(UTC)
        now_mono = (
            processed_monotonic_ns
            if processed_monotonic_ns is not None
            else time.monotonic_ns()
        )

        obs_mono = notification.monotonic_ns
        latency_ns = max(0, now_mono - obs_mono)
        latency_ms = round(latency_ns / 1_000_000.0, 3)

        root_id = notification.root_id
        is_out_of_order = False

        with self._lock:
            self._total_tracked += 1
            self._total_latency_ns += latency_ns
            if self._min_latency_ns is None or latency_ns < self._min_latency_ns:
                self._min_latency_ns = latency_ns
            if latency_ns > self._max_latency_ns:
                self._max_latency_ns = latency_ns

            last_mono = self._last_seen_monotonic.get(root_id)
            if last_mono is not None and obs_mono < last_mono:
                is_out_of_order = True
                self._total_out_of_order += 1
                self._out_of_order_by_root[root_id] = (
                    self._out_of_order_by_root.get(root_id, 0) + 1
                )
                logger.debug(
                    "Detected out-of-order notification in root '%s': "
                    "monotonic_ns %d < last_seen %d (delta: -%d ns)",
                    root_id,
                    obs_mono,
                    last_mono,
                    last_mono - obs_mono,
                )
            else:
                self._last_seen_monotonic[root_id] = obs_mono

        return EventOrderingMetadata(
            root_id=root_id,
            observed_at_utc=notification.observed_at,
            observed_monotonic_ns=obs_mono,
            processed_at_utc=now_utc,
            processed_monotonic_ns=now_mono,
            latency_ns=latency_ns,
            latency_ms=latency_ms,
            is_out_of_order=is_out_of_order,
        )

    def get_metrics(self) -> OrderingMetrics:
        """Return a thread-safe snapshot of ordering and latency metrics."""
        with self._lock:
            count = self._total_tracked
            avg_ms = (
                round((self._total_latency_ns / count) / 1_000_000.0, 3)
                if count > 0
                else 0.0
            )
            min_ms = (
                round((self._min_latency_ns or 0) / 1_000_000.0, 3)
                if count > 0
                else 0.0
            )
            max_ms = round(self._max_latency_ns / 1_000_000.0, 3) if count > 0 else 0.0

            return OrderingMetrics(
                total_tracked=self._total_tracked,
                total_out_of_order=self._total_out_of_order,
                out_of_order_by_root=dict(self._out_of_order_by_root),
                avg_latency_ms=avg_ms,
                max_latency_ms=max_ms,
                min_latency_ms=min_ms,
                last_seen_monotonic_by_root=dict(self._last_seen_monotonic),
            )
