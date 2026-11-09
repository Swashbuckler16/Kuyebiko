"""Sliding-window event correlation and statistical aggregation.

Provides chronological, bounded per-root event buffering, monotonic time-based
expiration, out-of-order handling, and O(1) incremental aggregation for
behavioural ransomware signals.

Complexity Characteristics:
- Normal Chronological Arrival (Fast Path): Amortized O(1) append to event and
  timestamp structures.
- Out-of-Order Arrival (Worst Case): O(log n) binary search on pre-allocated
  monotonic timestamp array + O(n) element shift for in-place list insertion.
- Expiration: Amortized O(k) where k is the number of expired events.
- Aggregate Statistics: O(1) instantaneous access via incremental counters.
"""

import bisect
import logging
import posixpath
import threading
import time
from collections import Counter, deque
from datetime import UTC, datetime

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import WindowAggregateStats
from kuyebiko.models.events import (
    EventType,
    FileEvent,
    TelemetryQuality,
    is_approved_rename_provenance,
)
from kuyebiko.processing.ordering import EventOrderingMetadata

logger = logging.getLogger("kuyebiko.detection.window")


class RootSlidingWindow:
    """Thread-safe bounded sliding window of events for a single monitored root."""

    def __init__(
        self,
        root_id: str,
        window_duration_seconds: float = 10.0,
        max_events: int = 5000,
    ) -> None:
        if not root_id.strip():
            raise ValueError("root_id cannot be empty")
        if window_duration_seconds <= 0.0:
            raise ValueError(
                "window_duration_seconds must be positive, "
                f"got {window_duration_seconds}"
            )
        if max_events < 10:
            raise ValueError(f"max_events must be at least 10, got {max_events}")

        self._root_id = root_id
        self._window_duration_ns = int(window_duration_seconds * 1_000_000_000)
        self._window_duration_seconds = window_duration_seconds
        self._max_events = max_events

        self._lock = threading.RLock()
        # Chronologically sorted list of events, ordering metadata, and timestamps
        self._events: list[FileEvent] = []
        self._ordering_meta: list[EventOrderingMetadata | None] = []
        self._timestamps: list[int] = []

        # Incremental counters for O(1) access
        self._created_count = 0
        self._modified_count = 0
        self._deleted_count = 0
        self._renamed_count = 0
        self._directory_operations_count = 0
        self._rename_pairs_count = 0

        self._path_counts: Counter[str] = Counter()
        self._ext_counts: Counter[str] = Counter()
        self._dir_counts: Counter[str] = Counter()
        self._active_event_ids: set[str] = set()

        # Capacity drop tracking with recovery: drops within active horizon
        self._capacity_drop_timestamps: deque[int] = deque()
        self._cumulative_capacity_dropped: int = 0

        # Retrograde (expired out-of-order) drop tracking with recovery
        self._retrograde_drop_timestamps: deque[int] = deque()
        self._cumulative_retrograde_dropped: int = 0

        self._last_event_monotonic_ns: int | None = None
        self._last_event_utc: datetime | None = None

    @property
    def root_id(self) -> str:
        return self._root_id

    @property
    def window_duration_seconds(self) -> float:
        return self._window_duration_seconds

    @property
    def capacity_dropped_events(self) -> int:
        """Active capacity drops within the current sliding window horizon."""
        with self._lock:
            return len(self._capacity_drop_timestamps)

    @property
    def active_capacity_dropped_events(self) -> int:
        """Active capacity drops within the current sliding window horizon."""
        with self._lock:
            return len(self._capacity_drop_timestamps)

    @property
    def cumulative_capacity_dropped_events(self) -> int:
        """Total cumulative capacity drops since window creation."""
        with self._lock:
            return self._cumulative_capacity_dropped

    @property
    def retrograde_dropped_events(self) -> int:
        """Active retrograde drops within current sliding window horizon."""
        with self._lock:
            return len(self._retrograde_drop_timestamps)

    @property
    def active_retrograde_dropped_events(self) -> int:
        """Active retrograde drops within current sliding window horizon."""
        with self._lock:
            return len(self._retrograde_drop_timestamps)

    @property
    def cumulative_retrograde_dropped_events(self) -> int:
        """Total cumulative retrograde drops since window creation."""
        with self._lock:
            return self._cumulative_retrograde_dropped

    def add_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
        now_monotonic_ns: int | None = None,
    ) -> None:
        """Append or chronologically insert a normalized FileEvent.

        Complexity:
        - Fast path: Amortized O(1) when event is empty or arrives >= latest event.
        - Out-of-order path: O(log n) binary search in pre-maintained monotonic
          timestamps followed by O(n) list insertion.
        """
        if event.root_id != self._root_id:
            raise ValueError(
                f"Event root_id {event.root_id} does not match "
                f"window root_id {self._root_id}"
            )

        with self._lock:
            # Suppress duplicate delivery of identical event ID within active window
            if event.event_id in self._active_event_ids:
                logger.debug(
                    "Duplicate event ID %s ignored in window for root %s",
                    event.event_id,
                    self._root_id,
                )
                return

            clock_ns = (
                now_monotonic_ns if now_monotonic_ns is not None else event.monotonic_ns
            )
            self._prune_expired_locked(clock_ns)

            # Check if this event arrived out-of-order and is already expired
            if (clock_ns - event.monotonic_ns) > self._window_duration_ns:
                # Event is outside active window horizon; record telemetry drop
                self._retrograde_drop_timestamps.append(clock_ns)
                self._cumulative_retrograde_dropped += 1
                return

            self._active_event_ids.add(event.event_id)

            # Fast path (O(1) amortized): Chronological arrival
            if not self._timestamps or event.monotonic_ns >= self._timestamps[-1]:
                self._events.append(event)
                self._ordering_meta.append(ordering)
                self._timestamps.append(event.monotonic_ns)
            else:
                # Out-of-order path: O(log n) binary search + O(n) list insertion
                # Reuses parallel self._timestamps without dynamic list allocations
                idx = bisect.bisect_right(self._timestamps, event.monotonic_ns)
                self._events.insert(idx, event)
                self._ordering_meta.insert(idx, ordering)
                self._timestamps.insert(idx, event.monotonic_ns)

            self._include_event_locked(event)

            # Strictly enforce capacity bound: evict oldest if capacity exceeded
            if len(self._events) > self._max_events:
                self._evict_oldest_locked()
                self._capacity_drop_timestamps.append(clock_ns)
                self._cumulative_capacity_dropped += 1

            self._last_event_monotonic_ns = event.monotonic_ns
            self._last_event_utc = event.timestamp_utc

    def prune_expired(self, now_monotonic_ns: int) -> int:
        """Evict events older than window_duration relative to now_monotonic_ns."""
        with self._lock:
            return self._prune_expired_locked(now_monotonic_ns)

    def _prune_expired_locked(self, now_monotonic_ns: int) -> int:
        evicted = 0
        cutoff_ns = now_monotonic_ns - self._window_duration_ns

        # Events are sorted chronologically: self._events[0] is oldest
        while self._events and self._events[0].monotonic_ns < cutoff_ns:
            self._evict_oldest_locked()
            evicted += 1

        # Expire old capacity drop records so degradation recovers
        while (
            self._capacity_drop_timestamps
            and self._capacity_drop_timestamps[0] < cutoff_ns
        ):
            self._capacity_drop_timestamps.popleft()

        # Expire old retrograde drop records so degradation recovers
        while (
            self._retrograde_drop_timestamps
            and self._retrograde_drop_timestamps[0] < cutoff_ns
        ):
            self._retrograde_drop_timestamps.popleft()

        return evicted

    def _evict_oldest_locked(self) -> None:
        if not self._events:
            return
        evicted_event = self._events.pop(0)
        self._ordering_meta.pop(0)
        self._timestamps.pop(0)
        self._active_event_ids.discard(evicted_event.event_id)
        self._exclude_event_locked(evicted_event)

    def _include_event_locked(self, event: FileEvent) -> None:
        match event.event_type:
            case EventType.CREATED:
                self._created_count += 1
            case EventType.MODIFIED:
                self._modified_count += 1
            case EventType.DELETED:
                self._deleted_count += 1
            case EventType.RENAMED:
                self._renamed_count += 1
                if (
                    not event.is_directory
                    and event.old_path
                    and event.new_path
                    and event.old_path != event.new_path
                    and is_approved_rename_provenance(event.correlation_provenance)
                ):
                    self._rename_pairs_count += 1

        if event.is_directory:
            self._directory_operations_count += 1

        path = event.file_path
        self._path_counts[path] += 1

        dirname = posixpath.dirname(path)
        self._dir_counts[dirname] += 1

        _, ext = posixpath.splitext(path)
        ext_clean = ext.lower()
        self._ext_counts[ext_clean] += 1

    def _exclude_event_locked(self, event: FileEvent) -> None:
        match event.event_type:
            case EventType.CREATED:
                self._created_count = max(0, self._created_count - 1)
            case EventType.MODIFIED:
                self._modified_count = max(0, self._modified_count - 1)
            case EventType.DELETED:
                self._deleted_count = max(0, self._deleted_count - 1)
            case EventType.RENAMED:
                self._renamed_count = max(0, self._renamed_count - 1)
                if (
                    not event.is_directory
                    and event.old_path
                    and event.new_path
                    and event.old_path != event.new_path
                    and is_approved_rename_provenance(event.correlation_provenance)
                ):
                    self._rename_pairs_count = max(0, self._rename_pairs_count - 1)

        if event.is_directory:
            self._directory_operations_count = max(
                0, self._directory_operations_count - 1
            )

        path = event.file_path
        self._path_counts[path] -= 1
        if self._path_counts[path] <= 0:
            del self._path_counts[path]

        dirname = posixpath.dirname(path)
        self._dir_counts[dirname] -= 1
        if self._dir_counts[dirname] <= 0:
            del self._dir_counts[dirname]

        _, ext = posixpath.splitext(path)
        ext_clean = ext.lower()
        self._ext_counts[ext_clean] -= 1
        if self._ext_counts[ext_clean] <= 0:
            del self._ext_counts[ext_clean]

    def get_events(self) -> list[FileEvent]:
        """Return a snapshot copy of current events in the window."""
        with self._lock:
            return list(self._events)

    def get_aggregate_stats(
        self, now_monotonic_ns: int | None = None
    ) -> WindowAggregateStats:
        """Calculate and return a snapshot of window metrics."""
        with self._lock:
            if now_monotonic_ns is not None:
                self._prune_expired_locked(now_monotonic_ns)

            total = len(self._events)
            eps = 0.0
            if total > 0:
                eps = total / self._window_duration_seconds

            # Sort path list for small collections (unit tests & inspection);
            # for high-load collections (> 200 paths), use O(n) direct key list
            if len(self._path_counts) <= 200:
                u_paths = sorted(self._path_counts.keys())
            else:
                u_paths = list(self._path_counts.keys())

            return WindowAggregateStats(
                total_events=total,
                created_count=self._created_count,
                modified_count=self._modified_count,
                deleted_count=self._deleted_count,
                renamed_count=self._renamed_count,
                directory_operations_count=self._directory_operations_count,
                unique_extensions=sorted(self._ext_counts.keys()),
                unique_directories=sorted(self._dir_counts.keys()),
                unique_relative_paths=u_paths,
                rename_pairs_count=self._rename_pairs_count,
                events_per_second=round(eps, 2),
                window_duration_seconds=self._window_duration_seconds,
            )

    def clear(self) -> None:
        """Reset the window and all incremental counters."""
        with self._lock:
            self._events.clear()
            self._ordering_meta.clear()
            self._timestamps.clear()
            self._active_event_ids.clear()
            self._created_count = 0
            self._modified_count = 0
            self._deleted_count = 0
            self._renamed_count = 0
            self._directory_operations_count = 0
            self._rename_pairs_count = 0
            self._path_counts.clear()
            self._ext_counts.clear()
            self._dir_counts.clear()
            self._capacity_drop_timestamps.clear()
            self._cumulative_capacity_dropped = 0
            self._retrograde_drop_timestamps.clear()
            self._cumulative_retrograde_dropped = 0
            self._last_event_monotonic_ns = None
            self._last_event_utc = None


class SlidingWindowCorrelator:
    """Manages independent, isolated sliding windows across all monitored roots."""

    def __init__(
        self,
        window_duration_seconds: float = 10.0,
        max_events_per_root: int = 5000,
        max_active_roots: int = 100,
    ) -> None:
        if window_duration_seconds <= 0.0:
            raise ValueError(
                "window_duration_seconds must be positive, "
                f"got {window_duration_seconds}"
            )
        if max_events_per_root < 10:
            raise ValueError(
                f"max_events_per_root must be at least 10, got {max_events_per_root}"
            )
        if max_active_roots < 1:
            raise ValueError(
                f"max_active_roots must be at least 1, got {max_active_roots}"
            )

        self._window_duration_seconds = window_duration_seconds
        self._max_events_per_root = max_events_per_root
        self._max_active_roots = max_active_roots

        self._windows: dict[str, RootSlidingWindow] = {}
        self._last_activity_monotonic: dict[str, int] = {}
        # Explicit telemetry loss tracking for forcefully evicted roots
        self._evicted_roots_loss: dict[str, int] = {}
        self._evicted_root_reseen_monotonic: dict[str, int] = {}
        self._total_evicted_roots_count: int = 0
        self._lock = threading.RLock()

    @property
    def window_duration_seconds(self) -> float:
        return self._window_duration_seconds

    @property
    def active_root_count(self) -> int:
        with self._lock:
            return len(self._windows)

    @property
    def total_evicted_roots_count(self) -> int:
        with self._lock:
            return self._total_evicted_roots_count

    def add_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
        now_monotonic_ns: int | None = None,
    ) -> None:
        """Route normalized FileEvent to its root's isolated sliding window."""
        root_id = event.root_id
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else event.monotonic_ns
        )

        with self._lock:
            if root_id not in self._windows:
                if len(self._windows) >= self._max_active_roots:
                    # Enforce bounded capacity and record explicit telemetry loss
                    oldest_idle_root = min(
                        self._last_activity_monotonic.keys(),
                        key=lambda r: self._last_activity_monotonic[r],
                    )
                    logger.warning(
                        "Active root capacity (%d) reached. Evicting oldest idle "
                        "root '%s'. Telemetry loss occurred.",
                        self._max_active_roots,
                        oldest_idle_root,
                    )
                    self._evicted_roots_loss[oldest_idle_root] = clock_ns
                    self._evicted_root_reseen_monotonic.pop(oldest_idle_root, None)
                    self._total_evicted_roots_count += 1
                    self.remove_root(oldest_idle_root)

                self._windows[root_id] = RootSlidingWindow(
                    root_id=root_id,
                    window_duration_seconds=self._window_duration_seconds,
                    max_events=self._max_events_per_root,
                )

            # If this root was evicted and returned, record re-seen timestamp
            if (
                root_id in self._evicted_roots_loss
                and root_id not in self._evicted_root_reseen_monotonic
            ):
                self._evicted_root_reseen_monotonic[root_id] = clock_ns

            self._last_activity_monotonic[root_id] = clock_ns
            self._windows[root_id].add_event(
                event=event,
                ordering=ordering,
                now_monotonic_ns=clock_ns,
            )

    def get_context(
        self,
        root_id: str,
        now_monotonic_ns: int | None = None,
        is_telemetry_degraded: bool = False,
        degradation_reason: str | None = None,
        uncounted_kernel_loss: bool = False,
        quality: TelemetryQuality = TelemetryQuality.NORMAL,
        config: dict | None = None,
    ) -> DetectionContext | None:
        """Construct an immutable DetectionContext for evaluation."""
        with self._lock:
            window = self._windows.get(root_id)
            if window is None:
                return None

            clock_ns = (
                now_monotonic_ns
                if now_monotonic_ns is not None
                else time.monotonic_ns()
            )
            window.prune_expired(clock_ns)

            events = window.get_events()
            stats = window.get_aggregate_stats(clock_ns)

            now_utc = datetime.now(UTC)
            if events:
                start_utc = events[0].timestamp_utc
                end_utc = events[-1].timestamp_utc
            else:
                start_utc = now_utc
                end_utc = now_utc

            # Track degradation reasons independently
            active_degradation_reasons: list[str] = []

            # 1. External Watcher / Pipeline Degradation
            if is_telemetry_degraded:
                active_degradation_reasons.append(
                    degradation_reason or "external_telemetry_degraded"
                )
            elif quality not in (
                TelemetryQuality.NORMAL,
                TelemetryQuality.RECOVERED,
            ):
                active_degradation_reasons.append(f"telemetry_quality_{quality.value}")

            if uncounted_kernel_loss:
                active_degradation_reasons.append("uncounted_kernel_loss")

            # 2. Sliding Window Capacity Drops (independently tracked)
            if window.active_capacity_dropped_events > 0:
                drops = window.active_capacity_dropped_events
                active_degradation_reasons.append(
                    f"sliding_window_capacity_dropped:{drops}"
                )

            # 3. Retrograde (Late Expired) Event Drops (independently tracked)
            if window.active_retrograde_dropped_events > 0:
                drops = window.active_retrograde_dropped_events
                active_degradation_reasons.append(f"retrograde_events_dropped:{drops}")

            # 4. Root Eviction Telemetry Loss & Recovery Check
            if root_id in self._evicted_roots_loss:
                reseen_ns = self._evicted_root_reseen_monotonic.get(root_id, clock_ns)
                time_since_reseen = clock_ns - reseen_ns
                window_duration_ns = int(self._window_duration_seconds * 1_000_000_000)

                # Recovery requires genuine observation continuity evidence:
                # - Must have active events demonstrating continuity (>= 2 events)
                # - Span of active events >= window_duration, OR
                #   elapsed time since reseen >= window_duration with recent event
                # - External watcher must be healthy (no degradation, no kernel loss)
                # - Window must have no active drops (capacity and retrograde == 0)
                has_continuity_evidence = len(events) >= 2 and (
                    (events[-1].monotonic_ns - events[0].monotonic_ns)
                    >= window_duration_ns
                    or (
                        time_since_reseen >= window_duration_ns
                        and (clock_ns - events[-1].monotonic_ns) <= window_duration_ns
                    )
                )
                is_watcher_healthy = (
                    not is_telemetry_degraded
                    and not uncounted_kernel_loss
                    and quality in (TelemetryQuality.NORMAL, TelemetryQuality.RECOVERED)
                )
                is_window_healthy = (
                    window.active_capacity_dropped_events == 0
                    and window.active_retrograde_dropped_events == 0
                )

                if has_continuity_evidence and is_watcher_healthy and is_window_healthy:
                    # Eviction loss state genuinely recovered!
                    self._evicted_roots_loss.pop(root_id, None)
                    self._evicted_root_reseen_monotonic.pop(root_id, None)
                    logger.info(
                        "Root '%s' observation continuity confirmed (%d events); "
                        "eviction degradation cleared.",
                        root_id,
                        len(events),
                    )
                else:
                    eviction_loss_time = self._evicted_roots_loss[root_id]
                    active_degradation_reasons.append(
                        f"root_previously_evicted_due_to_capacity_limit:{eviction_loss_time}"
                    )

            degraded = bool(active_degradation_reasons)
            deg_reason = (
                "; ".join(active_degradation_reasons)
                if active_degradation_reasons
                else None
            )

            return DetectionContext(
                root_id=root_id,
                events=events,
                stats=stats,
                evaluated_at_utc=now_utc,
                evaluated_monotonic_ns=clock_ns,
                window_start_utc=start_utc,
                window_end_utc=end_utc,
                window_duration_seconds=self._window_duration_seconds,
                quality=quality,
                is_telemetry_degraded=degraded,
                degradation_reason=deg_reason,
                uncounted_kernel_loss=uncounted_kernel_loss,
                config=config or {},
            )

    def get_stats(
        self, root_id: str, now_monotonic_ns: int | None = None
    ) -> WindowAggregateStats | None:
        """Return aggregate statistics for a specific root."""
        with self._lock:
            window = self._windows.get(root_id)
            if window is None:
                return None
            return window.get_aggregate_stats(now_monotonic_ns)

    def remove_root(self, root_id: str) -> bool:
        """Clean up and remove a root's correlation window."""
        with self._lock:
            self._last_activity_monotonic.pop(root_id, None)
            window = self._windows.pop(root_id, None)
            if window is not None:
                window.clear()
                return True
            return False

    def prune_stale_roots(
        self,
        max_idle_seconds: float = 300.0,
        now_monotonic_ns: int | None = None,
    ) -> int:
        """Evict correlation state for roots with no activity for max_idle_seconds."""
        idle_threshold_ns = int(max_idle_seconds * 1_000_000_000)
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else time.monotonic_ns()
        )

        with self._lock:
            stale = [
                r
                for r, last_ns in self._last_activity_monotonic.items()
                if (clock_ns - last_ns) > idle_threshold_ns
            ]
            for r in stale:
                self.remove_root(r)
            return len(stale)

    def clear(self) -> None:
        """Clear all active root windows, activity tracking, and eviction history."""
        with self._lock:
            for window in self._windows.values():
                window.clear()
            self._windows.clear()
            self._last_activity_monotonic.clear()
            self._evicted_roots_loss.clear()
            self._evicted_root_reseen_monotonic.clear()
            self._total_evicted_roots_count = 0
