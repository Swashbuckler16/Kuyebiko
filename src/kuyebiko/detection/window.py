"""Sliding-window event correlation and statistical aggregation.

Provides chronological, bounded per-root event buffering, monotonic time-based
expiration, out-of-order handling, and O(1) incremental aggregation for
behavioural ransomware signals.
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
from kuyebiko.models.events import EventType, FileEvent, TelemetryQuality
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
        # Chronologically sorted list of events and ordering metadata
        self._events: list[FileEvent] = []
        self._ordering_meta: list[EventOrderingMetadata | None] = []

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

        # Capacity drop tracking with recovery: drops within active horizon
        self._capacity_drop_timestamps: deque[int] = deque()
        self._cumulative_capacity_dropped: int = 0
        self._expired_retrograde_drops: int = 0

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

    def add_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
        now_monotonic_ns: int | None = None,
    ) -> None:
        """Append or chronologically insert a normalized FileEvent."""
        if event.root_id != self._root_id:
            raise ValueError(
                f"Event root_id {event.root_id} does not match "
                f"window root_id {self._root_id}"
            )

        with self._lock:
            clock_ns = (
                now_monotonic_ns if now_monotonic_ns is not None else event.monotonic_ns
            )
            self._prune_expired_locked(clock_ns)

            # Check if this event arrived out-of-order and is already expired
            if (clock_ns - event.monotonic_ns) > self._window_duration_ns:
                # Event is outside active window horizon; do not pollute window
                self._expired_retrograde_drops += 1
                return

            # Chronological insertion: if newer or empty, append in O(1)
            if not self._events or event.monotonic_ns >= self._events[-1].monotonic_ns:
                self._events.append(event)
                self._ordering_meta.append(ordering)
            else:
                # Out-of-order event: insert at exact chronological position via bisect
                timestamps = [e.monotonic_ns for e in self._events]
                idx = bisect.bisect_right(timestamps, event.monotonic_ns)
                self._events.insert(idx, event)
                self._ordering_meta.insert(idx, ordering)

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

        return evicted

    def _evict_oldest_locked(self) -> None:
        if not self._events:
            return
        evicted_event = self._events.pop(0)
        self._ordering_meta.pop(0)
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
                    event.old_path
                    and event.new_path
                    and event.old_path != event.new_path
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
                    event.old_path
                    and event.new_path
                    and event.old_path != event.new_path
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

            return WindowAggregateStats(
                total_events=total,
                created_count=self._created_count,
                modified_count=self._modified_count,
                deleted_count=self._deleted_count,
                renamed_count=self._renamed_count,
                directory_operations_count=self._directory_operations_count,
                unique_extensions=sorted(self._ext_counts.keys()),
                unique_directories=sorted(self._dir_counts.keys()),
                unique_relative_paths=sorted(self._path_counts.keys()),
                rename_pairs_count=self._rename_pairs_count,
                events_per_second=round(eps, 2),
                window_duration_seconds=self._window_duration_seconds,
            )

    def clear(self) -> None:
        """Reset the window and all incremental counters."""
        with self._lock:
            self._events.clear()
            self._ordering_meta.clear()
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
            self._expired_retrograde_drops = 0
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
                    self._total_evicted_roots_count += 1
                    self.remove_root(oldest_idle_root)

                self._windows[root_id] = RootSlidingWindow(
                    root_id=root_id,
                    window_duration_seconds=self._window_duration_seconds,
                    max_events=self._max_events_per_root,
                )

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

            degraded = is_telemetry_degraded
            deg_reason = degradation_reason

            # Capacity degradation recovers automatically when active drops reach 0
            if window.active_capacity_dropped_events > 0:
                degraded = True
                drops = window.active_capacity_dropped_events
                capacity_msg = f"sliding_window_capacity_dropped:{drops}"
                deg_reason = (
                    f"{deg_reason}; {capacity_msg}" if deg_reason else capacity_msg
                )

            # Check if this root was previously evicted due to root capacity limit
            if root_id in self._evicted_roots_loss:
                degraded = True
                eviction_msg = (
                    f"root_previously_evicted_due_to_capacity_limit:"
                    f"{self._evicted_roots_loss[root_id]}"
                )
                deg_reason = (
                    f"{deg_reason}; {eviction_msg}" if deg_reason else eviction_msg
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
            self._total_evicted_roots_count = 0
