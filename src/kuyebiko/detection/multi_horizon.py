"""Multi-horizon observation windows and correlation for Kuyebiko.

Maintains multi-tiered sliding correlation windows (e.g., short: 10s, medium: 60s,
long: 300s) with per-root isolation, strict monotonic time progression, bounded
memory caps, independent expiration, out-of-order handling, and unified telemetry
degradation propagation.
"""

import logging
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.window import RootSlidingWindow
from kuyebiko.models.events import FileEvent
from kuyebiko.processing.ordering import EventOrderingMetadata

logger = logging.getLogger("kuyebiko.detection.multi_horizon")

# Initial engineering defaults for multi-horizon observation
DEFAULT_HORIZONS: dict[str, float] = {
    "short": 10.0,
    "medium": 60.0,
    "long": 300.0,
}

DEFAULT_MAX_EVENTS_PER_HORIZON: dict[str, int] = {
    "short": 2000,
    "medium": 5000,
    "long": 10000,
}


def _build_context_for_window(
    root_id: str,
    window: RootSlidingWindow,
    clock_ns: int,
    upstream_degraded: bool = False,
    upstream_reason: str | None = None,
    upstream_kernel_loss: bool = False,
    config: dict | None = None,
) -> DetectionContext:
    """Build an immutable DetectionContext from a RootSlidingWindow snapshot."""
    window.prune_expired(clock_ns)
    events = window.get_events()
    stats = window.get_aggregate_stats(clock_ns)

    now_utc = datetime.now(UTC)
    start_utc = events[0].timestamp_utc if events else now_utc
    end_utc = events[-1].timestamp_utc if events else now_utc

    active_reasons: list[str] = []
    if upstream_degraded:
        active_reasons.append(upstream_reason or "upstream_telemetry_degraded")
    if upstream_kernel_loss:
        active_reasons.append("uncounted_kernel_loss")
    if window.active_capacity_dropped_events > 0:
        active_reasons.append(
            f"sliding_window_capacity_dropped:{window.active_capacity_dropped_events}"
        )
    if window.active_retrograde_dropped_events > 0:
        active_reasons.append(
            f"retrograde_events_dropped:{window.active_retrograde_dropped_events}"
        )

    is_degraded = bool(active_reasons)
    reason = "; ".join(active_reasons) if active_reasons else None

    return DetectionContext(
        root_id=root_id,
        events=events,
        stats=stats,
        evaluated_monotonic_ns=clock_ns,
        window_start_utc=start_utc,
        window_end_utc=end_utc,
        window_duration_seconds=window.window_duration_seconds,
        is_telemetry_degraded=is_degraded,
        degradation_reason=reason,
        uncounted_kernel_loss=upstream_kernel_loss,
        config=config or {},
    )


class RootMultiHorizonWindow:
    """Manages multi-tier observation windows for a single monitored root."""

    def __init__(
        self,
        root_id: str,
        horizons: Mapping[str, float] | None = None,
        max_events_per_horizon: Mapping[str, int] | None = None,
    ) -> None:
        if not root_id.strip():
            raise ValueError("root_id cannot be empty")

        self._root_id = root_id
        self._horizon_specs: dict[str, float] = dict(
            horizons if horizons is not None else DEFAULT_HORIZONS
        )
        self._max_events_specs: dict[str, int] = dict(
            max_events_per_horizon
            if max_events_per_horizon is not None
            else DEFAULT_MAX_EVENTS_PER_HORIZON
        )

        for name, duration in self._horizon_specs.items():
            if duration <= 0.0:
                raise ValueError(
                    f"Horizon '{name}' duration must be positive, got {duration}"
                )

        self._lock = threading.RLock()
        self._windows: dict[str, RootSlidingWindow] = {}

        for name, duration in self._horizon_specs.items():
            max_events = self._max_events_specs.get(name, 5000)
            self._windows[name] = RootSlidingWindow(
                root_id=root_id,
                window_duration_seconds=duration,
                max_events=max_events,
            )

    @property
    def root_id(self) -> str:
        return self._root_id

    @property
    def horizon_names(self) -> list[str]:
        with self._lock:
            return list(self._windows.keys())

    def get_horizon_window(self, horizon: str) -> RootSlidingWindow:
        with self._lock:
            if horizon not in self._windows:
                avail = list(self._windows.keys())
                raise KeyError(f"Unknown horizon '{horizon}'. Available: {avail}")
            return self._windows[horizon]

    def add_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
        now_monotonic_ns: int | None = None,
    ) -> None:
        """Route event synchronously to all isolated horizon windows."""
        with self._lock:
            for window in self._windows.values():
                window.add_event(
                    event=event,
                    ordering=ordering,
                    now_monotonic_ns=now_monotonic_ns,
                )

    def get_context(
        self,
        primary_horizon: str = "short",
        now_monotonic_ns: int | None = None,
        upstream_telemetry_degraded: bool = False,
        upstream_degradation_reason: str | None = None,
        upstream_kernel_loss: bool = False,
    ) -> DetectionContext:
        """Construct primary detection context enriched with multi-horizon telemetry.

        Ensures telemetry degradation in ANY horizon or upstream source is
        propagated to the primary context, preventing longer horizons from
        concealing observation loss.
        """
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else time.monotonic_ns()
        )

        with self._lock:
            if primary_horizon not in self._windows:
                raise KeyError(
                    f"Unknown primary horizon '{primary_horizon}'. "
                    f"Available: {list(self._windows.keys())}"
                )

            # Evaluate context for all horizons
            horizon_contexts: dict[str, DetectionContext] = {}
            horizon_stats: dict[str, Any] = {}
            any_degraded = upstream_telemetry_degraded
            degradation_reasons: list[str] = []
            if upstream_degradation_reason:
                degradation_reasons.append(upstream_degradation_reason)
            any_kernel_loss = upstream_kernel_loss

            for name, win in self._windows.items():
                ctx = _build_context_for_window(
                    root_id=self._root_id,
                    window=win,
                    clock_ns=clock_ns,
                    upstream_degraded=upstream_telemetry_degraded,
                    upstream_reason=upstream_degradation_reason,
                    upstream_kernel_loss=upstream_kernel_loss,
                )
                horizon_contexts[name] = ctx
                horizon_stats[name] = ctx.stats
                if ctx.is_telemetry_degraded:
                    any_degraded = True
                    if (
                        ctx.degradation_reason
                        and ctx.degradation_reason not in degradation_reasons
                    ):
                        degradation_reasons.append(f"{name}:{ctx.degradation_reason}")
                if ctx.uncounted_kernel_loss:
                    any_kernel_loss = True

            primary_ctx = horizon_contexts[primary_horizon]

            # Merge horizon telemetry into primary context config
            new_config = dict(primary_ctx.config)
            new_config["horizons"] = horizon_contexts
            new_config["multi_horizon_stats"] = horizon_stats
            new_config["configured_horizons"] = {
                name: win.window_duration_seconds for name, win in self._windows.items()
            }

            combined_reason = (
                "; ".join(degradation_reasons) if degradation_reasons else None
            )

            # Return primary context with unified degradation guarantees
            return primary_ctx.model_copy(
                update={
                    "config": new_config,
                    "is_telemetry_degraded": any_degraded,
                    "degradation_reason": combined_reason,
                    "uncounted_kernel_loss": any_kernel_loss,
                }
            )

    def clear(self) -> None:
        with self._lock:
            for window in self._windows.values():
                window.clear()


class MultiHorizonSlidingWindow:
    """Manages multi-horizon observation windows across multiple monitored roots."""

    def __init__(
        self,
        horizons: Mapping[str, float] | None = None,
        max_events_per_horizon: Mapping[str, int] | None = None,
        max_active_roots: int = 100,
    ) -> None:
        if max_active_roots < 1:
            raise ValueError(
                f"max_active_roots must be at least 1, got {max_active_roots}"
            )

        self._horizon_specs: dict[str, float] = dict(
            horizons if horizons is not None else DEFAULT_HORIZONS
        )
        self._max_events_specs: dict[str, int] = dict(
            max_events_per_horizon
            if max_events_per_horizon is not None
            else DEFAULT_MAX_EVENTS_PER_HORIZON
        )
        self._max_active_roots = max_active_roots

        self._roots: dict[str, RootMultiHorizonWindow] = {}
        self._last_activity_monotonic: dict[str, int] = {}
        self._evicted_roots_loss: dict[str, int] = {}
        self._total_evicted_roots_count: int = 0
        self._lock = threading.RLock()

    @property
    def window_duration_seconds(self) -> float:
        """Default duration (short horizon) for backward compatibility."""
        return self._horizon_specs.get("short", 10.0)

    @property
    def horizons(self) -> dict[str, float]:
        return dict(self._horizon_specs)

    @property
    def active_root_count(self) -> int:
        with self._lock:
            return len(self._roots)

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
        """Route FileEvent to the root's multi-horizon window collection."""
        root_id = event.root_id
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else event.monotonic_ns
        )

        with self._lock:
            if root_id not in self._roots:
                if len(self._roots) >= self._max_active_roots:
                    oldest_idle = min(
                        self._last_activity_monotonic.keys(),
                        key=lambda r: self._last_activity_monotonic[r],
                    )
                    logger.warning(
                        "MultiHorizon root capacity (%d) reached. Evicting '%s'.",
                        self._max_active_roots,
                        oldest_idle,
                    )
                    self._evicted_roots_loss[oldest_idle] = clock_ns
                    self._total_evicted_roots_count += 1
                    self.remove_root(oldest_idle)

                self._roots[root_id] = RootMultiHorizonWindow(
                    root_id=root_id,
                    horizons=self._horizon_specs,
                    max_events_per_horizon=self._max_events_specs,
                )

            self._last_activity_monotonic[root_id] = clock_ns
            self._roots[root_id].add_event(
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
        config: dict | None = None,
        horizon: str = "short",
        **kwargs: Any,
    ) -> DetectionContext:
        """Retrieve DetectionContext for a given root and observation horizon."""
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else time.monotonic_ns()
        )
        # Support both naming conventions for compatibility
        upstream_degraded = is_telemetry_degraded or kwargs.get(
            "upstream_telemetry_degraded", False
        )
        upstream_reason = degradation_reason or kwargs.get(
            "upstream_degradation_reason"
        )
        upstream_kernel = uncounted_kernel_loss or kwargs.get(
            "upstream_kernel_loss", False
        )

        with self._lock:
            if root_id not in self._roots:
                window = RootMultiHorizonWindow(
                    root_id=root_id,
                    horizons=self._horizon_specs,
                    max_events_per_horizon=self._max_events_specs,
                )
                self._roots[root_id] = window
                self._last_activity_monotonic[root_id] = clock_ns

            was_evicted = root_id in self._evicted_roots_loss
            eviction_loss = was_evicted and (
                clock_ns - self._evicted_roots_loss[root_id]
                < int(self._horizon_specs.get(horizon, 10.0) * 1_000_000_000)
            )

            is_degraded = upstream_degraded or eviction_loss
            reason = upstream_reason
            if eviction_loss:
                reason = (
                    f"{reason}; root_eviction_telemetry_loss"
                    if reason
                    else "root_eviction_telemetry_loss"
                )

            ctx = self._roots[root_id].get_context(
                primary_horizon=horizon,
                now_monotonic_ns=clock_ns,
                upstream_telemetry_degraded=is_degraded,
                upstream_degradation_reason=reason,
                upstream_kernel_loss=upstream_kernel,
            )
            if config:
                merged_config = dict(ctx.config)
                merged_config.update(config)
                ctx = ctx.model_copy(update={"config": merged_config})
            return ctx

    def remove_root(self, root_id: str) -> bool:
        with self._lock:
            self._last_activity_monotonic.pop(root_id, None)
            root_win = self._roots.pop(root_id, None)
            if root_win is not None:
                root_win.clear()
                return True
            return False

    def prune_stale_roots(
        self,
        max_idle_seconds: float = 300.0,
        now_monotonic_ns: int | None = None,
    ) -> int:
        idle_ns = int(max_idle_seconds * 1_000_000_000)
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else time.monotonic_ns()
        )
        with self._lock:
            stale = [
                r
                for r, last_ns in self._last_activity_monotonic.items()
                if (clock_ns - last_ns) > idle_ns
            ]
            for r in stale:
                self.remove_root(r)
            return len(stale)

    def clear(self) -> None:
        with self._lock:
            for root_win in self._roots.values():
                root_win.clear()
            self._roots.clear()
            self._last_activity_monotonic.clear()
            self._evicted_roots_loss.clear()
            self._total_evicted_roots_count = 0
