"""Unit tests for telemetry health & root recovery hardening (Step 4.7)."""

import time

from kuyebiko.detection.window import SlidingWindowCorrelator
from kuyebiko.models.events import EventSource, EventType, FileEvent, TelemetryQuality


def _make_event(
    root_id: str = "root-1",
    file_path: str = "file.txt",
    event_type: EventType = EventType.MODIFIED,
    monotonic_ns: int | None = None,
    event_id: str | None = None,
) -> FileEvent:
    return FileEvent(
        event_id=event_id or f"evt_{file_path}_{time.monotonic_ns()}",
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        monotonic_ns=(
            monotonic_ns if monotonic_ns is not None else time.monotonic_ns()
        ),
        source=EventSource.WINDOWS_WATCHER,
    )


def test_elapsed_time_alone_does_not_clear_eviction_degradation_if_idle():
    """An evicted root does NOT recover if elapsed time passed with no events."""
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_active_roots=2
    )
    t0 = 10_000_000_000

    correlator.add_event(
        _make_event(root_id="r1", monotonic_ns=t0), now_monotonic_ns=t0
    )
    correlator.add_event(
        _make_event(root_id="r2", monotonic_ns=t0 + 1_000_000_000),
        now_monotonic_ns=t0 + 1_000_000_000,
    )
    # Evict r1
    correlator.add_event(
        _make_event(root_id="r3", monotonic_ns=t0 + 2_000_000_000),
        now_monotonic_ns=t0 + 2_000_000_000,
    )
    assert correlator.total_evicted_roots_count == 1

    # r1 re-appears with 1 single event at t=15s
    t_reappear = t0 + 5_000_000_000
    correlator.add_event(
        _make_event(root_id="r1", monotonic_ns=t_reappear),
        now_monotonic_ns=t_reappear,
    )

    # 20 seconds later (no other events arrived for r1; e1 expired)
    t_far = t_reappear + 20_000_000_000
    ctx = correlator.get_context("r1", now_monotonic_ns=t_far)
    assert ctx is not None
    # Telemetry MUST still be degraded because 0 events exist in the active window!
    assert ctx.is_telemetry_degraded is True
    assert "root_previously_evicted" in ctx.degradation_reason


def test_eviction_recovery_requires_healthy_watcher():
    """Evicted root cannot recover if external watcher or pipeline is degraded."""
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_active_roots=2
    )
    t0 = 10_000_000_000

    correlator.add_event(
        _make_event(root_id="r1", monotonic_ns=t0), now_monotonic_ns=t0
    )
    correlator.add_event(
        _make_event(root_id="r2", monotonic_ns=t0 + 1_000_000_000),
        now_monotonic_ns=t0 + 1_000_000_000,
    )
    # Evict r1
    correlator.add_event(
        _make_event(root_id="r3", monotonic_ns=t0 + 2_000_000_000),
        now_monotonic_ns=t0 + 2_000_000_000,
    )

    # r1 re-appears and receives active stream across 12 seconds
    t_start = t0 + 5_000_000_000
    for i in range(12):
        correlator.add_event(
            _make_event(
                root_id="r1",
                file_path=f"f_{i}.txt",
                monotonic_ns=t_start + i * 1_000_000_000,
            ),
            now_monotonic_ns=t_start + i * 1_000_000_000,
        )

    t_eval = t_start + 12_000_000_000
    # But watcher reports degradation (e.g. kernel overflow or degraded quality)
    ctx_unhealthy_watcher = correlator.get_context(
        "r1",
        now_monotonic_ns=t_eval,
        is_telemetry_degraded=True,
        degradation_reason="watcher_buffer_overflow",
    )
    assert ctx_unhealthy_watcher is not None
    assert ctx_unhealthy_watcher.is_telemetry_degraded is True
    assert "watcher_buffer_overflow" in ctx_unhealthy_watcher.degradation_reason
    assert "root_previously_evicted" in ctx_unhealthy_watcher.degradation_reason

    # Once watcher recovers to healthy, root eviction recovers too!
    ctx_healthy = correlator.get_context(
        "r1",
        now_monotonic_ns=t_eval,
        is_telemetry_degraded=False,
        quality=TelemetryQuality.NORMAL,
    )
    assert ctx_healthy is not None
    assert ctx_healthy.is_telemetry_degraded is False
    assert ctx_healthy.degradation_reason is None


def test_independent_tracking_and_partial_recovery():
    """Verify multiple degradation reasons track and recover independently."""
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_events_per_root=10
    )
    root = "root-multi"
    base_ns = 50_000_000_000

    # 1. Trigger capacity drops by adding 12 events to a 10-event window
    for i in range(12):
        correlator.add_event(
            _make_event(
                root_id=root,
                file_path=f"f_{i}.txt",
                monotonic_ns=base_ns + i * 1000,
            ),
            now_monotonic_ns=base_ns + i * 1000,
        )

    # 2. Trigger retrograde drop by adding an event older by 15s
    correlator.add_event(
        _make_event(
            root_id=root,
            file_path="old.txt",
            monotonic_ns=base_ns - 15_000_000_000,
        ),
        now_monotonic_ns=base_ns + 12_000,
    )

    # 3. Add external watcher degradation
    ctx_all = correlator.get_context(
        root,
        now_monotonic_ns=base_ns + 15_000,
        is_telemetry_degraded=True,
        degradation_reason="driver_timeout",
    )
    assert ctx_all is not None
    assert ctx_all.is_telemetry_degraded is True
    # All 3 reasons must be present!
    assert "driver_timeout" in ctx_all.degradation_reason
    assert "sliding_window_capacity_dropped:2" in ctx_all.degradation_reason
    assert "retrograde_events_dropped:1" in ctx_all.degradation_reason

    # Partial recovery: Watcher recovers, but window drops remain active!
    ctx_partial = correlator.get_context(
        root,
        now_monotonic_ns=base_ns + 15_000,
        is_telemetry_degraded=False,
    )
    assert ctx_partial is not None
    assert ctx_partial.is_telemetry_degraded is True
    assert "driver_timeout" not in (ctx_partial.degradation_reason or "")
    assert "sliding_window_capacity_dropped:2" in ctx_partial.degradation_reason
    assert "retrograde_events_dropped:1" in ctx_partial.degradation_reason

    # Full recovery: Advance clock past 10s window horizon
    ctx_full = correlator.get_context(
        root,
        now_monotonic_ns=base_ns + 11_000_000_000,
        is_telemetry_degraded=False,
    )
    assert ctx_full is not None
    assert ctx_full.is_telemetry_degraded is False
    assert ctx_full.degradation_reason is None


def test_continued_capacity_drops_maintain_degradation():
    """If capacity drops continue to occur, degradation is maintained continuously."""
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=5.0, max_events_per_root=10
    )
    root = "root-stream"
    t = 1_000_000_000

    # Fill window with 12 events at t=1s (2 drops)
    for i in range(12):
        correlator.add_event(
            _make_event(root_id=root, file_path=f"f_{i}.txt", monotonic_ns=t),
            now_monotonic_ns=t,
        )

    # Advance 3 seconds (t=4s) and trigger another capacity drop
    t4 = t + 3_000_000_000
    for i in range(11):
        correlator.add_event(
            _make_event(root_id=root, file_path=f"f2_{i}.txt", monotonic_ns=t4),
            now_monotonic_ns=t4,
        )

    # At t=7s (drops from t=4s are still active within 5s window horizon)
    t7 = t + 6_000_000_000
    ctx = correlator.get_context(root, now_monotonic_ns=t7)
    assert ctx is not None
    assert ctx.is_telemetry_degraded is True
    assert "sliding_window_capacity_dropped" in ctx.degradation_reason
