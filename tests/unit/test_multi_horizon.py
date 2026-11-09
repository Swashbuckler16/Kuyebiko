"""Unit tests for Step 5.6: Multi-Horizon Observation Windows & Correlation."""

from uuid import uuid4

import pytest

from kuyebiko.detection.multi_horizon import (
    MultiHorizonSlidingWindow,
    RootMultiHorizonWindow,
)
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_event(
    file_path: str,
    monotonic_ns: int,
    root_id: str = "root-1",
    event_type: EventType = EventType.MODIFIED,
) -> FileEvent:
    return FileEvent(
        event_id=str(uuid4()),
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        monotonic_ns=monotonic_ns,
        source=EventSource.WINDOWS_WATCHER,
    )


def test_root_multi_horizon_window_routing_and_expiration():
    """Events route to all horizons and expire per individual duration."""
    horizons = {"short": 2.0, "medium": 5.0, "long": 10.0}
    root_window = RootMultiHorizonWindow(root_id="root-1", horizons=horizons)

    base_ns = 10_000_000_000  # 10s
    # Event 1 at t=10s
    ev1 = _make_event("docs/file1.txt", monotonic_ns=base_ns)
    # Event 2 at t=13s (3s later: ev1 expired for short (2s), active for medium (5s))
    ev2 = _make_event("docs/file2.txt", monotonic_ns=base_ns + 3_000_000_000)

    root_window.add_event(ev1)
    root_window.add_event(ev2)

    # Evaluate at t=13s
    ctx_short = root_window.get_context(
        primary_horizon="short", now_monotonic_ns=base_ns + 3_000_000_000
    )
    assert len(ctx_short.events) == 1
    assert ctx_short.events[0].file_path == "docs/file2.txt"

    # Multi-horizon enrichment present in config
    assert "horizons" in ctx_short.config
    ctx_medium = ctx_short.config["horizons"]["medium"]
    assert len(ctx_medium.events) == 2  # both ev1 and ev2 within 5s

    ctx_long = ctx_short.config["horizons"]["long"]
    assert len(ctx_long.events) == 2


def test_multi_horizon_degradation_propagation():
    """Telemetry degradation in any horizon propagates to the primary context."""
    horizons = {"short": 2.0, "medium": 5.0}
    # Set small max_events for short horizon to force capacity drop
    max_events = {"short": 10, "medium": 100}
    root_window = RootMultiHorizonWindow(
        root_id="root-1",
        horizons=horizons,
        max_events_per_horizon=max_events,
    )

    base_ns = 10_000_000_000
    # Add 12 events to trigger capacity drop on short horizon
    for i in range(12):
        ev = _make_event(f"file_{i}.txt", monotonic_ns=base_ns + i * 10_000_000)
        root_window.add_event(ev)

    # Medium horizon context (medium had capacity, but short experienced a drop)
    ctx_medium = root_window.get_context(
        primary_horizon="medium", now_monotonic_ns=base_ns + 500_000_000
    )
    assert ctx_medium.is_telemetry_degraded is True
    assert "sliding_window_capacity_dropped" in (ctx_medium.degradation_reason or "")


def test_multi_horizon_sliding_window_multi_root_isolation():
    """Roots are isolated, capacity-bounded, and support stale root pruning."""
    m_window = MultiHorizonSlidingWindow(max_active_roots=2)

    ev_r1 = _make_event("r1/file.txt", monotonic_ns=1_000_000_000, root_id="r1")
    ev_r2 = _make_event("r2/file.txt", monotonic_ns=1_000_000_000, root_id="r2")
    m_window.add_event(ev_r1)
    m_window.add_event(ev_r2)

    assert m_window.active_root_count == 2

    # Add r3 to trigger LRU eviction of r1
    ev_r3 = _make_event("r3/file.txt", monotonic_ns=2_000_000_000, root_id="r3")
    m_window.add_event(ev_r3)

    assert m_window.active_root_count == 2
    assert m_window.total_evicted_roots_count == 1

    # Context for newly added r3 is clean
    ctx_r3 = m_window.get_context("r3")
    assert ctx_r3.root_id == "r3"
    assert ctx_r3.is_telemetry_degraded is False

    # Stale root pruning
    pruned = m_window.prune_stale_roots(
        max_idle_seconds=1.0, now_monotonic_ns=10_000_000_000
    )
    assert pruned == 2
    assert m_window.active_root_count == 0


def test_invalid_horizon_handling():
    """Requesting an unknown horizon raises KeyError."""
    root_window = RootMultiHorizonWindow(root_id="root-1")
    with pytest.raises(KeyError):
        root_window.get_context(primary_horizon="ultra_long")
