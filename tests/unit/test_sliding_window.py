"""Unit tests for sliding-window event correlator and statistical aggregation."""

import time
from datetime import UTC, datetime

import pytest

from kuyebiko.detection.window import RootSlidingWindow, SlidingWindowCorrelator
from kuyebiko.models.events import EventSource, EventType, FileEvent
from kuyebiko.processing.ordering import EventOrderingMetadata


def _make_event(
    root_id: str = "root-1",
    file_path: str = "dir/doc.txt",
    event_type: EventType = EventType.MODIFIED,
    monotonic_ns: int | None = None,
    old_path: str | None = None,
    new_path: str | None = None,
    is_directory: bool = False,
    event_id: str = "evt-1",
) -> FileEvent:
    kwargs = {
        "event_id": event_id,
        "root_id": root_id,
        "file_path": file_path,
        "event_type": event_type,
        "monotonic_ns": monotonic_ns
        if monotonic_ns is not None
        else time.monotonic_ns(),
        "source": EventSource.WINDOWS_WATCHER,
        "is_directory": is_directory,
    }
    if event_type == EventType.RENAMED:
        kwargs["old_path"] = old_path or "dir/old.txt"
        kwargs["new_path"] = new_path or file_path
    return FileEvent(**kwargs)


def test_root_sliding_window_validation():
    with pytest.raises(ValueError, match="root_id"):
        RootSlidingWindow(root_id="")

    with pytest.raises(ValueError, match="window_duration_seconds"):
        RootSlidingWindow(root_id="r1", window_duration_seconds=-1.0)

    with pytest.raises(ValueError, match="max_events"):
        RootSlidingWindow(root_id="r1", max_events=5)


def test_root_sliding_window_normal_arrival_and_stats():
    window = RootSlidingWindow(root_id="root-1", window_duration_seconds=10.0)

    # Add 1 created, 2 modified, 1 deleted, 1 renamed
    e1 = _make_event(
        file_path="a.txt",
        event_type=EventType.CREATED,
        monotonic_ns=1_000_000_000,
        event_id="e1",
    )
    e2 = _make_event(
        file_path="sub/b.pdf",
        event_type=EventType.MODIFIED,
        monotonic_ns=2_000_000_000,
        event_id="e2",
    )
    e3 = _make_event(
        file_path="sub/b.pdf",
        event_type=EventType.MODIFIED,
        monotonic_ns=3_000_000_000,
        event_id="e3",
    )
    e4 = _make_event(
        file_path="c.log",
        event_type=EventType.DELETED,
        monotonic_ns=4_000_000_000,
        event_id="e4",
    )
    e5 = _make_event(
        file_path="d.locked",
        event_type=EventType.RENAMED,
        old_path="d.txt",
        new_path="d.locked",
        monotonic_ns=5_000_000_000,
        event_id="e5",
    )

    for e in (e1, e2, e3, e4, e5):
        window.add_event(e)

    stats = window.get_aggregate_stats(now_monotonic_ns=5_000_000_000)

    assert stats.total_events == 5
    assert stats.created_count == 1
    assert stats.modified_count == 2
    assert stats.deleted_count == 1
    assert stats.renamed_count == 1
    assert stats.rename_pairs_count == 1
    assert stats.unique_extensions == [".locked", ".log", ".pdf", ".txt"]
    assert stats.unique_directories == ["", "sub"]
    assert stats.unique_relative_paths == ["a.txt", "c.log", "d.locked", "sub/b.pdf"]
    assert stats.events_per_second == 0.5


def test_root_sliding_window_expiration():
    # 5-second window
    window = RootSlidingWindow(root_id="root-1", window_duration_seconds=5.0)

    # e1 at t=1s
    e1 = _make_event(
        file_path="a.txt",
        event_type=EventType.CREATED,
        monotonic_ns=1_000_000_000,
        event_id="e1",
    )
    # e2 at t=4s
    e2 = _make_event(
        file_path="b.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=4_000_000_000,
        event_id="e2",
    )

    window.add_event(e1)
    window.add_event(e2)

    # At t=5s, both are within 5s
    stats_t5 = window.get_aggregate_stats(now_monotonic_ns=5_000_000_000)
    assert stats_t5.total_events == 2

    # At t=7s, e1 (at 1s) is > 5s old (7 - 1 = 6s > 5s), so it should expire
    stats_t7 = window.get_aggregate_stats(now_monotonic_ns=7_000_000_000)
    assert stats_t7.total_events == 1
    assert stats_t7.created_count == 0
    assert stats_t7.modified_count == 1
    assert stats_t7.unique_relative_paths == ["b.txt"]


def test_root_sliding_window_max_capacity_bounded():
    # Capacity = 10
    window = RootSlidingWindow(
        root_id="root-1", window_duration_seconds=60.0, max_events=10
    )

    for i in range(15):
        e = _make_event(
            file_path=f"file_{i}.txt",
            monotonic_ns=1_000_000_000 + i * 100_000,
            event_id=f"e_{i}",
        )
        window.add_event(e)

    assert len(window.get_events()) == 10
    assert window.capacity_dropped_events == 5
    stats = window.get_aggregate_stats()
    assert stats.total_events == 10
    # Earliest 5 evicted
    assert "file_0.txt" not in stats.unique_relative_paths
    assert "file_14.txt" in stats.unique_relative_paths


def test_root_sliding_window_mismatched_root_rejected():
    window = RootSlidingWindow(root_id="root-1")
    event = _make_event(root_id="root-2")
    with pytest.raises(ValueError, match="does not match"):
        window.add_event(event)


def test_sliding_window_correlator_multi_root_isolation():
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_events_per_root=100
    )

    # Add events to root-A and root-B
    ea = _make_event(root_id="root-A", file_path="docA.txt", event_id="ea1")
    eb = _make_event(root_id="root-B", file_path="docB.txt", event_id="eb1")

    correlator.add_event(ea)
    correlator.add_event(eb)

    assert correlator.active_root_count == 2

    ctx_a = correlator.get_context("root-A")
    ctx_b = correlator.get_context("root-B")

    assert ctx_a is not None
    assert ctx_b is not None
    assert len(ctx_a.events) == 1
    assert ctx_a.events[0].file_path == "docA.txt"
    assert len(ctx_b.events) == 1
    assert ctx_b.events[0].file_path == "docB.txt"


def test_sliding_window_correlator_degradation_propagation():
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_events_per_root=10
    )

    # Force capacity drop
    for i in range(12):
        correlator.add_event(_make_event(root_id="root-1", file_path=f"f_{i}.txt"))

    ctx = correlator.get_context(
        "root-1",
        is_telemetry_degraded=False,
    )
    assert ctx is not None
    assert ctx.is_telemetry_degraded is True
    assert "sliding_window_capacity_dropped:2" in ctx.degradation_reason


def test_sliding_window_correlator_remove_and_prune_stale_roots():
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_active_roots=2
    )

    correlator.add_event(
        _make_event(root_id="r1", monotonic_ns=1_000_000_000, event_id="e1")
    )
    correlator.add_event(
        _make_event(root_id="r2", monotonic_ns=2_000_000_000, event_id="e2")
    )
    assert correlator.active_root_count == 2

    # Adding r3 when max_active_roots is 2 evicts the oldest idle root (r1)
    correlator.add_event(
        _make_event(root_id="r3", monotonic_ns=3_000_000_000, event_id="e3")
    )
    assert correlator.active_root_count == 2
    assert correlator.get_context("r1") is None
    assert correlator.get_context("r2") is not None
    assert correlator.get_context("r3") is not None

    # Explicit removal
    removed = correlator.remove_root("r2")
    assert removed is True
    assert correlator.active_root_count == 1

    # Prune stale roots
    pruned = correlator.prune_stale_roots(
        max_idle_seconds=10.0, now_monotonic_ns=20_000_000_000
    )
    assert pruned == 1
    assert correlator.active_root_count == 0


def test_sliding_window_correlator_empty_and_clear():
    correlator = SlidingWindowCorrelator()
    assert correlator.get_context("non-existent") is None

    correlator.add_event(_make_event(root_id="r1", event_id="e1"))
    assert correlator.active_root_count == 1
    correlator.clear()
    assert correlator.active_root_count == 0
    assert correlator.get_context("r1") is None


def test_sliding_window_ordering_metadata_support():
    window = RootSlidingWindow(root_id="r1")
    now_utc = datetime.now(UTC)
    ordering = EventOrderingMetadata(
        root_id="r1",
        observed_at_utc=now_utc,
        observed_monotonic_ns=1000,
        processed_at_utc=now_utc,
        processed_monotonic_ns=2000,
        latency_ns=1000,
        latency_ms=0.001,
        is_out_of_order=True,
    )
    event = _make_event(root_id="r1", monotonic_ns=1000)
    window.add_event(event, ordering=ordering)

    events = window.get_events()
    assert len(events) == 1
