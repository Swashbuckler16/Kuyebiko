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
        "monotonic_ns": (
            monotonic_ns if monotonic_ns is not None else time.monotonic_ns()
        ),
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
    window = RootSlidingWindow(root_id="root-1", window_duration_seconds=5.0)

    e1 = _make_event(
        file_path="a.txt",
        event_type=EventType.CREATED,
        monotonic_ns=1_000_000_000,
        event_id="e1",
    )
    e2 = _make_event(
        file_path="b.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=4_000_000_000,
        event_id="e2",
    )

    window.add_event(e1)
    window.add_event(e2)

    stats_t5 = window.get_aggregate_stats(now_monotonic_ns=5_000_000_000)
    assert stats_t5.total_events == 2

    stats_t7 = window.get_aggregate_stats(now_monotonic_ns=7_000_000_000)
    assert stats_t7.total_events == 1
    assert stats_t7.created_count == 0
    assert stats_t7.modified_count == 1
    assert stats_t7.unique_relative_paths == ["b.txt"]


def test_out_of_order_event_inserted_chronologically_and_expires_correctly():
    """An out-of-order event expires at its exact due time."""
    # 10-second window
    window = RootSlidingWindow(root_id="root-1", window_duration_seconds=10.0)

    # Event 1 at t=5s
    e1 = _make_event(
        file_path="mid.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=5_000_000_000,
        event_id="e1",
    )
    # Event 2 at t=10s
    e2 = _make_event(
        file_path="latest.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=10_000_000_000,
        event_id="e2",
    )
    window.add_event(e1)
    window.add_event(e2)

    # Event 3 arrives out-of-order with timestamp t=3s (older than e1 and e2)
    e3 = _make_event(
        file_path="earliest.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=3_000_000_000,
        event_id="e3",
    )
    window.add_event(e3, now_monotonic_ns=10_000_000_000)

    # Window should order them chronologically: [e3 (3s), e1 (5s), e2 (10s)]
    events = window.get_events()
    assert len(events) == 3
    assert events[0].event_id == "e3"
    assert events[1].event_id == "e1"
    assert events[2].event_id == "e2"

    # At t=14s (cutoff is 14 - 10 = 4s):
    # e3 (at 3s) MUST be pruned, but e1 (5s) and e2 (10s) must remain!
    stats = window.get_aggregate_stats(now_monotonic_ns=14_000_000_000)
    assert stats.total_events == 2
    remaining_ids = [e.event_id for e in window.get_events()]
    assert "e3" not in remaining_ids
    assert "e1" in remaining_ids
    assert "e2" in remaining_ids


def test_capacity_drop_recovers_after_window_expiration():
    """Capacity degradation recovers automatically once the active window passes."""
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_events_per_root=10
    )

    base_ns = 1_000_000_000
    # Add 12 events to trigger 2 capacity drops at t=1s
    for i in range(12):
        correlator.add_event(
            _make_event(
                root_id="root-rec",
                file_path=f"file_{i}.txt",
                monotonic_ns=base_ns + i * 1_000,
            ),
            now_monotonic_ns=base_ns + i * 1_000,
        )

    # While events and drops are within active window horizon, root is degraded
    ctx_active = correlator.get_context(
        "root-rec", now_monotonic_ns=base_ns + 5_000_000_000
    )
    assert ctx_active is not None
    assert ctx_active.is_telemetry_degraded is True
    assert "sliding_window_capacity_dropped:2" in ctx_active.degradation_reason

    # 15 seconds later (window is 10s), the capacity drops and events have expired!
    ctx_recovered = correlator.get_context(
        "root-rec", now_monotonic_ns=base_ns + 15_000_000_000
    )
    assert ctx_recovered is not None
    # Telemetry degradation has recovered!
    assert ctx_recovered.is_telemetry_degraded is False
    assert ctx_recovered.degradation_reason is None


def test_active_root_eviction_propagates_telemetry_loss():
    """When an active root is evicted, telemetry loss is explicitly recorded."""
    correlator = SlidingWindowCorrelator(
        window_duration_seconds=10.0, max_active_roots=2
    )

    t1 = 1_000_000_000
    t2 = 2_000_000_000
    t3 = 3_000_000_000

    correlator.add_event(
        _make_event(root_id="r1", monotonic_ns=t1, event_id="e1"), now_monotonic_ns=t1
    )
    correlator.add_event(
        _make_event(root_id="r2", monotonic_ns=t2, event_id="e2"), now_monotonic_ns=t2
    )
    assert correlator.active_root_count == 2

    # Adding r3 forces eviction of the oldest idle root (r1)
    correlator.add_event(
        _make_event(root_id="r3", monotonic_ns=t3, event_id="e3"), now_monotonic_ns=t3
    )
    assert correlator.active_root_count == 2
    assert correlator.total_evicted_roots_count == 1

    # Now if r1 becomes active again, its context explicitly reflects the telemetry loss
    correlator.add_event(
        _make_event(root_id="r1", monotonic_ns=t3 + 1_000_000_000, event_id="e1_new"),
        now_monotonic_ns=t3 + 1_000_000_000,
    )
    ctx_r1 = correlator.get_context("r1", now_monotonic_ns=t3 + 1_000_000_000)
    assert ctx_r1 is not None
    assert ctx_r1.is_telemetry_degraded is True
    assert "root_previously_evicted_due_to_capacity_limit" in ctx_r1.degradation_reason


def test_root_sliding_window_max_capacity_bounded():
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
    assert window.cumulative_capacity_dropped_events == 5
    stats = window.get_aggregate_stats()
    assert stats.total_events == 10
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
