"""Unit tests for Step 5.6: Low-and-Slow Activity Detection Module (T1486)."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, WindowAggregateStats
from kuyebiko.detection.signals.low_and_slow import LowAndSlowSignalEvaluator
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_event(
    file_path: str,
    monotonic_ns: int,
    event_type: EventType = EventType.MODIFIED,
    root_id: str = "root-1",
) -> FileEvent:
    return FileEvent(
        event_id=str(uuid4()),
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        monotonic_ns=monotonic_ns,
        source=EventSource.WINDOWS_WATCHER,
    )


def _make_context(
    events: list[FileEvent],
    window_duration_seconds: float = 60.0,
    evaluated_monotonic_ns: int | None = None,
) -> DetectionContext:
    now = datetime.now(UTC)
    eval_mono = (
        evaluated_monotonic_ns
        if evaluated_monotonic_ns is not None
        else (max((e.monotonic_ns for e in events), default=time.monotonic_ns()))
    )

    stats = WindowAggregateStats(
        total_events=len(events),
        created_count=0,
        modified_count=sum(1 for e in events if e.event_type == EventType.MODIFIED),
        deleted_count=sum(1 for e in events if e.event_type == EventType.DELETED),
        renamed_count=0,
        directory_operations_count=0,
        unique_extensions=[".doc"],
        unique_directories=list({e.file_path.split("/")[0] for e in events}),
        unique_relative_paths=[e.file_path for e in events],
        rename_pairs_count=0,
        events_per_second=float(len(events)) / max(0.1, window_duration_seconds),
        window_duration_seconds=window_duration_seconds,
    )

    return DetectionContext(
        root_id="root-1",
        events=events,
        stats=stats,
        evaluated_monotonic_ns=eval_mono,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=window_duration_seconds,
    )


def test_low_and_slow_metadata():
    """Verify evaluator metadata declares T1486 and FILE_TRANSFORMATION."""
    evaluator = LowAndSlowSignalEvaluator()
    assert evaluator.signal_id == "FS_LOW_AND_SLOW_ACTIVITY"
    assert evaluator.family == SignalFamily.FILE_TRANSFORMATION
    assert evaluator.metadata.mitre_technique == "T1486"
    assert evaluator.min_events == 20
    assert evaluator.min_directories == 3
    assert evaluator.min_time_span_seconds == 15.0


def test_distributed_low_and_slow_triggers():
    """25 events spread over 25 seconds across 4 directories triggers low-and-slow."""
    evaluator = LowAndSlowSignalEvaluator(
        min_events=20,
        min_directories=3,
        min_time_span_seconds=15.0,
        max_event_rate=6.0,
    )
    base_ns = 1_000_000_000
    dirs = ["users", "accounting", "projects", "contracts"]
    events = []
    # 1 event per second for 25 seconds
    for i in range(25):
        target_dir = dirs[i % len(dirs)]
        events.append(
            _make_event(
                f"{target_dir}/record_{i}.pdf",
                monotonic_ns=base_ns + i * 1_000_000_000,
            )
        )

    ctx = _make_context(
        events,
        window_duration_seconds=60.0,
        evaluated_monotonic_ns=base_ns + 30 * 1_000_000_000,
    )
    res = evaluator.evaluate(ctx)

    assert res.triggered is True
    assert res.severity_score >= 0.65
    assert len(res.evidence_event_ids) == 25
    assert "Distributed low-and-slow transformation detected (T1486)" in res.explanation
    assert res.metadata["transformation_count"] == 25
    assert res.metadata["unique_directories_count"] == 4
    assert res.metadata["time_span_seconds"] >= 24.0
    assert res.metadata["event_rate"] <= 2.0


def test_high_frequency_burst_does_not_trigger_low_and_slow():
    """High-frequency bursts (> 6.0 ops/sec) are excluded and left to burst write."""
    evaluator = LowAndSlowSignalEvaluator(
        min_events=20,
        min_directories=3,
        min_time_span_seconds=1.0,
        max_event_rate=6.0,
    )
    base_ns = 1_000_000_000
    # 25 events in 2 seconds = 12.5 ops/sec
    events = [
        _make_event(
            f"dir_{i % 3}/f_{i}.doc",
            monotonic_ns=base_ns + i * 80_000_000,
        )
        for i in range(25)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=2.0,
        evaluated_monotonic_ns=base_ns + 2 * 1_000_000_000,
    )
    res = evaluator.evaluate(ctx)

    assert res.triggered is False
    assert "exceeds low-and-slow envelope" in res.explanation


def test_short_time_span_does_not_trigger():
    """Events compressed in < 15s lack temporal distribution for low-and-slow."""
    evaluator = LowAndSlowSignalEvaluator(
        min_events=20,
        min_directories=3,
        min_time_span_seconds=15.0,
    )
    base_ns = 1_000_000_000
    # 20 events over 5 seconds
    events = [
        _make_event(
            f"dir_{i % 3}/f_{i}.doc",
            monotonic_ns=base_ns + i * 250_000_000,
        )
        for i in range(20)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=60.0,
        evaluated_monotonic_ns=base_ns + 10 * 1_000_000_000,
    )
    res = evaluator.evaluate(ctx)

    assert res.triggered is False
    assert "insufficient temporal persistence" in res.explanation


def test_confined_to_scratch_discounted():
    """Activity confined to build/temp scratch folders discounted as benign."""
    evaluator = LowAndSlowSignalEvaluator(
        min_events=20,
        min_directories=3,
        min_time_span_seconds=15.0,
    )
    base_ns = 1_000_000_000
    events = [
        _make_event(
            f"node_modules/pkg_{i % 3}/item_{i}.js",
            monotonic_ns=base_ns + i * 1_000_000_000,
        )
        for i in range(20)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=60.0,
        evaluated_monotonic_ns=base_ns + 25 * 1_000_000_000,
    )
    res = evaluator.evaluate(ctx)

    assert res.triggered is False
    assert res.metadata["is_confined_to_scratch"] is True
    assert "recognized as benign workload" in res.explanation
