"""Unit tests for rename correlation provenance and detection accuracy (Step 4.6)."""

import time
from datetime import UTC, datetime

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.signals.rename_ratio import RenameRatioSignalEvaluator
from kuyebiko.detection.window import RootSlidingWindow
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_event(
    root_id: str = "root-1",
    file_path: str = "file.txt",
    event_type: EventType = EventType.MODIFIED,
    old_path: str | None = None,
    new_path: str | None = None,
    is_directory: bool = False,
    correlation_provenance: str | None = None,
    monotonic_ns: int | None = None,
    event_id: str | None = None,
) -> FileEvent:
    kwargs = {
        "event_id": event_id or f"evt_{file_path}",
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
        kwargs["old_path"] = old_path or "old.txt"
        kwargs["new_path"] = new_path or file_path
        kwargs["correlation_provenance"] = correlation_provenance
    return FileEvent(**kwargs)


def _make_context(
    events: list[FileEvent],
    root_id: str = "root-1",
    window_duration_seconds: float = 10.0,
) -> DetectionContext:
    window = RootSlidingWindow(
        root_id=root_id, window_duration_seconds=window_duration_seconds
    )
    for e in events:
        window.add_event(e)
    stats = window.get_aggregate_stats()
    now = datetime.now(UTC)
    return DetectionContext(
        root_id=root_id,
        events=events,
        stats=stats,
        evaluated_monotonic_ns=time.monotonic_ns(),
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=window_duration_seconds,
    )


def test_correlated_rename_provenance_via_normalizer():
    """Verify Phase 3 RenameCorrelator assigns provenance via EventNormalizer."""
    correlator = RenameCorrelator(correlation_window_ns=1_000_000_000)
    normalizer = EventNormalizer(rename_correlator=correlator)
    t0 = 1_000_000_000

    n_old = RawFileNotification(
        root_id="root-1",
        relative_path="docs/draft.docx",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        observed_at=datetime.now(UTC),
        monotonic_ns=t0,
    )
    n_new = RawFileNotification(
        root_id="root-1",
        relative_path="docs/draft.docx.locked",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        observed_at=datetime.now(UTC),
        monotonic_ns=t0 + 10_000_000,
    )

    ev_old = normalizer.normalize_notification(n_old)
    assert ev_old is None  # Pending pairing

    ev_rename = normalizer.normalize_notification(n_new)
    assert ev_rename is not None
    assert ev_rename.event_type == EventType.RENAMED
    assert ev_rename.old_path == "docs/draft.docx"
    assert ev_rename.new_path == "docs/draft.docx.locked"
    assert ev_rename.correlation_provenance is not None
    assert "rename_correlator:docs/draft.docx->docs/draft.docx.locked" in (
        ev_rename.correlation_provenance
    )


def test_unpaired_old_rename_cannot_inflate_rename_ratio():
    """An unpaired RENAMED_OLD_NAME is buffered, never produces an event."""
    correlator = RenameCorrelator()
    normalizer = EventNormalizer(rename_correlator=correlator)

    n_old = RawFileNotification(
        root_id="root-1",
        relative_path="file.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        observed_at=datetime.now(UTC),
        monotonic_ns=1000,
    )
    event = normalizer.normalize_notification(n_old)
    assert event is None
    assert correlator.pending_count("root-1") == 1


def test_unpaired_new_rename_without_old_name_dropped():
    """A RENAMED_NEW_NAME without OLD_NAME is dropped and cannot inflate ratio."""
    correlator = RenameCorrelator()
    normalizer = EventNormalizer(rename_correlator=correlator)

    n_new = RawFileNotification(
        root_id="root-1",
        relative_path="orphan.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        observed_at=datetime.now(UTC),
        monotonic_ns=1000,
    )
    event = normalizer.normalize_notification(n_new)
    assert event is None


def test_rename_events_lacking_provenance_rejected_by_evaluator():
    """Rename events lacking correlation_provenance are ignored by evaluator."""
    evaluator = RenameRatioSignalEvaluator(threshold=0.50, min_renames=5, min_events=10)
    base_ns = 1_000_000

    # 10 rename events, but correlation_provenance is None
    events = [
        _make_event(
            event_id=f"r_{i}",
            file_path=f"file_{i}.locked",
            event_type=EventType.RENAMED,
            old_path=f"file_{i}.txt",
            new_path=f"file_{i}.locked",
            correlation_provenance=None,  # No provenance!
            monotonic_ns=base_ns + i * 1000,
        )
        for i in range(10)
    ]

    ctx = _make_context(events)
    # stats.rename_pairs_count is 0 because window ignores non-provenanced renames
    assert ctx.stats.rename_pairs_count == 0

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.observed_metric == 0.0
    assert len(res.evidence_event_ids) == 0


def test_directory_renames_excluded_from_rename_pairs_count_and_ratio():
    """Directory renames (is_directory=True) must not count toward rename ratio."""
    evaluator = RenameRatioSignalEvaluator(threshold=0.50, min_renames=5, min_events=10)
    base_ns = 1_000_000

    events = []
    # 7 directory renames with correlation provenance
    for i in range(7):
        events.append(
            _make_event(
                event_id=f"dir_ren_{i}",
                file_path=f"newdir_{i}",
                event_type=EventType.RENAMED,
                old_path=f"olddir_{i}",
                new_path=f"newdir_{i}",
                is_directory=True,
                correlation_provenance=f"rename_correlator:olddir_{i}->newdir_{i}",
                monotonic_ns=base_ns + i * 1000,
            )
        )
    # 3 normal file modifications
    for i in range(3):
        events.append(
            _make_event(
                event_id=f"mod_{i}",
                file_path=f"doc_{i}.txt",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + (7 + i) * 1000,
            )
        )

    ctx = _make_context(events)
    # stats.rename_pairs_count excludes directory renames
    assert ctx.stats.rename_pairs_count == 0

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.observed_metric == 0.0


def test_stats_discrepancy_detection_and_safeguard():
    """If events differ from aggregate stats, evaluator records metadata discrepancy."""
    evaluator = RenameRatioSignalEvaluator(threshold=0.60, min_renames=5, min_events=10)
    base_ns = 1_000_000

    # Build context with 6 provenanced renames + 4 writes
    events = [
        _make_event(
            event_id=f"r_{i}",
            file_path=f"file_{i}.locked",
            event_type=EventType.RENAMED,
            old_path=f"file_{i}.txt",
            new_path=f"file_{i}.locked",
            correlation_provenance=f"rename_correlator:file_{i}.txt->file_{i}.locked",
            monotonic_ns=base_ns + i * 1000,
        )
        for i in range(6)
    ]
    for i in range(4):
        events.append(
            _make_event(
                event_id=f"m_{i}",
                file_path=f"data_{i}.bin",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + (6 + i) * 1000,
            )
        )

    ctx = _make_context(events)
    assert ctx.stats.rename_pairs_count == 6

    # Simulate discrepancy by artificially mutating stats (e.g. out-of-sync stat)
    tampered_stats = ctx.stats.model_copy(update={"rename_pairs_count": 9})
    tampered_ctx = DetectionContext(
        root_id="root-1",
        events=events,
        stats=tampered_stats,
        evaluated_monotonic_ns=base_ns,
        window_start_utc=ctx.window_start_utc,
        window_end_utc=ctx.window_end_utc,
        window_duration_seconds=ctx.window_duration_seconds,
    )

    res = evaluator.evaluate(tampered_ctx)
    assert res.metadata["stats_discrepancy"] is True
    assert res.metadata["verified_rename_pairs_count"] == 6
    assert res.metadata["stats_rename_pairs_count"] == 9
    assert res.triggered is True
    assert len(res.evidence_event_ids) == 6


def test_repeated_and_duplicate_rename_pair_consistency():
    """Duplicate/repeated rename pairs are consistently tracked in the window."""
    window = RootSlidingWindow(root_id="root-1", window_duration_seconds=10.0)
    base_ns = 5_000_000_000

    e1 = _make_event(
        event_id="r1",
        file_path="target.txt",
        event_type=EventType.RENAMED,
        old_path="src.txt",
        new_path="target.txt",
        correlation_provenance="rename_correlator:src.txt->target.txt",
        monotonic_ns=base_ns,
    )
    # Same event object re-added (or identical paths)
    e2 = _make_event(
        event_id="r2",
        file_path="target2.txt",
        event_type=EventType.RENAMED,
        old_path="src2.txt",
        new_path="target2.txt",
        correlation_provenance="rename_correlator:src2.txt->target2.txt",
        monotonic_ns=base_ns + 1000,
    )

    window.add_event(e1)
    window.add_event(e2)

    stats = window.get_aggregate_stats()
    assert stats.rename_pairs_count == 2
    assert stats.renamed_count == 2

    # Prune and verify decrement consistency
    window.prune_expired(base_ns + 20_000_000_000)
    stats_pruned = window.get_aggregate_stats()
    assert stats_pruned.rename_pairs_count == 0
    assert stats_pruned.renamed_count == 0
