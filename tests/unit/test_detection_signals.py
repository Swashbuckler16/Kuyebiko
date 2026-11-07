"""Unit tests for the five foundational behaviour signal evaluators."""

from datetime import UTC, datetime

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import (
    SignalFamily,
)
from kuyebiko.detection.signals.burst_write import BurstWriteSignalEvaluator
from kuyebiko.detection.signals.delete_ratio import DeleteRatioSignalEvaluator
from kuyebiko.detection.signals.directory_traversal import (
    DirectoryTraversalSignalEvaluator,
)
from kuyebiko.detection.signals.extension_convergence import (
    ExtensionConvergenceSignalEvaluator,
)
from kuyebiko.detection.signals.rename_ratio import RenameRatioSignalEvaluator
from kuyebiko.detection.window import RootSlidingWindow
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_context(
    events: list[FileEvent],
    window_duration_seconds: float = 10.0,
) -> DetectionContext:
    window = RootSlidingWindow(
        root_id="root-1", window_duration_seconds=window_duration_seconds
    )
    for e in events:
        window.add_event(e)
    stats = window.get_aggregate_stats()
    now = datetime.now(UTC)
    return DetectionContext(
        root_id="root-1",
        events=events,
        stats=stats,
        evaluated_monotonic_ns=1_000_000_000,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=window_duration_seconds,
    )


# ---------------------------------------------------------------------------
# Signal 1: FS_BURST_WRITE
# ---------------------------------------------------------------------------


def test_burst_write_insufficient_events():
    evaluator = BurstWriteSignalEvaluator(threshold=10.0, min_events=15)
    events = [
        FileEvent(
            event_id=f"e_{i}",
            root_id="root-1",
            file_path=f"f_{i}.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i in range(5)
    ]
    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is False
    assert "Insufficient events" in res.explanation


def test_burst_write_single_file_repeated_no_trigger():
    evaluator = BurstWriteSignalEvaluator(threshold=10.0, min_events=10)
    # 20 writes to the exact same file
    events = [
        FileEvent(
            event_id=f"e_{i}",
            root_id="root-1",
            file_path="huge_database.db",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000 + i * 100,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i in range(20)
    ]
    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is False
    assert res.observed_metric == 1.0  # only 1 unique file
    assert (
        "below threshold" in res.explanation
        or "within normal limits" in res.explanation
    )


def test_burst_write_positive_trigger():
    evaluator = BurstWriteSignalEvaluator(
        threshold=10.0, rate_threshold=2.0, min_events=10
    )
    # 15 writes across 15 distinct files within 5 seconds -> 3 ops/sec
    events = [
        FileEvent(
            event_id=f"e_{i}",
            root_id="root-1",
            file_path=f"important_doc_{i}.docx",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000 + i * 100,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i in range(15)
    ]
    res = evaluator.evaluate(_make_context(events, window_duration_seconds=5.0))
    assert res.triggered is True
    assert res.observed_metric == 15.0
    assert res.family == SignalFamily.FILESYSTEM_ACTIVITY
    assert len(res.evidence_event_ids) == 15
    assert res.severity_score >= 0.6


# ---------------------------------------------------------------------------
# Signal 2: FS_RENAME_RATIO
# ---------------------------------------------------------------------------


def test_rename_ratio_insufficient_or_normal():
    evaluator = RenameRatioSignalEvaluator(threshold=0.60, min_renames=5, min_events=10)
    # 2 renames out of 10 events (20% ratio)
    events = []
    for i in range(8):
        events.append(
            FileEvent(
                event_id=f"w_{i}",
                root_id="root-1",
                file_path=f"f_{i}.txt",
                event_type=EventType.MODIFIED,
                monotonic_ns=1_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    for i in range(2):
        events.append(
            FileEvent(
                event_id=f"r_{i}",
                root_id="root-1",
                file_path=f"r_{i}.bak",
                event_type=EventType.RENAMED,
                old_path=f"r_{i}.txt",
                new_path=f"r_{i}.bak",
                monotonic_ns=1_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is False
    assert res.observed_metric == 0.20


def test_rename_ratio_positive_trigger():
    evaluator = RenameRatioSignalEvaluator(threshold=0.60, min_renames=5, min_events=10)
    # 8 renames out of 10 events (80% ratio)
    events = []
    for i in range(2):
        events.append(
            FileEvent(
                event_id=f"w_{i}",
                root_id="root-1",
                file_path=f"f_{i}.txt",
                event_type=EventType.MODIFIED,
                monotonic_ns=1_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    for i in range(8):
        events.append(
            FileEvent(
                event_id=f"r_{i}",
                root_id="root-1",
                file_path=f"file_{i}.encrypted",
                event_type=EventType.RENAMED,
                old_path=f"file_{i}.txt",
                new_path=f"file_{i}.encrypted",
                monotonic_ns=1_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is True
    assert res.observed_metric == 0.80
    assert len(res.evidence_event_ids) == 8


# ---------------------------------------------------------------------------
# Signal 3: FS_DELETE_RATIO
# ---------------------------------------------------------------------------


def test_delete_ratio_evaluation():
    evaluator = DeleteRatioSignalEvaluator(
        threshold=0.50, min_deletions=4, min_events=8
    )
    # 6 deletions, 2 modifications out of 8 events (75% delete ratio)
    events = []
    for i in range(2):
        events.append(
            FileEvent(
                event_id=f"m_{i}",
                root_id="root-1",
                file_path=f"doc_{i}.txt",
                event_type=EventType.MODIFIED,
                monotonic_ns=1_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    for i in range(6):
        events.append(
            FileEvent(
                event_id=f"d_{i}",
                root_id="root-1",
                file_path=f"deleted_{i}.pdf",
                event_type=EventType.DELETED,
                monotonic_ns=1_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is True
    assert res.observed_metric == 0.75
    assert len(res.evidence_event_ids) == 6


# ---------------------------------------------------------------------------
# Signal 4: FS_DIRECTORY_TRAVERSAL
# ---------------------------------------------------------------------------


def test_directory_traversal_diversity():
    evaluator = DirectoryTraversalSignalEvaluator(threshold=4.0, min_events=5)
    # Events in 5 distinct directories
    dirs = ["finance", "hr", "engineering", "legal", "personal"]
    events = [
        FileEvent(
            event_id=f"e_{i}",
            root_id="root-1",
            file_path=f"{d}/doc.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i, d in enumerate(dirs)
    ]

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is True
    assert res.observed_metric == 5.0
    assert res.family == SignalFamily.DIRECTORY_TRAVERSAL


# ---------------------------------------------------------------------------
# Signal 5: FS_EXTENSION_CONVERGENCE
# ---------------------------------------------------------------------------


def test_extension_convergence_trigger():
    evaluator = ExtensionConvergenceSignalEvaluator(
        threshold=3.0, min_renames=4, min_convergence_ratio=0.75, min_events=4
    )
    # 4 distinct original extensions (.docx, .pdf, .xlsx, .jpg) all renamed to .locked
    orig_exts = ["docx", "pdf", "xlsx", "jpg"]
    events = [
        FileEvent(
            event_id=f"ren_{i}",
            root_id="root-1",
            file_path=f"doc_{i}.locked",
            event_type=EventType.RENAMED,
            old_path=f"doc_{i}.{ext}",
            new_path=f"doc_{i}.locked",
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i, ext in enumerate(orig_exts)
    ]

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is True
    assert res.observed_metric == 4.0
    assert res.metadata["top_target_extension"] == ".locked"
    assert res.metadata["convergence_ratio"] == 1.0
    assert len(res.evidence_event_ids) == 4


def test_extension_convergence_negative_diverse_targets():
    evaluator = ExtensionConvergenceSignalEvaluator(
        threshold=3.0, min_renames=4, min_convergence_ratio=0.75, min_events=4
    )
    # Renames where every target extension is different (no convergence)
    pairs = [
        ("a.txt", "a.bak"),
        ("b.doc", "b.old"),
        ("c.pdf", "c.tmp"),
        ("d.xls", "d.csv"),
    ]
    events = [
        FileEvent(
            event_id=f"ren_{i}",
            root_id="root-1",
            file_path=target,
            event_type=EventType.RENAMED,
            old_path=src,
            new_path=target,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i, (src, target) in enumerate(pairs)
    ]

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is False
    assert res.metadata["convergence_ratio"] == 0.25


def test_rename_ratio_rejects_identical_paths_and_directory_renames():
    evaluator = RenameRatioSignalEvaluator(threshold=0.50, min_renames=3, min_events=5)
    # 5 rename events, but all have old_path == new_path or is_directory=True
    events = [
        FileEvent(
            event_id="r1",
            root_id="root-1",
            file_path="same.txt",
            event_type=EventType.RENAMED,
            old_path="same.txt",
            new_path="same.txt",
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        ),
        FileEvent(
            event_id="r2",
            root_id="root-1",
            file_path="subfolder",
            event_type=EventType.RENAMED,
            old_path="oldfolder",
            new_path="subfolder",
            is_directory=True,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        ),
        FileEvent(
            event_id="r3",
            root_id="root-1",
            file_path="file3.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        ),
        FileEvent(
            event_id="r4",
            root_id="root-1",
            file_path="file4.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        ),
        FileEvent(
            event_id="r5",
            root_id="root-1",
            file_path="file5.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000,
            source=EventSource.WINDOWS_WATCHER,
        ),
    ]

    res = evaluator.evaluate(_make_context(events))
    assert res.triggered is False
