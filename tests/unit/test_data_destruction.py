"""Unit tests for Step 5.3: Advanced Data Destruction Detection Module (T1485)."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, WindowAggregateStats
from kuyebiko.detection.signals.data_destruction import DataDestructionSignalEvaluator
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_event(
    file_path: str,
    event_type: EventType = EventType.DELETED,
    is_directory: bool = False,
    root_id: str = "root-1",
) -> FileEvent:
    return FileEvent(
        event_id=str(uuid4()),
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        is_directory=is_directory,
        monotonic_ns=time.monotonic_ns(),
        source=EventSource.WINDOWS_WATCHER,
    )


def _make_context(events: list[FileEvent]) -> DetectionContext:
    now = datetime.now(UTC)
    stats = WindowAggregateStats(
        total_events=len(events),
        created_count=0,
        modified_count=0,
        deleted_count=sum(1 for e in events if e.event_type == EventType.DELETED),
        renamed_count=0,
        directory_operations_count=0,
        unique_extensions=[".doc"],
        unique_directories=list({e.file_path.split("/")[0] for e in events}),
        unique_relative_paths=[e.file_path for e in events],
        rename_pairs_count=0,
        events_per_second=float(len(events)),
        window_duration_seconds=10.0,
    )

    return DetectionContext(
        root_id="root-1",
        events=events,
        stats=stats,
        evaluated_monotonic_ns=time.monotonic_ns(),
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
    )


def test_data_destruction_metadata_properties():
    """Verify evaluator metadata declares T1485 and DATA_DESTRUCTION."""
    evaluator = DataDestructionSignalEvaluator(min_deletions=15, min_directories=3)
    assert evaluator.signal_id == "FS_DATA_DESTRUCTION"
    assert evaluator.family == SignalFamily.DATA_DESTRUCTION
    assert evaluator.metadata.mitre_technique == "T1485"
    assert evaluator.min_deletions == 15
    assert evaluator.min_directories == 3


def test_multi_directory_mass_deletion_triggers():
    """Widespread deletion across 4 distinct directories triggers T1485."""
    evaluator = DataDestructionSignalEvaluator(
        min_deletions=15, min_directories=3, threshold=0.50
    )
    events = []
    # 20 deletions distributed across 4 directories
    dirs = ["documents", "finance", "legal", "archive"]
    for i in range(20):
        target_dir = dirs[i % len(dirs)]
        events.append(_make_event(f"{target_dir}/doc_{i}.pdf"))

    ctx = _make_context(events)
    res = evaluator.evaluate(ctx)

    assert res.triggered is True
    assert res.observed_metric == 1.0  # 100% deletions
    assert res.severity_score >= 0.70
    assert len(res.evidence_event_ids) == 20
    assert "Mass data destruction detected (T1485)" in res.explanation
    assert res.metadata["unique_directories_count"] == 4
    assert res.metadata["is_confined_to_temp"] is False


def test_benign_temp_cleanup_does_not_trigger():
    """High volume deletion confined to temporary cache does not trigger T1485."""
    evaluator = DataDestructionSignalEvaluator(
        min_deletions=15, min_directories=3, threshold=0.50
    )
    events = []
    # 25 deletions across temp subfolders
    for i in range(25):
        events.append(_make_event(f"temp/cache_{i % 3}/item_{i}.tmp"))

    ctx = _make_context(events)
    res = evaluator.evaluate(ctx)

    assert res.triggered is False
    assert res.severity_score == 0.0
    assert len(res.evidence_event_ids) == 0
    assert "confined to benign temporary/cache directories" in res.explanation
    assert res.metadata["is_confined_to_temp"] is True


def test_single_folder_deletion_does_not_trigger():
    """Bulk deletion within only a single folder does not trigger T1485."""
    evaluator = DataDestructionSignalEvaluator(
        min_deletions=15, min_directories=3, threshold=0.50
    )
    events = [_make_event(f"my_project/src/file_{i}.ts") for i in range(20)]

    ctx = _make_context(events)
    res = evaluator.evaluate(ctx)

    assert res.triggered is False
    assert res.severity_score == 0.0
    assert "within only 1 directory branch" in res.explanation
    assert res.metadata["unique_directories_count"] == 1


def test_insufficient_deletion_volume_does_not_trigger():
    """Fewer deletions than min_deletions does not trigger."""
    evaluator = DataDestructionSignalEvaluator(min_deletions=15, min_directories=3)
    events = [
        _make_event("dir1/file1.txt"),
        _make_event("dir2/file2.txt"),
        _make_event("dir3/file3.txt"),
    ]

    ctx = _make_context(events)
    res = evaluator.evaluate(ctx)

    assert res.triggered is False
    assert "Insufficient events (3)" in res.explanation


def test_massive_cache_burst_triggers_despite_temp_naming():
    """Massive deletion burst (50 files across 5 temp subdirs) triggers T1485."""
    evaluator = DataDestructionSignalEvaluator(
        min_deletions=15, min_directories=3, threshold=0.50
    )
    events = []
    # 50 deletions across 5 temp subdirectories
    for i in range(50):
        subdir = f"temp/cache_shard_{i % 5}"
        events.append(_make_event(f"{subdir}/file_{i}.tmp"))

    ctx = _make_context(events)
    res = evaluator.evaluate(ctx)

    assert res.triggered is True
    assert res.metadata["is_confined_to_temp"] is True
    assert res.metadata["is_massive_burst"] is True
    assert res.metadata["unique_directories_count"] == 5
    assert res.metadata["deleted_count"] == 50
    assert (
        "Massive data destruction burst detected in cache/temp structures"
        in res.explanation
    )


def test_mixed_workload_triggers_without_veto_from_temp():
    """Mixed workload with user document deletions is not vetoed by temp deletions."""
    evaluator = DataDestructionSignalEvaluator(
        min_deletions=15, min_directories=3, threshold=0.50
    )
    events = []
    # 20 deletions in user documents across 4 folders
    for i in range(20):
        events.append(_make_event(f"users/docs_{i % 4}/important_{i}.pdf"))
    # 10 deletions in temp
    for i in range(10):
        events.append(_make_event(f"temp/scratch/item_{i}.tmp"))

    ctx = _make_context(events)
    res = evaluator.evaluate(ctx)

    assert res.triggered is True
    assert res.metadata["is_confined_to_temp"] is False
    assert res.metadata["non_benign_deleted_count"] == 20
    assert res.metadata["non_benign_directories_count"] == 4
    assert res.observed_metric == 1.0  # all events are deletions
    assert "Mass data destruction detected (T1485)" in res.explanation
