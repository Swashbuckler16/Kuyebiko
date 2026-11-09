"""Unit tests for Step 5.6: In-Place File Transformation Detection Module (T1486)."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, WindowAggregateStats
from kuyebiko.detection.signals.in_place_transformation import (
    InPlaceTransformationSignalEvaluator,
)
from kuyebiko.models.events import (
    CorrelationProvenanceType,
    EventSource,
    EventType,
    FileEvent,
    sign_provenance_payload,
)


def _make_event(
    file_path: str,
    event_type: EventType = EventType.MODIFIED,
    is_directory: bool = False,
    root_id: str = "root-1",
    monotonic_ns: int | None = None,
    old_path: str | None = None,
    new_path: str | None = None,
) -> FileEvent:
    provenance = None
    if event_type == EventType.RENAMED:
        o = old_path or f"{file_path}.old"
        n = new_path or file_path
        old_path = o
        new_path = n
        provenance = sign_provenance_payload(
            CorrelationProvenanceType.PHASE3_CORRELATOR, o, n
        )

    return FileEvent(
        event_id=str(uuid4()),
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        is_directory=is_directory,
        old_path=old_path,
        new_path=new_path,
        correlation_provenance=provenance,
        monotonic_ns=monotonic_ns if monotonic_ns is not None else time.monotonic_ns(),
        source=EventSource.WINDOWS_WATCHER,
    )


def _make_context(events: list[FileEvent]) -> DetectionContext:
    now = datetime.now(UTC)
    mod_count = sum(
        1 for e in events if e.event_type == EventType.MODIFIED and not e.is_directory
    )
    renamed_count = sum(1 for e in events if e.event_type == EventType.RENAMED)
    deleted_count = sum(1 for e in events if e.event_type == EventType.DELETED)

    stats = WindowAggregateStats(
        total_events=len(events),
        created_count=0,
        modified_count=mod_count,
        deleted_count=deleted_count,
        renamed_count=renamed_count,
        directory_operations_count=0,
        unique_extensions=[".docx", ".pdf"],
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


def test_in_place_transformation_metadata():
    """Verify evaluator metadata declares T1486 and FILE_TRANSFORMATION."""
    evaluator = InPlaceTransformationSignalEvaluator()
    assert evaluator.signal_id == "FS_IN_PLACE_TRANSFORMATION"
    assert evaluator.family == SignalFamily.FILE_TRANSFORMATION
    assert evaluator.metadata.mitre_technique == "T1486"
    assert evaluator.min_unique_files == 15
    assert evaluator.min_directories == 3


def test_systematic_in_place_transformation_triggers():
    """Modifying 20 distinct files across 4 directories triggers T1486."""
    evaluator = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )
    dirs = ["documents", "finance", "legal", "hr"]
    events = [_make_event(f"{dirs[i % len(dirs)]}/file_{i}.docx") for i in range(20)]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 1.0  # 100% modifications
    assert res.severity_score >= 0.70
    assert len(res.evidence_event_ids) == 20
    assert "Suspicious in-place file transformation detected (T1486)" in res.explanation
    assert res.metadata["unique_files_modified"] == 20
    assert res.metadata["unique_directories_count"] == 4
    assert res.metadata["is_confined_to_dev"] is False


def test_single_file_repeated_saves_does_not_trigger():
    """Repeatedly modifying the same document (e.g. autosave) does not trigger."""
    evaluator = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )
    # 30 modifications to the exact same file
    events = [_make_event("projects/paper.docx") for _ in range(30)]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.severity_score == 0.0
    assert res.metadata["unique_files_modified"] == 1


def test_single_directory_modifications_do_not_trigger():
    """Modifications confined within only 1 directory branch do not trigger."""
    evaluator = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )
    events = [_make_event(f"photos/album/img_{i}.png") for i in range(20)]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.metadata["unique_directories_count"] == 1
    assert "localized activity within acceptable" in res.explanation


def test_high_rename_ratio_inhibits_in_place_signal():
    """If renames dominate, in-place signal yields to rename-specific signals."""
    evaluator = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )
    dirs = ["docs", "fin", "hr"]
    # 15 modifications
    mod_events = [_make_event(f"{dirs[i % len(dirs)]}/f_{i}.doc") for i in range(15)]
    # 15 renames
    rename_events = [
        _make_event(f"{dirs[i % len(dirs)]}/f_{i}.locked", event_type=EventType.RENAMED)
        for i in range(15)
    ]
    ctx = _make_context(mod_events + rename_events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert "Elevated rename activity present" in res.explanation


def test_confined_developer_scratch_discounted():
    """Modifications strictly in build/cache folders discounted unless massive burst."""
    evaluator = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )
    events = [_make_event(f"node_modules/pkg_{i % 3}/module_{i}.js") for i in range(20)]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.metadata["is_confined_to_dev"] is True
    assert "recognized as benign workload" in res.explanation


def test_massive_dev_burst_triggers():
    """Massive modification burst (50 files across 5 dev folders) triggers."""
    evaluator = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )
    events = [_make_event(f"build/target_{i % 5}/output_{i}.bin") for i in range(50)]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.metadata["is_massive_dev_burst"] is True
