"""Test corpus for Step 5.6: Benign Workload Discrimination and Adversarial Detection.

Evaluates behaviour detectors against 10 realistic workload scenarios (8 benign,
2 synthetic adversarial) to verify that normal user and system patterns do not cross
ransomware detection thresholds while stealthy transformations trigger.
"""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import WindowAggregateStats
from kuyebiko.detection.signals.burst_write import BurstWriteSignalEvaluator
from kuyebiko.detection.signals.in_place_transformation import (
    InPlaceTransformationSignalEvaluator,
)
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

    mod_count = sum(1 for e in events if e.event_type == EventType.MODIFIED)
    created_count = sum(1 for e in events if e.event_type == EventType.CREATED)
    deleted_count = sum(1 for e in events if e.event_type == EventType.DELETED)
    renamed_count = sum(1 for e in events if e.event_type == EventType.RENAMED)

    stats = WindowAggregateStats(
        total_events=len(events),
        created_count=created_count,
        modified_count=mod_count,
        deleted_count=deleted_count,
        renamed_count=renamed_count,
        directory_operations_count=0,
        unique_extensions=list(
            {e.file_path.split(".")[-1] for e in events if "." in e.file_path}
        ),
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


# Scenario 1: Normal document editing (frequent saves to 1-2 files in 1 dir)
def test_workload_1_normal_document_editing():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    events = [
        _make_event("Documents/thesis.docx", monotonic_ns=base_ns + i * 2_000_000_000)
        for i in range(15)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=60.0,
        evaluated_monotonic_ns=base_ns + 35_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 2: Large software installation (mass creation of binaries)
def test_workload_2_software_installation():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    # 60 creations
    events = [
        _make_event(
            f"Program Files/Vendor/App_{i % 5}/bin_{i}.dll",
            monotonic_ns=base_ns + i * 10_000_000,
            event_type=EventType.CREATED,
        )
        for i in range(60)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 1_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 3: Git checkout and source code updates (.git / project source tree)
def test_workload_3_git_checkout_updates():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    events = [
        _make_event(
            f".git/objects/{i % 4}/blob_{i}.pack",
            monotonic_ns=base_ns + i * 100_000_000,
            event_type=EventType.MODIFIED,
        )
        for i in range(25)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 3_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 4: Development build operations (build/ and target/ scratch dirs)
def test_workload_4_dev_build_operations():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    events = [
        _make_event(
            f"target/release/incremental/{i % 3}/module_{i}.o",
            monotonic_ns=base_ns + i * 50_000_000,
            event_type=EventType.MODIFIED,
        )
        for i in range(30)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 2_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 5: Database writes (periodic WAL / DB modifications to app.db)
def test_workload_5_database_writes():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    events = [
        _make_event(
            "var/data/kuyebiko.db-wal", monotonic_ns=base_ns + i * 1_500_000_000
        )
        for i in range(20)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=60.0,
        evaluated_monotonic_ns=base_ns + 35_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 6: Backup and synchronization workloads (copying / reading files)
def test_workload_6_backup_synchronization():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    # Files created in one backup destination directory
    events = [
        _make_event(
            f"BackupDrive/Snapshot_2026/file_{i}.bak",
            monotonic_ns=base_ns + i * 100_000_000,
            event_type=EventType.CREATED,
        )
        for i in range(30)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 4_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 7: Bulk file copying (creating files in destination folder)
def test_workload_7_bulk_file_copying():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    events = [
        _make_event(
            f"Downloads/Archive/extracted_{i}.jpg",
            monotonic_ns=base_ns + i * 50_000_000,
            event_type=EventType.CREATED,
        )
        for i in range(40)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 3_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 8: Repeated file modifications (editing code.py 30 times in 10s)
def test_workload_8_repeated_file_modifications():
    eval_in_place = InPlaceTransformationSignalEvaluator()
    eval_low_slow = LowAndSlowSignalEvaluator()

    base_ns = 1_000_000_000
    events = [
        _make_event("src/kuyebiko/main.py", monotonic_ns=base_ns + i * 300_000_000)
        for i in range(30)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 10_000_000_000,
    )

    assert eval_in_place.evaluate(ctx).triggered is False
    assert eval_low_slow.evaluate(ctx).triggered is False


# Scenario 9: ADVERSARIAL — Synthetic low-frequency multi-directory transformation
def test_workload_9_adversarial_low_and_slow():
    eval_low_slow = LowAndSlowSignalEvaluator(
        min_events=20, min_directories=3, min_time_span_seconds=15.0
    )
    eval_burst = BurstWriteSignalEvaluator(min_events=20, threshold=10.0)

    base_ns = 1_000_000_000
    dirs = ["Finance", "HumanResources", "Legal", "Operations", "Executive"]
    # 25 modifications: 1 file every 1.5 seconds = ~0.67 ops/sec (evades BurstWrite!)
    events = [
        _make_event(
            f"{dirs[i % len(dirs)]}/confidential_{i}.xlsx",
            monotonic_ns=base_ns + int(i * 1.5 * 1_000_000_000),
            event_type=EventType.MODIFIED,
        )
        for i in range(25)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=60.0,
        evaluated_monotonic_ns=base_ns + 40_000_000_000,
    )

    # Burst write does NOT trigger (rate is only 0.67 ops/sec)
    assert eval_burst.evaluate(ctx).triggered is False
    # Low-and-slow DOES trigger!
    res_low_slow = eval_low_slow.evaluate(ctx)
    assert res_low_slow.triggered is True
    assert (
        "Distributed low-and-slow transformation detected" in res_low_slow.explanation
    )


# Scenario 10: ADVERSARIAL — Synthetic in-place transformation (25 files, 5 folders)
def test_workload_10_adversarial_in_place_transformation():
    eval_in_place = InPlaceTransformationSignalEvaluator(
        min_unique_files=15, min_directories=3
    )

    base_ns = 1_000_000_000
    dirs = ["Accounting", "Contracts", "Medical", "Projects", "Clients"]
    events = [
        _make_event(
            f"{dirs[i % len(dirs)]}/document_{i}.pdf",
            monotonic_ns=base_ns + i * 200_000_000,
            event_type=EventType.MODIFIED,
        )
        for i in range(25)
    ]
    ctx = _make_context(
        events,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=base_ns + 6_000_000_000,
    )

    res_in_place = eval_in_place.evaluate(ctx)
    assert res_in_place.triggered is True
    assert res_in_place.metadata["unique_files_modified"] == 25
    assert res_in_place.metadata["unique_directories_count"] == 5
    assert (
        "Suspicious in-place file transformation detected (T1486)"
        in res_in_place.explanation
    )
