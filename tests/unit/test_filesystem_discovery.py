"""Unit tests for Step 5.4: Filesystem Discovery Detection Module (T1083)."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.advanced import DiscoveryTelemetryEvent, TelemetryCapability
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, WindowAggregateStats
from kuyebiko.detection.signals.filesystem_discovery import (
    FilesystemDiscoverySignalEvaluator,
)
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_context(
    discovery_events: list[DiscoveryTelemetryEvent] | None = None,
    available_capabilities: set[TelemetryCapability] | None = None,
    window_duration_seconds: float = 2.0,
    evaluated_monotonic_ns: int | None = None,
) -> DetectionContext:
    now = datetime.now(UTC)
    config = {}
    if discovery_events is not None:
        config["discovery_events"] = discovery_events
    if available_capabilities is not None:
        config["available_capabilities"] = available_capabilities

    stats = WindowAggregateStats(
        total_events=1,
        created_count=0,
        modified_count=1,
        deleted_count=0,
        renamed_count=0,
        directory_operations_count=0,
        unique_extensions=[".txt"],
        unique_directories=["dir"],
        unique_relative_paths=["dir/file.txt"],
        rename_pairs_count=0,
        events_per_second=0.5,
        window_duration_seconds=window_duration_seconds,
    )

    eval_mono = (
        evaluated_monotonic_ns
        if evaluated_monotonic_ns is not None
        else time.monotonic_ns()
    )

    ev = FileEvent(
        event_id=str(uuid4()),
        root_id="root-1",
        file_path="dir/file.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=eval_mono,
        source=EventSource.WINDOWS_WATCHER,
    )

    return DetectionContext(
        root_id="root-1",
        events=[ev],
        stats=stats,
        evaluated_monotonic_ns=eval_mono,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=window_duration_seconds,
        config=config,
    )


def test_filesystem_discovery_metadata_properties():
    """Verify evaluator metadata declares T1083 and read-access requirement."""
    evaluator = FilesystemDiscoverySignalEvaluator()
    assert evaluator.signal_id == "FS_FILESYSTEM_DISCOVERY"
    assert evaluator.family == SignalFamily.FILESYSTEM_DISCOVERY
    assert evaluator.metadata.mitre_technique == "T1083"
    assert (
        TelemetryCapability.FILESYSTEM_READ_ACCESS
        in evaluator.metadata.required_capabilities
    )


def test_missing_telemetry_produces_explicit_capability_limitation():
    """In default environment, returns un-triggered with capability limitation."""
    evaluator = FilesystemDiscoverySignalEvaluator()
    # Default environment only has FILESYSTEM_METADATA
    ctx = _make_context(
        available_capabilities={TelemetryCapability.FILESYSTEM_METADATA}
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.severity_score == 0.0
    assert (
        "cannot be evaluated: Missing required telemetry capabilities"
        in res.explanation
    )
    assert "filesystem_read_access" in res.metadata["missing_capabilities"]


def test_rapid_discovery_triggers_with_read_telemetry():
    """Rapid enumeration across 16 directories by unknown process triggers T1083."""
    evaluator = FilesystemDiscoverySignalEvaluator(min_directories=15, threshold=5.0)
    now_ns = 10_000_000_000
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/User/Folder_{i}",
            operation="enumerate",
            process_id=9876,
            process_name="cmd.exe",
            monotonic_ns=now_ns - 1_000_000_000 + i * 10_000,
        )
        for i in range(16)
    ]

    ctx = _make_context(
        discovery_events=disc_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
        },
        window_duration_seconds=2.0,  # 16 dirs / 2s = 8 dirs/sec (>= 5.0)
        evaluated_monotonic_ns=now_ns,
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 8.0
    assert res.severity_score >= 0.60
    assert len(res.evidence_event_ids) == 16
    assert "Rapid filesystem discovery detected (T1083)" in res.explanation
    assert res.metadata["unique_directories_enumerated"] == 16
    assert res.metadata["is_benign_indexer"] is False


def test_benign_indexer_does_not_trigger():
    """Rapid enumeration attributed to SearchIndexer.exe is recognized as benign."""
    evaluator = FilesystemDiscoverySignalEvaluator(min_directories=15, threshold=5.0)
    now_ns = 10_000_000_000
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/User/Folder_{i}",
            operation="enumerate",
            process_id=1010,
            process_name="SearchIndexer.exe",
            monotonic_ns=now_ns - 1_000_000_000 + i * 10_000,
        )
        for i in range(20)
    ]

    ctx = _make_context(
        discovery_events=disc_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
        },
        window_duration_seconds=2.0,
        evaluated_monotonic_ns=now_ns,
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.severity_score == 0.0
    assert "attributed to known benign indexing/system process" in res.explanation
    assert res.metadata["is_benign_indexer"] is True


def test_throttled_discovery_does_not_trigger():
    """Enumeration below rate threshold does not trigger."""
    evaluator = FilesystemDiscoverySignalEvaluator(min_directories=15, threshold=10.0)
    now_ns = 20_000_000_000
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/User/Folder_{i}",
            operation="enumerate",
            process_id=2020,
            process_name="powershell.exe",
            monotonic_ns=now_ns - 5_000_000_000 + i * 10_000,
        )
        for i in range(16)
    ]

    ctx = _make_context(
        discovery_events=disc_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
        },
        window_duration_seconds=10.0,  # 16 dirs / 10s = 1.6 dirs/sec (< 10.0)
        evaluated_monotonic_ns=now_ns,
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert "within normal operational limits" in res.explanation


def test_concurrent_benign_indexer_does_not_mask_suspicious_discovery():
    """A dominant SearchIndexer cannot mask concurrent rapid enumeration by cmd.exe."""
    evaluator = FilesystemDiscoverySignalEvaluator(min_directories=15, threshold=5.0)
    now_ns = 10_000_000_000
    # 50 events from SearchIndexer across 50 dirs (dominant benign activity)
    benign_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Indexed/Dir_{i}",
            operation="enumerate",
            process_id=1010,
            process_name="SearchIndexer.exe",
            monotonic_ns=now_ns - 1_000_000_000 + i * 1_000,
        )
        for i in range(50)
    ]
    # 18 events from cmd.exe across 18 dirs (suspicious discovery)
    suspicious_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/Secret/Dir_{i}",
            operation="enumerate",
            process_id=4444,
            process_name="cmd.exe",
            monotonic_ns=now_ns - 1_000_000_000 + i * 10_000,
        )
        for i in range(18)
    ]

    ctx = _make_context(
        discovery_events=benign_events + suspicious_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
            TelemetryCapability.PROCESS_EXECUTION,
        },
        window_duration_seconds=2.0,  # 18 dirs / 2s = 9 dirs/sec (>= 5.0)
        evaluated_monotonic_ns=now_ns,
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.metadata["is_benign_indexer"] is False
    assert any(
        p["process_name"] == "cmd.exe" for p in res.metadata["offending_processes"]
    )
    assert "SearchIndexer.exe".lower() in res.metadata["benign_processes_suppressed"]
    assert "cmd.exe" in res.explanation


def test_cross_root_discovery_events_rejected():
    """Discovery events from an unrelated root do not contribute to evaluation."""
    evaluator = FilesystemDiscoverySignalEvaluator(min_directories=15, threshold=5.0)
    now_ns = 10_000_000_000
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="foreign-root",
            target_directory=f"C:/Users/Target/Dir_{i}",
            operation="enumerate",
            process_id=9876,
            process_name="cmd.exe",
            monotonic_ns=now_ns - 1_000_000_000 + i * 10_000,
        )
        for i in range(20)
    ]
    ctx = _make_context(
        discovery_events=disc_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
        },
        window_duration_seconds=2.0,
        evaluated_monotonic_ns=now_ns,
    )
    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.metadata["rejected_auxiliary_events_count"] == 20
