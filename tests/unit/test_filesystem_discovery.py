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

    ev = FileEvent(
        event_id=str(uuid4()),
        root_id="root-1",
        file_path="dir/file.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=time.monotonic_ns(),
        source=EventSource.WINDOWS_WATCHER,
    )

    return DetectionContext(
        root_id="root-1",
        events=[ev],
        stats=stats,
        evaluated_monotonic_ns=time.monotonic_ns(),
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
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/User/Folder_{i}",
            operation="enumerate",
            process_id=9876,
            process_name="cmd.exe",
            monotonic_ns=1_000_000 + i * 10_000,
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
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/User/Folder_{i}",
            operation="enumerate",
            process_id=1010,
            process_name="SearchIndexer.exe",
            monotonic_ns=1_000_000 + i * 10_000,
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
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.severity_score == 0.0
    assert "attributed to known benign indexing/system process" in res.explanation
    assert res.metadata["is_benign_indexer"] is True


def test_throttled_discovery_does_not_trigger():
    """Enumeration below rate threshold does not trigger."""
    evaluator = FilesystemDiscoverySignalEvaluator(min_directories=15, threshold=10.0)
    disc_events = [
        DiscoveryTelemetryEvent(
            root_id="root-1",
            target_directory=f"C:/Users/User/Folder_{i}",
            operation="enumerate",
            process_id=2020,
            process_name="powershell.exe",
            monotonic_ns=1_000_000 + i * 10_000,
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
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert "within normal operational limits" in res.explanation
