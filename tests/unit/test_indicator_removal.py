"""Unit tests for Step 5.5: Indicator Removal & Security Log Tampering (T1070)."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.advanced import (
    EventLogTelemetryEvent,
    ProcessTelemetryEvent,
    TelemetryCapability,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, WindowAggregateStats
from kuyebiko.detection.signals.indicator_removal import IndicatorRemovalSignalEvaluator
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


def _make_context(
    events: list[FileEvent],
    event_log_events: list[EventLogTelemetryEvent] | None = None,
    process_events: list[ProcessTelemetryEvent] | None = None,
) -> DetectionContext:
    now = datetime.now(UTC)
    config = {}
    if event_log_events is not None:
        config["event_log_events"] = event_log_events
    if process_events is not None:
        config["process_events"] = process_events

    stats = WindowAggregateStats(
        total_events=len(events),
        created_count=0,
        modified_count=0,
        deleted_count=sum(1 for e in events if e.event_type == EventType.DELETED),
        renamed_count=0,
        directory_operations_count=0,
        unique_extensions=[".evtx"],
        unique_directories=["logs"],
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
        config=config,
    )


def test_indicator_removal_metadata_properties():
    """Verify evaluator metadata declares T1070 and INDICATOR_REMOVAL."""
    evaluator = IndicatorRemovalSignalEvaluator()
    assert evaluator.signal_id == "FS_INDICATOR_REMOVAL"
    assert evaluator.family == SignalFamily.INDICATOR_REMOVAL
    assert evaluator.metadata.mitre_technique == "T1070"
    assert (
        TelemetryCapability.FILESYSTEM_METADATA
        in evaluator.metadata.required_capabilities
    )


def test_evtx_deletion_triggers():
    """Deletion of primary Security.evtx or System.evtx triggers T1070."""
    evaluator = IndicatorRemovalSignalEvaluator(threshold=1.0)
    events = [
        _make_event("Windows/System32/winevt/Logs/Security.evtx"),
    ]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 1.0
    assert res.severity_score >= 0.85
    assert len(res.evidence_event_ids) == 1
    assert "Security.evtx" in res.explanation
    assert res.metadata["filesystem_tampering_count"] == 1


def test_journal_and_database_deletion_triggers():
    """Deletion of $LogFile, $UsnJrnl, or kuyebiko.db triggers T1070."""
    evaluator = IndicatorRemovalSignalEvaluator(threshold=1.0)
    events = [
        _make_event("$Extend/$UsnJrnl"),
        _make_event("kuyebiko.db"),
    ]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 2.0
    assert len(res.evidence_event_ids) == 2


def test_event_log_cleared_telemetry_triggers():
    """Windows Event 1102 (audit log cleared) triggers with highest severity."""
    evaluator = IndicatorRemovalSignalEvaluator(threshold=1.0)
    event_logs = [
        EventLogTelemetryEvent(
            root_id="root-1",
            provider_name="Microsoft-Windows-Security-Auditing",
            channel="Security",
            event_code=1102,
            message="The audit log was cleared",
            monotonic_ns=1_000_000,
        )
    ]
    ctx = _make_context(events=[], event_log_events=event_logs)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.severity_score == 0.95
    assert res.observed_metric == 1.0
    assert "Event ID [1102]" in res.explanation


def test_wevtutil_command_execution_triggers():
    """Execution of wevtutil cl System command triggers T1070."""
    evaluator = IndicatorRemovalSignalEvaluator(threshold=1.0)
    proc_events = [
        ProcessTelemetryEvent(
            root_id="root-1",
            process_id=3344,
            process_name="wevtutil.exe",
            command_line="wevtutil.exe cl System",
            monotonic_ns=1_000_000,
        )
    ]
    ctx = _make_context(events=[], process_events=proc_events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 1.0
    assert "wevtutil.exe" in res.explanation


def test_benign_archive_rotation_does_not_trigger():
    """Standard rotation of archive event logs (Archive-*.evtx) does not trigger."""
    evaluator = IndicatorRemovalSignalEvaluator(threshold=1.0)
    events = [
        _make_event("Windows/System32/winevt/Logs/Archive-Security-2026-03-01.evtx"),
    ]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.observed_metric == 0.0
    assert "No observable indicator removal" in res.explanation
