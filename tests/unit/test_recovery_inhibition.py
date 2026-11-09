"""Unit tests for Step 5.2: Recovery Inhibition Detection Module (T1490)."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.advanced import ProcessTelemetryEvent, TelemetryCapability
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, WindowAggregateStats
from kuyebiko.detection.signals.recovery_inhibition import (
    RecoveryInhibitionSignalEvaluator,
)
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_event(
    file_path: str,
    event_type: EventType = EventType.DELETED,
    root_id: str = "root-1",
) -> FileEvent:
    return FileEvent(
        event_id=str(uuid4()),
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        monotonic_ns=time.monotonic_ns(),
        source=EventSource.WINDOWS_WATCHER,
    )


def _make_context(
    events: list[FileEvent],
    process_events: list[ProcessTelemetryEvent] | None = None,
    available_capabilities: set[TelemetryCapability] | None = None,
) -> DetectionContext:
    now = datetime.now(UTC)
    config = {}
    if process_events is not None:
        config["process_events"] = process_events
    if available_capabilities is not None:
        config["available_capabilities"] = available_capabilities

    stats = WindowAggregateStats(
        total_events=len(events),
        created_count=0,
        modified_count=sum(1 for e in events if e.event_type == EventType.MODIFIED),
        deleted_count=sum(1 for e in events if e.event_type == EventType.DELETED),
        renamed_count=0,
        directory_operations_count=0,
        unique_extensions=[".vhd"],
        unique_directories=["backup"],
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


def test_recovery_inhibition_metadata_properties():
    """Verify evaluator metadata declares T1490 and RECOVERY_INTERFERENCE."""
    evaluator = RecoveryInhibitionSignalEvaluator()
    assert evaluator.signal_id == "FS_RECOVERY_INHIBITION"
    assert evaluator.family == SignalFamily.RECOVERY_INTERFERENCE
    assert evaluator.metadata.mitre_technique == "T1490"
    assert (
        TelemetryCapability.FILESYSTEM_METADATA
        in evaluator.metadata.required_capabilities
    )


def test_recovery_filesystem_deletion_triggers():
    """Destructive deletion targeting recovery paths triggers FS_RECOVERY_INHIBITION."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    events = [
        _make_event("System Volume Information/SPP/OnlineMetadataCache/cat.vss"),
        _make_event("WindowsImageBackup/PC/Backup.vhd"),
    ]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 2.0
    assert res.severity_score >= 0.70
    assert len(res.evidence_event_ids) == 2
    assert "Recovery inhibition behaviour detected (T1490)" in res.explanation
    assert res.metadata["recovery_filesystem_events"] == 2
    assert res.metadata["process_telemetry_available"] is False
    assert "Command-line execution" in res.metadata["capability_limitation"]


def test_recovery_backup_extension_modification_triggers():
    """Destructive modification of .bkf or .wbcat backup catalogs triggers."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    events = [
        _make_event("backups/system_state.wbcat", event_type=EventType.MODIFIED),
    ]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 1.0
    assert "system_state.wbcat" in res.explanation


def test_recovery_process_execution_telemetry():
    """When process telemetry is available, detects vssadmin and wbadmin commands."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    now_ns = time.monotonic_ns()
    proc_events = [
        ProcessTelemetryEvent(
            root_id="root-1",
            process_id=4567,
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            monotonic_ns=now_ns - 1_000_000_000,
        ),
        ProcessTelemetryEvent(
            root_id="root-1",
            process_id=4568,
            process_name="bcdedit.exe",
            command_line="bcdedit /set {default} recoveryenabled no",
            monotonic_ns=now_ns - 500_000_000,
        ),
    ]
    ctx = _make_context(
        events=[],
        process_events=proc_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.PROCESS_EXECUTION,
        },
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 2.0
    assert res.severity_score >= 0.85
    assert len(res.evidence_event_ids) == 2
    assert "vssadmin.exe" in res.explanation
    assert res.metadata["process_telemetry_available"] is True
    assert res.metadata["telemetry_state"]["process_execution"] == "evidence_observed"
    assert "capability_limitation" not in res.metadata


def test_weak_recovery_indicators_do_not_trigger_alone():
    """Single .vhd modification or routine $Recycle.Bin deletion do not trigger."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    # 1. Single routine .vhd modification
    ctx_vhd = _make_context(
        [_make_event("virtual_machines/dev.vhd", event_type=EventType.MODIFIED)]
    )
    res_vhd = evaluator.evaluate(ctx_vhd)
    assert res_vhd.triggered is False
    assert res_vhd.metadata["weak_recovery_events"] == 1
    assert res_vhd.metadata["strong_recovery_events"] == 0

    # 2. Routine $Recycle.Bin deletion
    ctx_bin = _make_context(
        [
            _make_event(
                "$Recycle.Bin/S-1-5-21-12345/old_file.tmp",
                event_type=EventType.DELETED,
            )
        ]
    )
    res_bin = evaluator.evaluate(ctx_bin)
    assert res_bin.triggered is False
    assert res_bin.metadata["weak_recovery_events"] == 1
    assert res_bin.metadata["strong_recovery_events"] == 0


def test_cross_root_process_event_rejected():
    """Process execution telemetry from a foreign root is rejected."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    now_ns = time.monotonic_ns()
    proc_events = [
        ProcessTelemetryEvent(
            root_id="foreign-root-id",
            process_id=9999,
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all",
            monotonic_ns=now_ns - 1_000_000,
        )
    ]
    ctx = _make_context(
        events=[],
        process_events=proc_events,
        available_capabilities={
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.PROCESS_EXECUTION,
        },
    )
    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.metadata["rejected_auxiliary_events_count"] == 1


def test_process_capability_unmonitored():
    """When PROCESS_EXECUTION capability is unavailable, events are not inspected."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    now_ns = time.monotonic_ns()
    proc_events = [
        ProcessTelemetryEvent(
            root_id="root-1",
            process_id=1234,
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all",
            monotonic_ns=now_ns - 1_000_000,
        )
    ]
    # Context does NOT have PROCESS_EXECUTION capability
    ctx = _make_context(
        events=[],
        process_events=proc_events,
        available_capabilities={TelemetryCapability.FILESYSTEM_METADATA},
    )
    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.metadata["process_telemetry_available"] is False
    assert res.metadata["telemetry_state"]["process_execution"] == "unavailable"


def test_benign_administrative_deletion_does_not_trigger():
    """Ordinary file deletions not matching recovery paths do not trigger T1490."""
    evaluator = RecoveryInhibitionSignalEvaluator(threshold=1.0)
    events = [
        _make_event("documents/project_report.docx"),
        _make_event("photos/vacation.jpg"),
        _make_event("code/main.py"),
    ]
    ctx = _make_context(events)

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.observed_metric == 0.0
    assert res.severity_score == 0.0
    assert len(res.evidence_event_ids) == 0
    assert "No observable recovery inhibition activity detected" in res.explanation
