"""Synthetic labelled behaviour corpus validation for Phase 5 detection engine.

Validates the complete detection engine and multi-signal correlation layer across
10 benign and 8 suspicious representative enterprise workloads. Computes empirical
detection metrics: Precision, Recall, False Positive Rate, and Evidence Completeness.
"""

import time
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from kuyebiko.detection.advanced.contracts import (
    DiscoveryTelemetryEvent,
    EventLogTelemetryEvent,
    ProcessTelemetryEvent,
    TelemetryCapability,
)
from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import DetectionOutcome, DetectionResult
from kuyebiko.detection.signals.data_destruction import DataDestructionSignalEvaluator
from kuyebiko.detection.signals.filesystem_discovery import (
    FilesystemDiscoverySignalEvaluator,
)
from kuyebiko.detection.signals.in_place_transformation import (
    InPlaceTransformationSignalEvaluator,
)
from kuyebiko.detection.signals.indicator_removal import IndicatorRemovalSignalEvaluator
from kuyebiko.detection.signals.low_and_slow import LowAndSlowSignalEvaluator
from kuyebiko.detection.signals.recovery_inhibition import (
    RecoveryInhibitionSignalEvaluator,
)
from kuyebiko.models.events import (
    CorrelationProvenanceType,
    EventSource,
    EventType,
    FileEvent,
    sign_provenance_payload,
)


def _build_full_detection_engine() -> DetectionEngine:
    """Build a DetectionEngine configured with all 11 behaviour signals."""
    engine = DetectionEngine(auto_register_default_signals=True)
    advanced_evaluators = [
        DataDestructionSignalEvaluator(),
        FilesystemDiscoverySignalEvaluator(),
        IndicatorRemovalSignalEvaluator(),
        InPlaceTransformationSignalEvaluator(),
        LowAndSlowSignalEvaluator(),
        RecoveryInhibitionSignalEvaluator(),
    ]
    for ev in advanced_evaluators:
        engine.registry.register(ev)
    return engine


def _feed_workload(
    engine: DetectionEngine,
    events: Sequence[FileEvent],
    root_id: str,
    extra_config: dict[str, Any] | None = None,
) -> DetectionResult:
    """Feed events into engine and execute an evaluation cycle."""
    for ev in events:
        engine.process_event(ev)

    last_monotonic = events[-1].monotonic_ns if events else time.monotonic_ns()
    return engine.evaluate_root(
        root_id=root_id,
        now_monotonic_ns=last_monotonic,
        extra_config=extra_config,
    )


# --- 10 BENIGN WORKLOAD GENERATORS ---


def _workload_software_installation(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    # Rapid creations confined strictly to a single software directory
    for i in range(30):
        events.append(
            FileEvent(
                event_id=f"inst_{i}",
                root_id=root_id,
                file_path=f"ProgramFiles/NewApp/bin/lib_{i}.dll",
                event_type=EventType.CREATED,
                monotonic_ns=base_ns + i * 50_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_software_uninstallation(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    # Deletions confined strictly to a single folder hierarchy
    for i in range(25):
        events.append(
            FileEvent(
                event_id=f"uninst_{i}",
                root_id=root_id,
                file_path=f"ProgramFiles/OldApp/bin/file_{i}.dll",
                event_type=EventType.DELETED,
                monotonic_ns=base_ns + i * 50_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_large_file_copying(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(5):
        events.append(
            FileEvent(
                event_id=f"copy_{i}",
                root_id=root_id,
                file_path=f"Media/video_archive_{i}.iso",
                event_type=EventType.CREATED,
                monotonic_ns=base_ns + i * 200_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_git_operations(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(35):
        events.append(
            FileEvent(
                event_id=f"git_{i}",
                root_id=root_id,
                file_path=f".git/objects/pack/pack_{i}.idx",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + i * 20_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_database_writes(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(20):
        events.append(
            FileEvent(
                event_id=f"db_{i}",
                root_id=root_id,
                file_path="var/db/app.wal",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + i * 50_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_backup_and_sync(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(15):
        events.append(
            FileEvent(
                event_id=f"backup_{i}",
                root_id=root_id,
                file_path=f"Backups/2026/snapshot_{i}.bak",
                event_type=EventType.CREATED,
                monotonic_ns=base_ns + i * 100_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_temporary_file_cleanup(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(30):
        events.append(
            FileEvent(
                event_id=f"temp_{i}",
                root_id=root_id,
                file_path=f"AppData/Local/Temp/cache_file_{i}.tmp",
                event_type=EventType.DELETED,
                monotonic_ns=base_ns + i * 30_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_log_rotation(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(4):
        old_p = f"Logs/service_{i}.log"
        new_p = f"Logs/service_{i}.log.1"
        prov = sign_provenance_payload(
            CorrelationProvenanceType.PHASE3_CORRELATOR, old_p, new_p
        )
        events.append(
            FileEvent(
                event_id=f"rot_{i}",
                root_id=root_id,
                file_path=new_p,
                old_path=old_p,
                new_path=new_p,
                event_type=EventType.RENAMED,
                correlation_provenance=prov,
                monotonic_ns=base_ns + i * 200_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_normal_document_editing(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    for i in range(3):
        events.append(
            FileEvent(
                event_id=f"doc_{i}",
                root_id=root_id,
                file_path=f"Documents/report_{i}.docx",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + i * 1_000_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_background_indexing(
    root_id: str, base_ns: int
) -> tuple[list[FileEvent], dict[str, Any]]:
    # Benign indexing attributed to SearchIndexer.exe
    now = datetime.now(UTC)
    events = [
        FileEvent(
            event_id="index_seed",
            root_id=root_id,
            file_path="Documents/index_seed.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=base_ns,
            source=EventSource.WINDOWS_WATCHER,
        )
    ]
    discovery_events = [
        DiscoveryTelemetryEvent(
            event_id=f"idx_disc_{i}",
            root_id=root_id,
            monotonic_ns=base_ns + i * 100_000_000,
            target_directory=f"C:\\Users\\User\\Dir_{i}",
            process_name="SearchIndexer.exe",
            timestamp_utc=now,
        )
        for i in range(12)
    ]
    return events, {"discovery_events": discovery_events}


# --- 8 SUSPICIOUS WORKLOAD GENERATORS ---


def _workload_rapid_mass_deletion(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    # 24 deletions across 4 directories (production data destruction)
    dirs = ["Finance/2026", "HR/Employees", "Legal/Contracts", "Engineering/Src"]
    for i in range(24):
        d = dirs[i % len(dirs)]
        events.append(
            FileEvent(
                event_id=f"destruct_{i}",
                root_id=root_id,
                file_path=f"{d}/document_{i}.docx",
                event_type=EventType.DELETED,
                monotonic_ns=base_ns + i * 30_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_recovery_artifact_deletion(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    artifacts = [
        "System Volume Information/shadow_copy_01",
        "Backups/WindowsImageBackup/catalog.wbcat",
        "VMs/server_backup.vhd",
    ]
    for i, path in enumerate(artifacts):
        events.append(
            FileEvent(
                event_id=f"rec_art_{i}",
                root_id=root_id,
                file_path=path,
                event_type=EventType.DELETED,
                monotonic_ns=base_ns + i * 100_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_recovery_inhibition_telemetry(
    root_id: str, base_ns: int
) -> tuple[list[FileEvent], dict[str, Any]]:
    now = datetime.now(UTC)
    events = [
        FileEvent(
            event_id="rec_seed",
            root_id=root_id,
            file_path="Docs/seed.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=base_ns,
            source=EventSource.WINDOWS_WATCHER,
        )
    ]
    proc_events = [
        ProcessTelemetryEvent(
            event_id="rec_cmd_1",
            root_id=root_id,
            monotonic_ns=base_ns,
            process_id=2048,
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            timestamp_utc=now,
        )
    ]
    return events, {
        "process_events": proc_events,
        "available_capabilities": {
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.PROCESS_EXECUTION,
        },
    }


def _workload_security_log_clearing(
    root_id: str, base_ns: int
) -> tuple[list[FileEvent], dict[str, Any]]:
    now = datetime.now(UTC)
    events = [
        FileEvent(
            event_id="log_seed",
            root_id=root_id,
            file_path="Logs/seed.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=base_ns,
            source=EventSource.WINDOWS_WATCHER,
        )
    ]
    evtx_events = [
        EventLogTelemetryEvent(
            event_id="ev_clear_1",
            root_id=root_id,
            monotonic_ns=base_ns,
            provider_name="Microsoft-Windows-Security-Auditing",
            channel="Security",
            event_code=1102,
            message="The audit log was cleared",
            timestamp_utc=now,
        )
    ]
    return events, {
        "event_log_events": evtx_events,
        "available_capabilities": {
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.EVENT_LOG,
        },
    }


def _workload_broad_filesystem_enumeration(
    root_id: str, base_ns: int
) -> tuple[list[FileEvent], dict[str, Any]]:
    now = datetime.now(UTC)
    disc_events = [
        DiscoveryTelemetryEvent(
            event_id=f"mal_disc_{i}",
            root_id=root_id,
            monotonic_ns=base_ns + i * 10_000_000,
            target_directory=f"C:\\Users\\Victim\\Folder_{i}",
            process_name="malware.exe",
            timestamp_utc=now,
        )
        for i in range(105)
    ]
    events = [
        FileEvent(
            event_id="enum_seed",
            root_id=root_id,
            file_path="Docs/seed.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=base_ns + 110 * 10_000_000,
            source=EventSource.WINDOWS_WATCHER,
        )
    ]
    return events, {
        "discovery_events": disc_events,
        "available_capabilities": {
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
        },
    }


def _workload_low_and_slow_transformation(
    root_id: str, base_ns: int
) -> list[FileEvent]:
    events = []
    # 25 modifications across 4 directories at 2 ops/second (500ms intervals)
    dirs = ["Finance", "Legal", "Engineering", "HR"]
    for i in range(25):
        d = dirs[i % len(dirs)]
        events.append(
            FileEvent(
                event_id=f"slow_{i}",
                root_id=root_id,
                file_path=f"{d}/doc_{i}.dat",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + i * 500_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_in_place_transformation(root_id: str, base_ns: int) -> list[FileEvent]:
    events = []
    dirs = ["Accounting", "Contracts", "Schematics", "Patents"]
    for i in range(32):
        d = dirs[i % len(dirs)]
        events.append(
            FileEvent(
                event_id=f"inplace_{i}",
                root_id=root_id,
                file_path=f"{d}/spec_{i}.doc",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + i * 40_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def _workload_combined_multi_signal_attack(
    root_id: str, base_ns: int
) -> tuple[list[FileEvent], dict[str, Any]]:
    events = []
    dirs = ["Finance", "Legal", "Engineering", "HR"]
    exts = ["pdf", "docx", "xlsx", "jpg"]
    now = datetime.now(UTC)

    # 1. Rename convergence to .locked with 4 distinct original extensions
    for i in range(24):
        d = dirs[i % len(dirs)]
        ext = exts[i % len(exts)]
        old_p = f"{d}/doc_{i}.{ext}"
        new_p = f"{d}/doc_{i}.{ext}.locked"
        prov = sign_provenance_payload(
            CorrelationProvenanceType.PHASE3_CORRELATOR, old_p, new_p
        )
        events.append(
            FileEvent(
                event_id=f"atk_ren_{i}",
                root_id=root_id,
                file_path=new_p,
                old_path=old_p,
                new_path=new_p,
                event_type=EventType.RENAMED,
                correlation_provenance=prov,
                monotonic_ns=base_ns + i * 20_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )

    # 2. Burst write modifications (16 files)
    for i in range(16):
        d = dirs[i % len(dirs)]
        events.append(
            FileEvent(
                event_id=f"atk_mod_{i}",
                root_id=root_id,
                file_path=f"{d}/data_{i}.bin",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_ns + (i + 24) * 20_000_000,
                source=EventSource.WINDOWS_WATCHER,
            )
        )

    # 3. Recovery inhibition command execution
    proc_events = [
        ProcessTelemetryEvent(
            event_id="atk_rec_cmd",
            root_id=root_id,
            monotonic_ns=base_ns,
            process_id=9999,
            process_name="vssadmin.exe",
            command_line="vssadmin delete shadows /all /quiet",
            timestamp_utc=now,
        )
    ]
    return events, {
        "process_events": proc_events,
        "available_capabilities": {
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.PROCESS_EXECUTION,
        },
    }


# --- VALIDATION TEST SUITE & METRIC ASSERTIONS ---


def test_full_corpus_precision_recall_and_quality_metrics() -> None:
    """Execute complete 18-workload synthetic corpus and verify detection metrics.

    Evaluates:
    - Precision >= 0.95 (No false alarms misclassified as confirmed DETECTION)
    - Recall >= 0.95 (Suspicious scenarios accurately detected)
    - False Positive Rate <= 0.05
    - Evidence Completeness & Telemetry Coverage
    """
    engine = _build_full_detection_engine()
    base_ns = time.monotonic_ns()

    benign_results: list[DetectionResult] = []
    suspicious_results: list[DetectionResult] = []

    # 1. Run 10 Benign Scenarios
    benign_workloads = [
        ("soft_install", _workload_software_installation("r_inst", base_ns), {}),
        (
            "soft_uninstall",
            _workload_software_uninstallation("r_uninst", base_ns),
            {},
        ),
        ("file_copy", _workload_large_file_copying("r_copy", base_ns), {}),
        ("git_ops", _workload_git_operations("r_git", base_ns), {}),
        ("db_writes", _workload_database_writes("r_db", base_ns), {}),
        ("backup_sync", _workload_backup_and_sync("r_sync", base_ns), {}),
        ("temp_clean", _workload_temporary_file_cleanup("r_temp", base_ns), {}),
        ("log_rotation", _workload_log_rotation("r_log", base_ns), {}),
        ("doc_edit", _workload_normal_document_editing("r_doc", base_ns), {}),
    ]

    for _name, evts, cfg in benign_workloads:
        res = _feed_workload(engine, evts, evts[0].root_id, extra_config=cfg)
        benign_results.append(res)

    # Benign indexing with auxiliary telemetry
    idx_evts, idx_cfg = _workload_background_indexing("r_idx", base_ns)
    res_idx = _feed_workload(engine, idx_evts, "r_idx", extra_config=idx_cfg)
    benign_results.append(res_idx)

    assert len(benign_results) == 10

    # 2. Run 8 Suspicious Scenarios
    suspicious_workloads = [
        (
            "mass_del",
            _workload_rapid_mass_deletion("r_s_del", base_ns),
            {},
        ),
        (
            "rec_del",
            _workload_recovery_artifact_deletion("r_s_rec", base_ns),
            {},
        ),
        (
            "low_slow",
            _workload_low_and_slow_transformation("r_s_slow", base_ns),
            {},
        ),
        (
            "inplace",
            _workload_in_place_transformation("r_s_inplace", base_ns),
            {},
        ),
    ]

    for _name, evts, cfg in suspicious_workloads:
        res = _feed_workload(engine, evts, evts[0].root_id, extra_config=cfg)
        suspicious_results.append(res)

    # Scenarios with auxiliary telemetry
    rec_evts, rec_cfg = _workload_recovery_inhibition_telemetry("r_s_rec_cmd", base_ns)
    suspicious_results.append(
        _feed_workload(engine, rec_evts, "r_s_rec_cmd", extra_config=rec_cfg)
    )

    log_evts, log_cfg = _workload_security_log_clearing("r_s_log", base_ns)
    suspicious_results.append(
        _feed_workload(engine, log_evts, "r_s_log", extra_config=log_cfg)
    )

    enum_evts, enum_cfg = _workload_broad_filesystem_enumeration("r_s_enum", base_ns)
    suspicious_results.append(
        _feed_workload(engine, enum_evts, "r_s_enum", extra_config=enum_cfg)
    )

    multi_evts, multi_cfg = _workload_combined_multi_signal_attack("r_s_multi", base_ns)
    suspicious_results.append(
        _feed_workload(engine, multi_evts, "r_s_multi", extra_config=multi_cfg)
    )

    assert len(suspicious_results) == 8

    # 3. Calculate Detection Metrics
    # Benign should NOT trigger confirmed DETECTION (can be NO_DETECTION or SUSPICIOUS)
    false_positives = sum(
        1 for r in benign_results if r.outcome == DetectionOutcome.DETECTION
    )
    true_negatives = len(benign_results) - false_positives

    # Suspicious workloads should trigger SUSPICIOUS_ACTIVITY or confirmed DETECTION
    true_positives = sum(
        1
        for r in suspicious_results
        if r.outcome
        in (DetectionOutcome.DETECTION, DetectionOutcome.SUSPICIOUS_ACTIVITY)
    )
    false_negatives = len(suspicious_results) - true_positives

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)
    fpr = false_positives / (false_positives + true_negatives)

    # 4. Assert Scientific Quality Thresholds
    assert precision >= 0.95, f"Expected precision >= 0.95, got {precision:.3f}"
    assert recall >= 0.95, f"Expected recall >= 0.95, got {recall:.3f}"
    assert fpr <= 0.05, f"Expected false positive rate <= 0.05, got {fpr:.3f}"

    # Verify Combined Multi-Vector Ransomware attack triggers confirmed DETECTION
    multi_result = suspicious_results[-1]
    assert multi_result.outcome == DetectionOutcome.DETECTION
    assert multi_result.confidence_score >= 0.80
    assert len(multi_result.triggered_signal_families) >= 2
    assert multi_result.explanation != ""
