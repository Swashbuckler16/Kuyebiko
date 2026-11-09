"""Integration tests for Phase 5 Advanced Detection Modules (Steps 5.1 to 5.5).

Verifies DetectionEngine orchestration across foundational and advanced signal
evaluators, ensuring multi-vector attacks are detected with full explainability
while benign developer and cleanup workloads remain isolated.
"""

from datetime import UTC, datetime
from uuid import uuid4

from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import DetectionOutcome, SignalFamily
from kuyebiko.models.events import (
    CorrelationProvenanceType,
    EventSource,
    EventType,
    FileEvent,
    sign_provenance_payload,
)


def _make_event(
    root_id: str,
    file_path: str,
    event_type: EventType,
    monotonic_ns: int,
    is_directory: bool = False,
    old_path: str | None = None,
    new_path: str | None = None,
    correlation_provenance: str | None = None,
) -> FileEvent:
    kwargs = {
        "event_id": str(uuid4()),
        "root_id": root_id,
        "file_path": file_path,
        "event_type": event_type,
        "monotonic_ns": monotonic_ns,
        "timestamp_utc": datetime.now(UTC),
        "source": EventSource.WINDOWS_WATCHER,
        "is_directory": is_directory,
    }
    if event_type == EventType.RENAMED:
        kwargs["old_path"] = old_path or "old.txt"
        kwargs["new_path"] = new_path or file_path
        kwargs["correlation_provenance"] = correlation_provenance or (
            sign_provenance_payload(
                CorrelationProvenanceType.PHASE3_CORRELATOR,
                kwargs["old_path"],
                kwargs["new_path"],
            )
        )
    return FileEvent(**kwargs)


def test_detection_engine_with_advanced_signals_registered():
    """Verify DetectionEngine can register advanced signals alongside foundational."""
    engine = DetectionEngine(auto_register_default_signals=True)
    engine.register_advanced_signals()

    reg_ids = engine.registry.list_signal_ids()
    assert "FS_BURST_WRITE" in reg_ids
    assert "FS_RENAME_RATIO" in reg_ids
    assert "FS_DELETE_RATIO" in reg_ids
    assert "FS_DIRECTORY_TRAVERSAL" in reg_ids
    assert "FS_EXTENSION_CONVERGENCE" in reg_ids
    # Advanced signals
    assert "FS_RECOVERY_INHIBITION" in reg_ids
    assert "FS_DATA_DESTRUCTION" in reg_ids
    assert "FS_FILESYSTEM_DISCOVERY" in reg_ids
    assert "FS_INDICATOR_REMOVAL" in reg_ids


def test_multi_vector_ransomware_attack_detection():
    """Attack with burst writes, recovery deletion, and mass destruction triggers."""
    engine = DetectionEngine(auto_register_default_signals=True)
    engine.register_advanced_signals()

    root_id = "target-drive"
    base_ns = 1_000_000_000

    # 1. Burst writes on 30 user files across multiple dirs
    for i in range(30):
        ev = _make_event(
            root_id=root_id,
            file_path=f"data_{i % 5}/file_{i}.locked",
            event_type=EventType.CREATED,
            monotonic_ns=base_ns + i * 1_000_000,
        )
        engine.process_event(ev)

    # 2. Deletion of recovery image / VSS
    ev_vss = _make_event(
        root_id=root_id,
        file_path="System Volume Information/SPP/OnlineMetadataCache/store.vss",
        event_type=EventType.DELETED,
        monotonic_ns=base_ns + 35_000_000,
    )
    engine.process_event(ev_vss)

    # 3. Mass destruction across 4 distinct user directories (20 deletions)
    dirs = ["documents", "finance", "legal", "archive"]
    for i in range(20):
        target_dir = dirs[i % len(dirs)]
        ev_del = _make_event(
            root_id=root_id,
            file_path=f"{target_dir}/original_{i}.docx",
            event_type=EventType.DELETED,
            monotonic_ns=base_ns + (40 + i) * 1_000_000,
        )
        engine.process_event(ev_del)

    # Trigger explicit evaluation cycle
    res = engine.evaluate_root(root_id, now_monotonic_ns=base_ns + 70_000_000)

    assert res.outcome == DetectionOutcome.DETECTION
    assert len(res.triggered_signal_families) >= 3
    assert SignalFamily.FILESYSTEM_ACTIVITY in res.triggered_signal_families
    assert SignalFamily.RECOVERY_INTERFERENCE in res.triggered_signal_families
    assert SignalFamily.DATA_DESTRUCTION in res.triggered_signal_families

    # Verify evidence IDs exist and trace to actual events
    triggered_sr = [sr for sr in res.signal_results if sr.triggered]
    assert len(triggered_sr) >= 3
    for sr in triggered_sr:
        assert len(sr.evidence_event_ids) > 0


def test_benign_build_workload_no_false_detection():
    """Benign compiler build workload does not trigger ransomware DETECTION."""
    engine = DetectionEngine(auto_register_default_signals=True)
    engine.register_advanced_signals()

    root_id = "build-root"
    base_ns = 2_000_000_000

    # 25 files written in target/debug/build
    for i in range(25):
        ev = _make_event(
            root_id=root_id,
            file_path=f"target/debug/build/artifact_{i}.obj",
            event_type=EventType.CREATED,
            monotonic_ns=base_ns + i * 1_000_000,
        )
        engine.process_event(ev)

    res = engine.evaluate_root(root_id, now_monotonic_ns=base_ns + 30_000_000)

    # May trigger burst write yielding SUSPICIOUS, but never confirmed DETECTION
    assert res.outcome != DetectionOutcome.DETECTION
    assert res.outcome in (
        DetectionOutcome.NO_DETECTION,
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
    )
    assert SignalFamily.RECOVERY_INTERFERENCE not in res.triggered_signal_families
    assert SignalFamily.DATA_DESTRUCTION not in res.triggered_signal_families
    assert SignalFamily.INDICATOR_REMOVAL not in res.triggered_signal_families


def test_benign_temp_cache_cleanup_no_data_destruction():
    """Cleaning temp files in single build folder does not trigger DATA_DESTRUCTION."""
    engine = DetectionEngine(auto_register_default_signals=True)
    engine.register_advanced_signals()

    root_id = "cleanup-root"
    base_ns = 3_000_000_000

    # 25 temporary files deleted in node_modules/.cache
    for i in range(25):
        ev = _make_event(
            root_id=root_id,
            file_path=f"node_modules/.cache/item_{i}.tmp",
            event_type=EventType.DELETED,
            monotonic_ns=base_ns + i * 1_000_000,
        )
        engine.process_event(ev)

    res = engine.evaluate_root(root_id, now_monotonic_ns=base_ns + 30_000_000)

    assert res.outcome != DetectionOutcome.DETECTION
    assert "FS_DATA_DESTRUCTION" not in res.triggered_signal_ids
    assert SignalFamily.DATA_DESTRUCTION not in res.triggered_signal_families
