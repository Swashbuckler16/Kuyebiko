"""Integration tests for DetectionEngine end-to-end pipeline scenarios.

Validates the full chain from normalized FileEvent objects through the
SlidingWindowCorrelator, SignalRegistry, and all 5 foundational signal evaluators.
"""

import time
from datetime import UTC, datetime

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import (
    DetectionOutcome,
    SignalFamily,
    SignalResult,
)
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventSource, EventType, FileEvent, TelemetryQuality
from kuyebiko.processing.ordering import EventOrderingMetadata


def _event(
    root_id: str = "root-1",
    file_path: str = "doc.txt",
    event_type: EventType = EventType.MODIFIED,
    old_path: str | None = None,
    new_path: str | None = None,
    is_directory: bool = False,
    monotonic_ns: int | None = None,
    quality: TelemetryQuality = TelemetryQuality.NORMAL,
    event_id: str | None = None,
) -> FileEvent:
    kwargs = {
        "event_id": event_id or f"evt_{time.monotonic_ns()}_{file_path}",
        "root_id": root_id,
        "file_path": file_path,
        "event_type": event_type,
        "monotonic_ns": (
            monotonic_ns if monotonic_ns is not None else time.monotonic_ns()
        ),
        "source": EventSource.WINDOWS_WATCHER,
        "is_directory": is_directory,
        "quality": quality,
    }
    if event_type == EventType.RENAMED:
        kwargs["old_path"] = old_path or "old.txt"
        kwargs["new_path"] = new_path or file_path
    return FileEvent(**kwargs)


class CrashingEvaluator(BaseSignalEvaluator):
    def __init__(self) -> None:
        super().__init__(
            signal_id="SIG_CRASH",
            name="Crashing Evaluator",
            family=SignalFamily.FILESYSTEM_ACTIVITY,
            threshold=1.0,
        )

    def evaluate(self, context: DetectionContext) -> SignalResult:
        raise RuntimeError("Fatal bug inside evaluator")


def test_scenario_a_benign_activity():
    """Benign activity: normal modifications, occasional save, single directory."""
    engine = DetectionEngine(auto_register_default_signals=True)

    base_time = time.monotonic_ns()
    events = [
        _event(
            root_id="root-corp",
            file_path="workspace/readme.md",
            event_type=EventType.MODIFIED,
            monotonic_ns=base_time + i * 1_000_000_000,
        )
        for i in range(5)
    ]

    last_result = None
    for e in events:
        last_result = engine.process_event(e)

    assert last_result is not None
    assert last_result.outcome == DetectionOutcome.NO_DETECTION
    assert len(last_result.triggered_signal_ids) == 0


def test_scenario_b_suspicious_burst_multi_family():
    """Suspicious burst: 20 rapid unique writes across 6 directories and 8 renames."""
    engine = DetectionEngine(
        auto_register_default_signals=True,
        detection_family_threshold=2,
    )

    base_time = time.monotonic_ns()
    events = []

    dirs = ["finance", "hr", "legal", "engineering", "sales", "executive"]
    for i in range(20):
        d = dirs[i % len(dirs)]
        events.append(
            _event(
                root_id="root-attack",
                file_path=f"{d}/doc_{i}.docx",
                event_type=EventType.MODIFIED,
                monotonic_ns=base_time + i * 50_000_000,
                event_id=f"write_{i}",
            )
        )

    for i in range(8):
        d = dirs[i % len(dirs)]
        events.append(
            _event(
                root_id="root-attack",
                file_path=f"{d}/doc_{i}.locked",
                event_type=EventType.RENAMED,
                old_path=f"{d}/doc_{i}.docx",
                new_path=f"{d}/doc_{i}.locked",
                monotonic_ns=base_time + 1_000_000_000 + i * 50_000_000,
                event_id=f"rename_{i}",
            )
        )

    last_result = None
    for e in events:
        last_result = engine.process_event(e)

    assert last_result is not None
    assert last_result.outcome == DetectionOutcome.DETECTION
    assert "FS_BURST_WRITE" in last_result.triggered_signal_ids
    assert "FS_DIRECTORY_TRAVERSAL" in last_result.triggered_signal_ids
    assert len(last_result.triggered_signal_families) >= 2
    assert SignalFamily.FILESYSTEM_ACTIVITY in last_result.triggered_signal_families
    assert SignalFamily.DIRECTORY_TRAVERSAL in last_result.triggered_signal_families


def test_scenario_c_extension_convergence():
    """Extension convergence: diverse files (.pdf, .docx, .xlsx, .jpg) to .kuyebiko."""
    engine = DetectionEngine(auto_register_default_signals=True)

    base_time = time.monotonic_ns()
    exts = ["pdf", "docx", "xlsx", "jpg", "png", "zip"]
    events = [
        _event(
            root_id="root-vault",
            file_path=f"data/file_{i}.kuyebiko",
            event_type=EventType.RENAMED,
            old_path=f"data/file_{i}.{ext}",
            new_path=f"data/file_{i}.kuyebiko",
            monotonic_ns=base_time + i * 100_000_000,
            event_id=f"conv_{i}",
        )
        for i, ext in enumerate(exts)
    ]

    last_result = None
    for e in events:
        last_result = engine.process_event(e)

    assert last_result is not None
    assert "FS_EXTENSION_CONVERGENCE" in last_result.triggered_signal_ids
    assert last_result.outcome in (
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
        DetectionOutcome.DETECTION,
    )


def test_scenario_d_incomplete_degraded_telemetry():
    """Degraded telemetry: watcher buffer drops propagate INSUFFICIENT_TELEMETRY."""
    engine = DetectionEngine(auto_register_default_signals=True)

    engine.set_root_telemetry_status(
        root_id="root-degraded",
        is_degraded=True,
        reason="ERROR_NOTIFY_ENUM_DIR (1022) kernel overflow",
    )

    ev = _event(
        root_id="root-degraded",
        file_path="a.txt",
        event_type=EventType.MODIFIED,
    )
    result = engine.process_event(ev)

    assert result is not None
    assert result.is_telemetry_degraded is True
    assert result.outcome == DetectionOutcome.INSUFFICIENT_TELEMETRY
    assert any("kernel overflow" in r for r in result.degradation_reasons)


def test_scenario_e_multi_root_isolation():
    """Multi-root isolation: Root A receives burst, Root B receives benign edits."""
    engine = DetectionEngine(auto_register_default_signals=True)

    base_time = time.monotonic_ns()

    dirs = ["dir1", "dir2", "dir3", "dir4", "dir5", "dir6"]
    for i in range(20):
        ev_a = _event(
            root_id="root-victim",
            file_path=f"{dirs[i % len(dirs)]}/f_{i}.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=base_time + i * 50_000_000,
            event_id=f"a_{i}",
        )
        engine.process_event(ev_a)

    ev_b1 = _event(
        root_id="root-safe",
        file_path="safe_notes.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=base_time + 100_000_000,
        event_id="b_1",
    )
    ev_b2 = _event(
        root_id="root-safe",
        file_path="safe_notes.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=base_time + 200_000_000,
        event_id="b_2",
    )
    engine.process_event(ev_b1)
    res_b = engine.process_event(ev_b2)

    assert res_b is not None
    assert res_b.outcome == DetectionOutcome.NO_DETECTION
    assert len(res_b.triggered_signal_ids) == 0
    assert res_b.total_events_evaluated == 2

    res_a = engine.get_latest_result("root-victim")
    assert res_a is not None
    assert "FS_BURST_WRITE" in res_a.triggered_signal_ids
    assert "FS_DIRECTORY_TRAVERSAL" in res_a.triggered_signal_ids


def test_detection_engine_listeners():
    """Verify listener dispatch upon completed evaluation."""
    engine = DetectionEngine(auto_register_default_signals=True)
    captured = []

    engine.add_listener(lambda res: captured.append(res))

    ev = _event(root_id="root-1", file_path="sample.txt")
    engine.process_event(ev)

    assert len(captured) == 1
    assert captured[0].root_id == "root-1"


def test_evaluator_failure_produces_evaluation_error():
    """When an individual evaluator fails, engine reports EVALUATION_ERROR."""
    engine = DetectionEngine(auto_register_default_signals=False)
    engine.registry.register(CrashingEvaluator())

    ev = _event(root_id="root-crash", file_path="sample.txt")
    result = engine.process_event(ev)

    assert result is not None
    assert result.outcome == DetectionOutcome.EVALUATION_ERROR
    assert len(result.evaluation_errors) == 1
    assert "Fatal bug inside evaluator" in result.evaluation_errors[0]


def test_window_expiration_and_clear_restart():
    """Verify window expiration and clear/restart behaviour."""
    engine = DetectionEngine(auto_register_default_signals=True)

    base_ns = 1_000_000_000
    ev1 = _event(
        root_id="root-exp",
        file_path="file1.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=base_ns,
    )
    engine.process_event(ev1)

    # 15 seconds later (window is 10s), previous event is expired
    ev2 = _event(
        root_id="root-exp",
        file_path="file2.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=base_ns + 15_000_000_000,
    )
    res2 = engine.process_event(ev2)

    assert res2 is not None
    assert res2.total_events_evaluated == 1

    # Clear and restart engine
    engine.clear()
    assert engine.get_latest_result("root-exp") is None
    assert engine.correlator.active_root_count == 0


def test_out_of_order_and_duplicate_event_handling():
    """Engine processes out-of-order events safely without exceptions."""
    engine = DetectionEngine(auto_register_default_signals=True)

    now_utc = datetime.now(UTC)
    ordering_meta = EventOrderingMetadata(
        root_id="root-ooo",
        observed_at_utc=now_utc,
        observed_monotonic_ns=2_000_000_000,
        processed_at_utc=now_utc,
        processed_monotonic_ns=3_000_000_000,
        latency_ns=1_000_000_000,
        latency_ms=1000.0,
        is_out_of_order=True,
    )

    ev = _event(
        root_id="root-ooo",
        file_path="doc.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=2_000_000_000,
    )
    res = engine.process_event(ev, ordering=ordering_meta)

    assert res is not None
    assert res.total_events_evaluated == 1
