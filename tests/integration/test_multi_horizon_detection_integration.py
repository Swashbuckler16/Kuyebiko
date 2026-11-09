"""Integration tests for Step 5.6: Multi-Horizon & Behaviour Detection Engine."""

from uuid import uuid4

from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import DetectionOutcome, DetectionResult
from kuyebiko.detection.multi_horizon import MultiHorizonSlidingWindow
from kuyebiko.models.events import EventSource, EventType, FileEvent


def _make_event(
    file_path: str,
    monotonic_ns: int,
    root_id: str = "root-1",
    event_type: EventType = EventType.MODIFIED,
) -> FileEvent:
    return FileEvent(
        event_id=str(uuid4()),
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        monotonic_ns=monotonic_ns,
        source=EventSource.WINDOWS_WATCHER,
    )


def test_engine_with_multi_horizon_correlator_and_advanced_signals():
    """Engine ingests events into MultiHorizonSlidingWindow and runs signals."""
    correlator = MultiHorizonSlidingWindow(
        horizons={"short": 10.0, "medium": 60.0, "long": 300.0}
    )
    engine = DetectionEngine(correlator=correlator, auto_register_default_signals=True)
    engine.register_advanced_signals()

    # Ensure all 11 signals are registered (5 foundational + 6 advanced)
    registered_ids = engine.registry.list_signal_ids()
    assert "FS_IN_PLACE_TRANSFORMATION" in registered_ids
    assert "FS_LOW_AND_SLOW_ACTIVITY" in registered_ids
    assert "FS_BURST_WRITE" in registered_ids
    assert "FS_RECOVERY_INHIBITION" in registered_ids
    assert len(registered_ids) == 11

    results_captured: list[DetectionResult] = []
    engine.add_listener(lambda r: results_captured.append(r))

    base_ns = 10_000_000_000
    dirs = ["Accounting", "Legal", "Operations", "Research"]

    # Stream 20 in-place modification events across 4 directories
    last_res = None
    for i in range(20):
        ev = _make_event(
            f"{dirs[i % len(dirs)]}/file_{i}.docx",
            monotonic_ns=base_ns + i * 200_000_000,
            root_id="root-1",
        )
        last_res = engine.process_event(ev, now_monotonic_ns=base_ns + i * 200_000_000)

    assert last_res is not None
    # FS_IN_PLACE_TRANSFORMATION should trigger
    triggered_signals = [s.signal_id for s in last_res.signal_results if s.triggered]
    assert "FS_IN_PLACE_TRANSFORMATION" in triggered_signals
    assert last_res.outcome in (
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
        DetectionOutcome.DETECTION,
    )
    assert len(results_captured) == 20
