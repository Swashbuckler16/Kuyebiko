"""Edge-case reliability and benign workload validation tests (Step 4.8)."""

import time

from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import DetectionOutcome
from kuyebiko.detection.window import SlidingWindowCorrelator
from kuyebiko.models.events import EventSource, EventType, FileEvent, TelemetryQuality


def _make_event(
    root_id: str = "root-1",
    file_path: str = "doc.txt",
    event_type: EventType = EventType.MODIFIED,
    old_path: str | None = None,
    new_path: str | None = None,
    is_directory: bool = False,
    monotonic_ns: int | None = None,
    quality: TelemetryQuality = TelemetryQuality.NORMAL,
    correlation_provenance: str | None = None,
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
        kwargs["correlation_provenance"] = correlation_provenance or (
            f"rename_correlator:{kwargs['old_path']}->{kwargs['new_path']}"
        )
    return FileEvent(**kwargs)


def _build_standard_engine() -> DetectionEngine:
    correlator = SlidingWindowCorrelator(window_duration_seconds=10.0)
    return DetectionEngine(correlator=correlator, auto_register_default_signals=True)


def test_sliding_window_boundary_edge_cases():
    """Events arriving exactly at window boundary boundaries expire cleanly."""
    engine = _build_standard_engine()
    t_base = 50_000_000_000

    # Event 1 at t=50s
    e1 = _make_event(monotonic_ns=t_base, event_id="boundary_1")
    engine.process_event(e1)

    # Event 2 exactly at boundary: t + 10s - 1ns (should be retained)
    e2 = _make_event(monotonic_ns=t_base + 9_999_999_999, event_id="boundary_2")
    engine.process_event(e2)

    # Context at t=60s
    ctx = engine.correlator.get_context(
        "root-1", now_monotonic_ns=t_base + 9_999_999_999
    )
    assert ctx is not None
    assert len(ctx.events) == 2

    # Context at t=60s + 1ns: e1 (at 50s) expires, e2 remains
    ctx_after = engine.correlator.get_context(
        "root-1", now_monotonic_ns=t_base + 10_000_000_001
    )
    assert ctx_after is not None
    assert len(ctx_after.events) == 1
    assert ctx_after.events[0].event_id == "boundary_2"


def test_benign_workload_file_copying_no_severe_detection():
    """Bulk file copy operations (many CREATED) do not trigger false POSITIVE."""
    engine = _build_standard_engine()
    t = 10_000_000_000

    results = []
    # 30 new files copied into a folder
    for i in range(30):
        ev = _make_event(
            file_path=f"dest/copy_{i}.pdf",
            event_type=EventType.CREATED,
            monotonic_ns=t + i * 50_000_000,
            event_id=f"copy_{i}",
        )
        res = engine.process_event(ev)
        if res:
            results.append(res)

    last_res = results[-1] if results else None
    assert last_res is not None
    # Copying files does not contain transformation or destruction: not DETECTION
    assert last_res.outcome in (
        DetectionOutcome.NO_DETECTION,
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
    )
    assert last_res.outcome != DetectionOutcome.DETECTION


def test_benign_workload_software_installer():
    """Software installation (burst writes in folder) produces at most SUSPICIOUS."""
    engine = _build_standard_engine()
    t = 20_000_000_000

    results = []
    # Installer unpacking 25 files into program_files/app/
    extensions = [".exe", ".dll", ".dat", ".ini", ".sys"]
    for i in range(25):
        ext = extensions[i % len(extensions)]
        ev = _make_event(
            file_path=f"ProgramFiles/App/bin/lib_{i}{ext}",
            event_type=EventType.MODIFIED,
            monotonic_ns=t + i * 20_000_000,
            event_id=f"inst_{i}",
        )
        res = engine.process_event(ev)
        if res:
            results.append(res)

    last_res = results[-1]
    # May trigger burst write, but lacks file transformation or mass deletion:
    # Must NOT be classified as DETECTION
    assert last_res.outcome in (
        DetectionOutcome.NO_DETECTION,
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
    )
    assert last_res.outcome != DetectionOutcome.DETECTION


def test_benign_workload_large_scale_cleanup():
    """Deleting 30 temporary log files does not trigger ransomware DETECTION."""
    engine = _build_standard_engine()
    t = 30_000_000_000

    results = []
    for i in range(30):
        ev = _make_event(
            file_path=f"temp/cleanup_{i}.log",
            event_type=EventType.DELETED,
            monotonic_ns=t + i * 30_000_000,
            event_id=f"clean_{i}",
        )
        res = engine.process_event(ev)
        if res:
            results.append(res)

    last_res = results[-1]
    # Single-family deletion alone is not ransomware DETECTION
    assert last_res.outcome in (
        DetectionOutcome.NO_DETECTION,
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
    )
    assert last_res.outcome != DetectionOutcome.DETECTION


def test_benign_workload_bulk_refactoring_renames():
    """Renaming files during code refactor (.c -> .cpp) is not DETECTION."""
    engine = _build_standard_engine()
    t = 40_000_000_000

    results = []
    for i in range(20):
        ev = _make_event(
            file_path=f"src/module_{i}.cpp",
            event_type=EventType.RENAMED,
            old_path=f"src/module_{i}.c",
            new_path=f"src/module_{i}.cpp",
            monotonic_ns=t + i * 25_000_000,
            event_id=f"refactor_{i}",
        )
        res = engine.process_event(ev)
        if res:
            results.append(res)

    last_res = results[-1]
    # Rename alone without burst destruction or convergence is at most SUSPICIOUS
    assert last_res.outcome in (
        DetectionOutcome.NO_DETECTION,
        DetectionOutcome.SUSPICIOUS_ACTIVITY,
    )
    assert last_res.outcome != DetectionOutcome.DETECTION


def test_ransomware_multi_vector_attack_produces_detection_with_evidence():
    """Multi-vector attack (burst + traversal + convergence) produces DETECTION."""
    engine = _build_standard_engine()
    t = 50_000_000_000

    # 1. Traversal across 4 directories
    # 2. Burst write on each
    # 3. Extension convergence from (.docx, .pdf, .xlsx, .jpg) to .locked
    orig_exts = [".docx", ".pdf", ".xlsx", ".jpg"]
    results = []
    for i in range(20):
        orig_ext = orig_exts[i % len(orig_exts)]
        folder = f"dir_{i % 4}"
        # Rename from original to .locked
        ev = _make_event(
            file_path=f"{folder}/document_{i}.locked",
            event_type=EventType.RENAMED,
            old_path=f"{folder}/document_{i}{orig_ext}",
            new_path=f"{folder}/document_{i}.locked",
            monotonic_ns=t + i * 50_000_000,
            event_id=f"enc_{i}",
        )
        res = engine.process_event(ev)
        if res:
            results.append(res)

    last_res = results[-1]
    assert last_res.outcome == DetectionOutcome.DETECTION
    assert len(last_res.triggered_signal_families) >= 2
    # Verify evidence traceability across triggered signals
    all_evidence = [
        eid
        for sig in last_res.signal_results
        if sig.triggered
        for eid in sig.evidence_event_ids
    ]
    assert len(all_evidence) > 0
    assert "enc_19" in all_evidence


def test_multi_root_concurrency_isolation_under_load():
    """Five simultaneous roots process interleaved events without data crosstalk."""
    engine = _build_standard_engine()
    t = 60_000_000_000

    for i in range(25):
        for r_idx in range(5):
            root_id = f"drive-{r_idx}"
            ev = _make_event(
                root_id=root_id,
                file_path=f"file_{i}.txt",
                event_type=EventType.MODIFIED,
                monotonic_ns=t + (i * 5 + r_idx) * 10_000_000,
                event_id=f"r_{r_idx}_e_{i}",
            )
            engine.process_event(ev)

    assert engine.correlator.active_root_count == 5
    for r_idx in range(5):
        stats = engine.correlator.get_stats(f"drive-{r_idx}")
        assert stats is not None
        assert stats.total_events == 25
        assert stats.modified_count == 25
