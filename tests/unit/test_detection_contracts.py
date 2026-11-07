"""Unit tests for detection architecture models, contracts, and base evaluators."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.contracts import SignalEvaluator
from kuyebiko.detection.models import (
    DetectionOutcome,
    DetectionResult,
    SignalFamily,
    SignalResult,
    WindowAggregateStats,
)
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventSource, EventType, FileEvent, TelemetryQuality


def _sample_file_event(
    event_id: str = "evt-1",
    root_id: str = "root-1",
    file_path: str = "doc.txt",
    event_type: EventType = EventType.MODIFIED,
    monotonic_ns: int = 1_000_000,
) -> FileEvent:
    return FileEvent(
        event_id=event_id,
        root_id=root_id,
        file_path=file_path,
        event_type=event_type,
        monotonic_ns=monotonic_ns,
        source=EventSource.WINDOWS_WATCHER,
    )


class ConcreteEvaluator(BaseSignalEvaluator):
    def evaluate(self, context: DetectionContext) -> SignalResult:
        triggered = len(context.events) >= self.min_events
        return self._create_result(
            triggered=triggered,
            observed_metric=float(len(context.events)),
            explanation=f"Evaluated {len(context.events)} events",
            severity_score=0.75 if triggered else 0.0,
            evidence_event_ids=[e.event_id for e in context.events],
        )


def test_signal_family_and_outcome_enum_values():
    assert SignalFamily.FILESYSTEM_ACTIVITY == "filesystem_activity"
    assert SignalFamily.RENAME_DELETION == "rename_deletion"
    assert SignalFamily.DIRECTORY_TRAVERSAL == "directory_traversal"
    assert SignalFamily.FILE_TRANSFORMATION == "file_transformation"
    assert SignalFamily.RECOVERY_INTERFERENCE == "recovery_interference"
    assert SignalFamily.CANARY_INTERACTION == "canary_interaction"
    assert SignalFamily.PROCESS_ATTRIBUTION == "process_attribution"

    assert DetectionOutcome.NO_DETECTION == "no_detection"
    assert DetectionOutcome.SUSPICIOUS_ACTIVITY == "suspicious_activity"
    assert DetectionOutcome.DETECTION == "detection"
    assert DetectionOutcome.INSUFFICIENT_TELEMETRY == "insufficient_telemetry"
    assert DetectionOutcome.EVALUATION_ERROR == "evaluation_error"


def test_signal_result_creation_and_immutability():
    res = SignalResult(
        signal_id="SIG_TEST",
        signal_name="Test Signal",
        family=SignalFamily.FILESYSTEM_ACTIVITY,
        triggered=True,
        severity_score=0.8,
        observed_metric=10.0,
        threshold=5.0,
        explanation="Threshold exceeded",
        evidence_event_ids=["evt-1"],
    )

    assert res.signal_id == "SIG_TEST"
    assert res.triggered is True
    assert res.severity_score == 0.8
    assert res.evidence_event_ids == ["evt-1"]

    with pytest.raises(ValidationError):
        res.triggered = False  # frozen model


def test_signal_result_timezone_validation():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    with pytest.raises(ValidationError, match="timezone-aware"):
        SignalResult(
            signal_id="SIG_TEST",
            signal_name="Test",
            family=SignalFamily.FILESYSTEM_ACTIVITY,
            triggered=False,
            observed_metric=0.0,
            threshold=1.0,
            explanation="None",
            evaluated_at_utc=naive,
        )


def test_window_aggregate_stats_defaults_and_immutability():
    stats = WindowAggregateStats(
        total_events=5,
        modified_count=5,
        unique_extensions=[".txt"],
        unique_directories=["docs"],
        unique_relative_paths=["docs/a.txt"],
        events_per_second=2.5,
        window_duration_seconds=2.0,
    )

    assert stats.total_events == 5
    assert stats.modified_count == 5
    assert stats.unique_extensions == [".txt"]

    with pytest.raises(ValidationError):
        stats.total_events = 10


def test_detection_context_creation_and_immutability():
    event = _sample_file_event()
    now = datetime.now(UTC)
    stats = WindowAggregateStats(total_events=1, modified_count=1)

    ctx = DetectionContext(
        root_id="root-1",
        events=[event],
        stats=stats,
        evaluated_monotonic_ns=100_000_000,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
        quality=TelemetryQuality.NORMAL,
    )

    assert ctx.root_id == "root-1"
    assert len(ctx.events) == 1
    assert ctx.stats.total_events == 1
    assert ctx.is_telemetry_degraded is False

    with pytest.raises(ValidationError):
        ctx.root_id = "root-2"


def test_detection_result_model():
    now = datetime.now(UTC)
    sig_res = SignalResult(
        signal_id="SIG_BURST",
        signal_name="Burst",
        family=SignalFamily.FILESYSTEM_ACTIVITY,
        triggered=True,
        observed_metric=15.0,
        threshold=10.0,
        explanation="Burst detected",
        evidence_event_ids=["evt-1"],
    )

    det = DetectionResult(
        root_id="root-1",
        outcome=DetectionOutcome.SUSPICIOUS_ACTIVITY,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
        total_events_evaluated=1,
        signal_results=[sig_res],
        triggered_signal_ids=["SIG_BURST"],
        triggered_signal_families=[SignalFamily.FILESYSTEM_ACTIVITY],
    )

    assert det.root_id == "root-1"
    assert det.outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY
    assert len(det.signal_results) == 1
    assert det.triggered_signal_ids == ["SIG_BURST"]


def test_base_signal_evaluator_subclass_and_protocol():
    evaluator = ConcreteEvaluator(
        signal_id="CONCRETE_SIG",
        name="Concrete Evaluator",
        family=SignalFamily.FILESYSTEM_ACTIVITY,
        threshold=2.0,
        min_events=2,
    )

    assert isinstance(evaluator, SignalEvaluator)
    assert evaluator.signal_id == "CONCRETE_SIG"
    assert evaluator.name == "Concrete Evaluator"
    assert evaluator.family == SignalFamily.FILESYSTEM_ACTIVITY
    assert evaluator.threshold == 2.0
    assert evaluator.is_enabled is True

    # Mutability of threshold and enabled status
    evaluator.threshold = 5.0
    assert evaluator.threshold == 5.0
    evaluator.is_enabled = False
    assert evaluator.is_enabled is False

    with pytest.raises(ValueError):
        evaluator.threshold = -1.0

    with pytest.raises(ValueError):
        evaluator.min_events = -1


def test_concrete_evaluator_execution():
    evaluator = ConcreteEvaluator(
        signal_id="CONCRETE_SIG",
        name="Concrete Evaluator",
        family=SignalFamily.FILESYSTEM_ACTIVITY,
        threshold=2.0,
        min_events=2,
    )

    now = datetime.now(UTC)
    events = [_sample_file_event(event_id=f"e-{i}") for i in range(2)]
    stats = WindowAggregateStats(total_events=2, modified_count=2)
    ctx = DetectionContext(
        root_id="root-1",
        events=events,
        stats=stats,
        evaluated_monotonic_ns=100,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.observed_metric == 2.0
    assert len(res.evidence_event_ids) == 2
