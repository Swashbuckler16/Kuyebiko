"""Unit tests for SignalRegistry, dynamic configuration, and evaluation isolation."""

from datetime import UTC, datetime

import pytest

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import (
    SignalFamily,
    SignalResult,
    WindowAggregateStats,
)
from kuyebiko.detection.registry import SignalRegistry
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventSource, EventType, FileEvent


class DummyEvaluator(BaseSignalEvaluator):
    def __init__(
        self,
        signal_id: str = "DUMMY_SIG",
        name: str = "Dummy",
        threshold: float = 5.0,
        should_raise: bool = False,
    ) -> None:
        super().__init__(
            signal_id=signal_id,
            name=name,
            family=SignalFamily.FILESYSTEM_ACTIVITY,
            threshold=threshold,
        )
        self.should_raise = should_raise

    def evaluate(self, context: DetectionContext) -> SignalResult:
        if self.should_raise:
            raise RuntimeError("Simulated evaluator crash")
        triggered = len(context.events) >= self.threshold
        return self._create_result(
            triggered=triggered,
            observed_metric=float(len(context.events)),
            explanation=f"Observed {len(context.events)} events",
            severity_score=0.5 if triggered else 0.0,
            evidence_event_ids=[e.event_id for e in context.events],
        )


def _make_context(event_count: int = 3) -> DetectionContext:
    events = [
        FileEvent(
            event_id=f"e_{i}",
            root_id="root-1",
            file_path=f"file_{i}.txt",
            event_type=EventType.MODIFIED,
            monotonic_ns=1_000_000_000,
            source=EventSource.WINDOWS_WATCHER,
        )
        for i in range(event_count)
    ]
    now = datetime.now(UTC)
    return DetectionContext(
        root_id="root-1",
        events=events,
        stats=WindowAggregateStats(
            total_events=event_count, modified_count=event_count
        ),
        evaluated_monotonic_ns=1_000_000_000,
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
    )


def test_registry_register_and_retrieve():
    registry = SignalRegistry()
    evaluator = DummyEvaluator(signal_id="SIG_1", name="Signal 1")

    registry.register(evaluator)
    assert registry.get("SIG_1") is evaluator
    assert registry.list_signal_ids() == ["SIG_1"]
    assert len(registry.list_evaluators()) == 1


def test_registry_duplicate_registration_rejected():
    registry = SignalRegistry()
    e1 = DummyEvaluator(signal_id="SIG_DUP")
    e2 = DummyEvaluator(signal_id="SIG_DUP")

    registry.register(e1)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(e2)


def test_registry_unregister():
    registry = SignalRegistry()
    e1 = DummyEvaluator(signal_id="SIG_1")
    registry.register(e1)
    assert registry.unregister("SIG_1") is True
    assert registry.get("SIG_1") is None
    assert registry.unregister("SIG_1") is False


def test_registry_set_enabled_and_threshold():
    registry = SignalRegistry()
    e1 = DummyEvaluator(signal_id="SIG_1", threshold=5.0)
    registry.register(e1)

    registry.set_threshold("SIG_1", 10.0)
    assert e1.threshold == 10.0

    registry.set_enabled("SIG_1", False)
    assert e1.is_enabled is False

    with pytest.raises(KeyError):
        registry.set_enabled("NON_EXISTENT", True)

    with pytest.raises(ValueError):
        registry.set_threshold("SIG_1", -1.0)


def test_registry_evaluation_isolation_on_evaluator_exception():
    registry = SignalRegistry()
    good_eval = DummyEvaluator(signal_id="GOOD_SIG", threshold=2.0)
    faulty_eval = DummyEvaluator(signal_id="FAULTY_SIG", should_raise=True)

    registry.register(good_eval)
    registry.register(faulty_eval)

    ctx = _make_context(event_count=3)
    results, errors = registry.evaluate_all(ctx)

    # Both evaluators produced a result (faulty produced a structured failure result)
    assert len(results) == 2
    assert len(errors) == 1
    assert "FAULTY_SIG" in errors[0]
    assert registry.get_failure_count("FAULTY_SIG") == 1

    good_res = next(r for r in results if r.signal_id == "GOOD_SIG")
    faulty_res = next(r for r in results if r.signal_id == "FAULTY_SIG")

    assert good_res.triggered is True
    assert faulty_res.triggered is False
    assert "Evaluation failed" in faulty_res.explanation


def test_registry_evaluate_all_target_signals_and_disabled():
    registry = SignalRegistry()
    e1 = DummyEvaluator(signal_id="SIG_1", threshold=2.0)
    e2 = DummyEvaluator(signal_id="SIG_2", threshold=2.0)

    registry.register(e1)
    registry.register(e2)

    ctx = _make_context(event_count=3)

    # Filter target_signals
    res1, _ = registry.evaluate_all(ctx, target_signals=["SIG_1"])
    assert len(res1) == 1
    assert res1[0].signal_id == "SIG_1"

    # Disable e1
    registry.set_enabled("SIG_1", False)
    res2, _ = registry.evaluate_all(ctx)
    assert len(res2) == 1
    assert res2[0].signal_id == "SIG_2"


def test_registry_clear():
    registry = SignalRegistry()
    registry.register(DummyEvaluator(signal_id="S1"))
    registry.clear()
    assert len(registry.list_evaluators()) == 0
