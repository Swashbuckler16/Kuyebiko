"""Integration tests for the multi-signal correlation and explainability pipeline.

Covers all 12 required scenarios defined in Step 5.7.7:
1. One isolated weak signal.
2. Two overlapping signals using the same evidence.
3. Two independent signal families.
4. Three independent signal families.
5. Strong suspicious activity with degraded telemetry.
6. Strong suspicious activity with complete telemetry.
7. Benign bulk workload.
8. Recovery inhibition combined with destructive activity.
9. Low-and-slow transformation combined with extension convergence.
10. Evaluator failure during correlation.
11. Duplicate evidence UUIDs.
12. Empty or insufficient evidence.
"""

import time
from datetime import UTC, datetime
from typing import Any

from kuyebiko.detection.advanced.contracts import (
    DiscoveryTelemetryEvent,
    EventLogTelemetryEvent,
    ProcessTelemetryEvent,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.correlation.engine import CorrelationEngine
from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import (
    DetectionOutcome,
    SignalFamily,
    SignalResult,
    WindowAggregateStats,
)
from kuyebiko.detection.registry import SignalRegistry
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import (
    EventSource,
    EventType,
    FileEvent,
    TelemetryQuality,
)


class MockEvaluator(BaseSignalEvaluator):
    """Custom mock evaluator for precise scenario orchestration."""

    def __init__(
        self,
        signal_id: str,
        family: SignalFamily,
        should_trigger: bool,
        severity: float = 0.8,
        event_ids: list[str] | None = None,
        should_raise: bool = False,
    ) -> None:
        super().__init__(
            signal_id=signal_id,
            name=signal_id,
            family=family,
            threshold=5.0,
        )
        self._should_trigger = should_trigger
        self._severity = severity
        self._event_ids = event_ids or []
        self._should_raise = should_raise

    def evaluate(self, context: DetectionContext) -> SignalResult:
        if self._should_raise:
            raise RuntimeError(f"Simulated failure in {self.signal_id}")
        return SignalResult(
            signal_id=self.signal_id,
            signal_name=self.signal_id,
            family=self.family,
            triggered=self._should_trigger,
            severity_score=self._severity if self._should_trigger else 0.0,
            observed_metric=10.0 if self._should_trigger else 0.0,
            threshold=self.threshold,
            explanation=f"Mock evaluation for {self.signal_id}",
            evidence_event_ids=self._event_ids if self._should_trigger else [],
            evaluated_at_utc=datetime.now(UTC),
        )


def _seed_engine_with_event(
    engine: DetectionEngine, root_id: str = "root_test"
) -> None:
    event = FileEvent(
        event_id=f"seed_{time.monotonic_ns()}",
        root_id=root_id,
        file_path="seed.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=time.monotonic_ns(),
        source=EventSource.WINDOWS_WATCHER,
        quality=TelemetryQuality.NORMAL,
    )
    engine.process_event(event)


def _make_context(
    is_degraded: bool = False,
    uncounted_loss: bool = False,
    extra_config: dict[str, Any] | None = None,
) -> DetectionContext:
    now = datetime.now(UTC)
    return DetectionContext(
        root_id="root_test",
        events=[],
        stats=WindowAggregateStats(),
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=1_000_000_000,
        is_telemetry_degraded=is_degraded,
        degradation_reason="degradation_loss" if is_degraded else None,
        uncounted_kernel_loss=uncounted_loss,
        config=extra_config or {},
    )


def test_scenario_1_isolated_weak_signal() -> None:
    """Scenario 1: One isolated weak signal produces SUSPICIOUS_ACTIVITY."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_BURST_WRITE",
            SignalFamily.FILESYSTEM_ACTIVITY,
            True,
            severity=0.5,
            event_ids=["e1", "e2"],
        )
    )
    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY
    assert res.confidence_score <= 0.60
    assert res.severity_score == 0.5
    assert len(res.triggered_signal_ids) == 1


def test_scenario_2_two_overlapping_signals_shared_evidence() -> None:
    """Scenario 2: Two overlapping signals receive confidence discount."""
    shared = ["del_1", "del_2", "del_3", "del_4"]
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_DELETE_RATIO",
            SignalFamily.RENAME_DELETION,
            True,
            severity=0.7,
            event_ids=shared,
        )
    )
    registry.register(
        MockEvaluator(
            "FS_DATA_DESTRUCTION",
            SignalFamily.DATA_DESTRUCTION,
            True,
            severity=0.8,
            event_ids=shared,
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.metadata["shared_evidence_count"] == 4
    assert res.contributing_event_ids == shared


def test_scenario_3_two_independent_signal_families() -> None:
    """Scenario 3: Two independent signal families trigger DETECTION."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_BURST_WRITE",
            SignalFamily.FILESYSTEM_ACTIVITY,
            True,
            severity=0.7,
            event_ids=["w1", "w2"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_EXTENSION_CONVERGENCE",
            SignalFamily.FILE_TRANSFORMATION,
            True,
            severity=0.9,
            event_ids=["ext1", "ext2"],
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.DETECTION
    assert res.confidence_score >= 0.70
    assert len(res.triggered_signal_families) == 2


def test_scenario_4_three_independent_signal_families() -> None:
    """Scenario 4: Three independent signal families trigger definitive DETECTION."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_RENAME_RATIO",
            SignalFamily.RENAME_DELETION,
            True,
            severity=0.8,
            event_ids=["r1"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_DATA_DESTRUCTION",
            SignalFamily.DATA_DESTRUCTION,
            True,
            severity=0.85,
            event_ids=["d1"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_INDICATOR_REMOVAL",
            SignalFamily.INDICATOR_REMOVAL,
            True,
            severity=0.95,
            event_ids=["i1"],
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.DETECTION
    assert res.confidence_score >= 0.85
    assert len(res.triggered_signal_families) == 3


def test_scenario_5_strong_suspicious_activity_with_degraded_telemetry() -> None:
    """Scenario 5: Degraded telemetry discounts confidence."""
    correlator = CorrelationEngine()
    context = _make_context(is_degraded=True, uncounted_loss=True)

    sig1 = MockEvaluator(
        "FS_BURST_WRITE",
        SignalFamily.FILESYSTEM_ACTIVITY,
        True,
        severity=0.8,
        event_ids=["e1", "e2"],
    ).evaluate(context)
    sig2 = MockEvaluator(
        "FS_DIRECTORY_TRAVERSAL",
        SignalFamily.DIRECTORY_TRAVERSAL,
        True,
        severity=0.7,
        event_ids=["e3"],
    ).evaluate(context)

    outcome, conf, sev, cov, comp, evidence, exp = correlator.evaluate_correlation(
        context=context, signal_results=[sig1, sig2]
    )

    assert conf < 0.55  # Degraded penalty applied
    assert outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY
    assert "telemetry degradation" in exp.to_markdown()


def test_scenario_6_strong_suspicious_activity_with_complete_telemetry() -> None:
    """Scenario 6: Complete telemetry yields high confidence."""
    correlator = CorrelationEngine()
    now_utc = datetime.now(UTC)
    context = _make_context(
        is_degraded=False,
        extra_config={
            "process_events": [
                ProcessTelemetryEvent(
                    event_id="proc_1",
                    root_id="root_test",
                    monotonic_ns=1_000_000_000,
                    process_id=123,
                    process_name="vssadmin.exe",
                    command_line="vssadmin delete shadows",
                    timestamp_utc=now_utc,
                )
            ],
            "event_log_events": [
                EventLogTelemetryEvent(
                    event_id="ev_1",
                    root_id="root_test",
                    monotonic_ns=1_000_000_000,
                    provider_name="Microsoft-Windows-Security-Auditing",
                    channel="Security",
                    event_code=1102,
                    timestamp_utc=now_utc,
                )
            ],
            "discovery_events": [
                DiscoveryTelemetryEvent(
                    event_id="disc_1",
                    root_id="root_test",
                    monotonic_ns=1_000_000_000,
                    target_directory="C:\\Users",
                    timestamp_utc=now_utc,
                )
            ],
        },
    )

    sig1 = MockEvaluator(
        "FS_RECOVERY_INHIBITION",
        SignalFamily.RECOVERY_INTERFERENCE,
        True,
        severity=0.9,
        event_ids=["vss1"],
    ).evaluate(context)
    sig2 = MockEvaluator(
        "FS_DATA_DESTRUCTION",
        SignalFamily.DATA_DESTRUCTION,
        True,
        severity=0.9,
        event_ids=["des1"],
    ).evaluate(context)

    outcome, conf, sev, cov, comp, evidence, exp = correlator.evaluate_correlation(
        context=context, signal_results=[sig1, sig2]
    )

    assert outcome == DetectionOutcome.DETECTION
    assert cov == 1.0  # All capabilities present
    assert conf >= 0.75
    assert not exp.missing_capabilities


def test_scenario_7_benign_bulk_workload() -> None:
    """Scenario 7: Benign bulk workload does not trigger ransomware detection."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_BURST_WRITE",
            SignalFamily.FILESYSTEM_ACTIVITY,
            True,
            severity=0.6,
            event_ids=["b1", "b2"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_DIRECTORY_TRAVERSAL",
            SignalFamily.DIRECTORY_TRAVERSAL,
            True,
            severity=0.5,
            event_ids=["t1"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_EXTENSION_CONVERGENCE",
            SignalFamily.FILE_TRANSFORMATION,
            False,
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    # Burst + Traversal alone is classified as SUSPICIOUS, never confirmed DETECTION
    assert res.outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY


def test_scenario_8_recovery_inhibition_combined_with_destruction() -> None:
    """Scenario 8: Recovery inhibition + mass destruction triggers DETECTION."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_RECOVERY_INHIBITION",
            SignalFamily.RECOVERY_INTERFERENCE,
            True,
            severity=0.95,
            event_ids=["rec_1"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_DATA_DESTRUCTION",
            SignalFamily.DATA_DESTRUCTION,
            True,
            severity=0.90,
            event_ids=["del_1", "del_2"],
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.DETECTION
    assert res.severity_score >= 0.95


def test_scenario_9_low_and_slow_combined_with_extension_convergence() -> None:
    """Scenario 9: Low-and-slow plus extension convergence yields DETECTION."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_LOW_AND_SLOW_ACTIVITY",
            SignalFamily.FILE_TRANSFORMATION,
            True,
            severity=0.85,
            event_ids=["slow_1", "slow_2"],
        )
    )
    registry.register(
        MockEvaluator(
            "FS_EXTENSION_CONVERGENCE",
            SignalFamily.FILE_TRANSFORMATION,
            True,
            severity=0.90,
            event_ids=["ext_1", "ext_2"],
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.DETECTION


def test_scenario_10_evaluator_failure_during_correlation() -> None:
    """Scenario 10: Evaluator exception yields EVALUATION_ERROR."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_CRASHING_SIGNAL",
            SignalFamily.FILESYSTEM_ACTIVITY,
            True,
            should_raise=True,
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.EVALUATION_ERROR
    assert len(res.evaluation_errors) > 0
    assert "Simulated failure" in res.evaluation_errors[0]


def test_scenario_11_duplicate_evidence_uuids() -> None:
    """Scenario 11: Duplicate event UUIDs are deduplicated without double-counting."""
    registry = SignalRegistry()
    dup_ids = ["evt_dup_1", "evt_dup_1", "evt_dup_1"]
    registry.register(
        MockEvaluator(
            "FS_BURST_WRITE",
            SignalFamily.FILESYSTEM_ACTIVITY,
            True,
            severity=0.6,
            event_ids=dup_ids,
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.contributing_event_ids == ["evt_dup_1"]
    assert res.metadata["unique_evidence_count"] == 1


def test_scenario_12_empty_or_insufficient_evidence() -> None:
    """Scenario 12: Triggered signal with no evidence handled safely."""
    registry = SignalRegistry()
    registry.register(
        MockEvaluator(
            "FS_BURST_WRITE",
            SignalFamily.FILESYSTEM_ACTIVITY,
            True,
            severity=0.6,
            event_ids=[],  # Empty evidence
        )
    )

    engine = DetectionEngine(registry=registry, auto_register_default_signals=False)
    _seed_engine_with_event(engine)
    res = engine.evaluate_root("root_test")

    assert res.outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY
    assert res.evidence_completeness == 0.0
    assert res.contributing_event_ids == []
