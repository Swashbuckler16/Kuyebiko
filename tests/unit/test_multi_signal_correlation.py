"""Unit tests for the behavioural Multi-Signal Correlation Engine."""

from datetime import UTC, datetime

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.correlation.engine import CorrelationEngine
from kuyebiko.detection.models import (
    DetectionOutcome,
    SignalFamily,
    SignalResult,
    WindowAggregateStats,
)


def _make_dummy_context(is_degraded: bool = False) -> DetectionContext:
    now = datetime.now(UTC)
    return DetectionContext(
        root_id="root_1",
        events=[],
        stats=WindowAggregateStats(),
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
        evaluated_monotonic_ns=1_000_000_000,
        is_telemetry_degraded=is_degraded,
        degradation_reason="buffer_overflow" if is_degraded else None,
        uncounted_kernel_loss=is_degraded,
        config={},
    )


def _make_signal_result(
    signal_id: str,
    family: SignalFamily,
    triggered: bool,
    severity: float = 0.8,
    event_ids: list[str] | None = None,
) -> SignalResult:
    return SignalResult(
        signal_id=signal_id,
        signal_name=signal_id,
        family=family,
        triggered=triggered,
        severity_score=severity if triggered else 0.0,
        observed_metric=10.0 if triggered else 0.0,
        threshold=5.0,
        explanation=f"Signal {signal_id} explanation",
        evidence_event_ids=event_ids or [],
        evaluated_at_utc=datetime.now(UTC),
    )


def test_correlation_engine_no_signals() -> None:
    """Verify clean context with zero triggered signals yields NO_DETECTION."""
    engine = CorrelationEngine()
    context = _make_dummy_context(is_degraded=False)
    outcome, conf, sev, cov, comp, evidence, explanation = engine.evaluate_correlation(
        context=context, signal_results=[]
    )

    assert outcome == DetectionOutcome.NO_DETECTION
    assert conf == 0.0
    assert sev == 0.0
    assert cov == 0.25  # Only filesystem metadata present
    assert comp == 1.0
    assert explanation.outcome == DetectionOutcome.NO_DETECTION


def test_correlation_engine_isolated_signal() -> None:
    """Verify single triggered signal yields SUSPICIOUS_ACTIVITY, not DETECTION."""
    engine = CorrelationEngine()
    context = _make_dummy_context(is_degraded=False)
    sig = _make_signal_result(
        "FS_BURST_WRITE",
        SignalFamily.FILESYSTEM_ACTIVITY,
        True,
        severity=0.6,
        event_ids=["e1", "e2"],
    )

    outcome, conf, sev, cov, comp, evidence, explanation = engine.evaluate_correlation(
        context=context, signal_results=[sig]
    )

    assert outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY
    assert conf < 0.65
    assert sev == 0.6
    assert evidence.total_unique_events == 2


def test_correlation_engine_overlapping_signals_discount() -> None:
    """Verify overlapping signals sharing evidence receive confidence discount."""
    engine = CorrelationEngine()
    context = _make_dummy_context(is_degraded=False)

    # DELETE_RATIO and DATA_DESTRUCTION sharing 100% of event IDs
    shared_events = ["e1", "e2", "e3", "e4", "e5"]
    sig1 = _make_signal_result(
        "FS_DELETE_RATIO",
        SignalFamily.RENAME_DELETION,
        True,
        severity=0.7,
        event_ids=shared_events,
    )
    sig2 = _make_signal_result(
        "FS_DATA_DESTRUCTION",
        SignalFamily.DATA_DESTRUCTION,
        True,
        severity=0.8,
        event_ids=shared_events,
    )

    outcome, conf, sev, cov, comp, evidence, explanation = engine.evaluate_correlation(
        context=context, signal_results=[sig1, sig2]
    )

    # 2 signals triggered sharing 100% of evidence in destruction category
    assert len(evidence.shared_event_ids) == 5
    # Overlapping evidence discounts confidence
    assert len(explanation.overlapping_signal_pairs) >= 1


def test_correlation_engine_three_independent_families_detection() -> None:
    """Verify 3 independent families trigger confirmed DETECTION."""
    engine = CorrelationEngine()
    context = _make_dummy_context(is_degraded=False)

    sig1 = _make_signal_result(
        "FS_RENAME_RATIO",
        SignalFamily.RENAME_DELETION,
        True,
        severity=0.8,
        event_ids=["e1", "e2"],
    )
    sig2 = _make_signal_result(
        "FS_DATA_DESTRUCTION",
        SignalFamily.DATA_DESTRUCTION,
        True,
        severity=0.9,
        event_ids=["e3", "e4"],
    )
    sig3 = _make_signal_result(
        "FS_INDICATOR_REMOVAL",
        SignalFamily.INDICATOR_REMOVAL,
        True,
        severity=0.95,
        event_ids=["e5"],
    )

    outcome, conf, sev, cov, comp, evidence, explanation = engine.evaluate_correlation(
        context=context, signal_results=[sig1, sig2, sig3]
    )

    assert outcome == DetectionOutcome.DETECTION
    assert conf >= 0.85
    assert sev >= 0.95
    assert len(explanation.independent_families) == 3
