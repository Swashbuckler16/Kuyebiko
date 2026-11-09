"""Unit tests for Step 5.1: Advanced Detection Architecture & Contracts."""

import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from kuyebiko.detection.advanced import (
    AdvancedSignalEvaluator,
    DiscoveryTelemetryEvent,
    EventLogTelemetryEvent,
    ProcessTelemetryEvent,
    SignalMetadata,
    TelemetryCapability,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult, WindowAggregateStats
from kuyebiko.detection.registry import SignalRegistry
from kuyebiko.models.events import EventSource, EventType, FileEvent


class _MockAdvancedEvaluator(AdvancedSignalEvaluator):
    """Concrete evaluator for testing AdvancedSignalEvaluator contract."""

    def __init__(
        self,
        required_caps: list[TelemetryCapability] | None = None,
        should_trigger: bool = True,
    ) -> None:
        meta = SignalMetadata(
            signal_id="ADV_TEST_SIGNAL",
            name="Advanced Test Signal",
            family=SignalFamily.RECOVERY_INTERFERENCE,
            mitre_technique="T0000",
            description="Test signal for capability checking",
            required_capabilities=required_caps
            or [TelemetryCapability.FILESYSTEM_METADATA],
            evidence_requirements="Mock requirements",
            confidence_limitations="Mock limitations",
            threshold=1.0,
            default_threshold=1.0,
            min_events=1,
        )
        super().__init__(metadata=meta)
        self.should_trigger = should_trigger

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        return self._create_result(
            triggered=self.should_trigger,
            observed_metric=1.0 if self.should_trigger else 0.0,
            explanation="Mock advanced evaluation executed",
            severity_score=0.75 if self.should_trigger else 0.0,
        )


def _make_context(
    available_capabilities: set[TelemetryCapability] | None = None,
) -> DetectionContext:
    now = datetime.now(UTC)
    config = {}
    if available_capabilities is not None:
        config["available_capabilities"] = available_capabilities

    stats = WindowAggregateStats(
        total_events=1,
        created_count=0,
        modified_count=1,
        deleted_count=0,
        renamed_count=0,
        directory_operations_count=0,
        unique_extensions=[".txt"],
        unique_directories=["dir"],
        unique_relative_paths=["dir/file.txt"],
        rename_pairs_count=0,
        events_per_second=1.0,
        window_duration_seconds=10.0,
    )

    ev = FileEvent(
        event_id=str(uuid4()),
        root_id="root-1",
        file_path="dir/file.txt",
        event_type=EventType.MODIFIED,
        monotonic_ns=time.monotonic_ns(),
        source=EventSource.WINDOWS_WATCHER,
    )

    return DetectionContext(
        root_id="root-1",
        events=[ev],
        stats=stats,
        evaluated_monotonic_ns=time.monotonic_ns(),
        window_start_utc=now,
        window_end_utc=now,
        window_duration_seconds=10.0,
        config=config,
    )


def test_signal_metadata_validation():
    """Verify SignalMetadata requires valid fields and is immutable."""
    meta = SignalMetadata(
        signal_id="SIG_META_TEST",
        name="Meta Test",
        family=SignalFamily.DATA_DESTRUCTION,
        mitre_technique="T1485",
        description="Testing metadata",
        required_capabilities=[TelemetryCapability.FILESYSTEM_METADATA],
        evidence_requirements="Requirements",
        confidence_limitations="Limitations",
        threshold=0.5,
        default_threshold=0.5,
    )
    assert meta.signal_id == "SIG_META_TEST"
    assert meta.family == SignalFamily.DATA_DESTRUCTION
    assert meta.mitre_technique == "T1485"

    with pytest.raises(ValidationError):
        # Immutable
        meta.threshold = 0.8  # type: ignore


def test_advanced_evaluator_satisfied_capabilities():
    """When required capabilities are satisfied, evaluate_advanced is invoked."""
    evaluator = _MockAdvancedEvaluator(
        required_caps=[TelemetryCapability.FILESYSTEM_METADATA]
    )
    ctx = _make_context(
        available_capabilities={TelemetryCapability.FILESYSTEM_METADATA}
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is True
    assert res.severity_score == 0.75
    assert "Mock advanced evaluation executed" in res.explanation
    assert "capability_limitation" not in res.metadata


def test_advanced_evaluator_missing_capabilities():
    """Missing required capability returns un-triggered with limitation metadata."""
    evaluator = _MockAdvancedEvaluator(
        required_caps=[
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.PROCESS_EXECUTION,
        ]
    )
    # Context only provides FILESYSTEM_METADATA
    ctx = _make_context(
        available_capabilities={TelemetryCapability.FILESYSTEM_METADATA}
    )

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.severity_score == 0.0
    assert "cannot be evaluated" in res.explanation
    assert (
        "Missing required telemetry capabilities"
        in res.metadata["capability_limitation"]
    )
    assert "process_execution" in res.metadata["missing_capabilities"]


def test_advanced_evaluator_disabled():
    """When evaluator is disabled, returns non-triggered disabled result."""
    evaluator = _MockAdvancedEvaluator()
    evaluator.is_enabled = False
    ctx = _make_context()

    res = evaluator.evaluate(ctx)
    assert res.triggered is False
    assert res.metadata["disabled"] is True


def test_registry_exception_isolation():
    """Registry isolates exceptions raised by faulty advanced evaluators."""
    registry = SignalRegistry()

    class _FaultyEvaluator(AdvancedSignalEvaluator):
        def __init__(self) -> None:
            meta = SignalMetadata(
                signal_id="FAULTY_SIG",
                name="Faulty Signal",
                family=SignalFamily.RECOVERY_INTERFERENCE,
                description="Raises error",
                evidence_requirements="None",
                confidence_limitations="None",
                threshold=1.0,
                default_threshold=1.0,
            )
            super().__init__(metadata=meta)

        def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
            raise RuntimeError("Hardware sensor failure simulation")

    registry.register(_FaultyEvaluator())
    ctx = _make_context()

    results, errors = registry.evaluate_all(ctx)
    assert len(results) == 1
    assert results[0].triggered is False
    assert len(errors) == 1
    assert "Hardware sensor failure simulation" in errors[0]


def test_telemetry_event_models():
    """Verify non-filesystem telemetry event models serialize and validate cleanly."""
    proc = ProcessTelemetryEvent(
        root_id="r1",
        process_id=1234,
        process_name="vssadmin.exe",
        command_line="vssadmin delete shadows /all",
        monotonic_ns=100_000,
    )
    assert proc.process_name == "vssadmin.exe"

    ev_log = EventLogTelemetryEvent(
        root_id="r1",
        provider_name="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_code=1102,
        monotonic_ns=200_000,
    )
    assert ev_log.event_code == 1102

    disc = DiscoveryTelemetryEvent(
        root_id="r1",
        target_directory="C:/Users/Administrator/Documents",
        operation="enumerate",
        process_id=5678,
        process_name="cmd.exe",
        monotonic_ns=300_000,
    )
    assert disc.operation == "enumerate"
