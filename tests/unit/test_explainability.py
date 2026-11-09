"""Unit tests for the explainability engine."""

from kuyebiko.detection.correlation.evidence import DeduplicatedEvidence
from kuyebiko.detection.correlation.explainability import (
    DetectionExplanation,
    ExplainabilityEngine,
)
from kuyebiko.detection.models import DetectionOutcome


def test_explainability_markdown_generation() -> None:
    """Verify DetectionExplanation renders clean, formatted markdown."""
    exp = DetectionExplanation(
        summary="Ransomware behaviour detected across 2 independent families",
        outcome=DetectionOutcome.DETECTION,
        confidence_score=0.85,
        confidence_rationale="High confidence from independent corroboration",
        severity_score=0.9,
        severity_rationale="Mass transformation and destruction observed",
        telemetry_coverage=0.75,
        telemetry_state={
            "filesystem_metadata": "clean",
            "process_execution": "unavailable",
        },
        missing_capabilities=["process_execution"],
        known_uncertainties=["Missing auxiliary telemetry: process_execution."],
        triggered_signals=["FS_BURST_WRITE", "FS_EXTENSION_CONVERGENCE"],
        independent_families=["filesystem_activity", "file_transformation"],
        independent_categories=["activity_volume", "transformation"],
        contributing_event_ids=["evt1", "evt2"],
        shared_evidence_count=0,
        unique_evidence_count=2,
        overlapping_signal_pairs=[],
        classification_rationale="Meets multi-family detection criteria.",
    )

    md = exp.to_markdown()
    assert "### Detection Outcome: **DETECTION**" in md
    assert "**Severity:** 0.90" in md
    assert "**Confidence:** 0.85" in md
    assert "`FS_BURST_WRITE`" in md
    assert "`FS_EXTENSION_CONVERGENCE`" in md
    assert "Missing auxiliary telemetry: process_execution." in md


def test_explainability_engine_clean_state() -> None:
    """Verify explainability engine produces correct explanation for clean state."""
    engine = ExplainabilityEngine()
    evidence = DeduplicatedEvidence(
        unique_event_ids=[],
        total_unique_events=0,
        signal_to_events={},
        event_to_signals={},
        shared_event_ids=[],
        independent_event_ids=[],
        overlap_matrix={},
        evidence_completeness=1.0,
    )

    exp = engine.generate_explanation(
        outcome=DetectionOutcome.NO_DETECTION,
        signal_results=[],
        evidence=evidence,
        confidence_score=0.0,
        severity_score=0.0,
        telemetry_coverage=1.0,
        is_telemetry_degraded=False,
        degradation_reasons=[],
        missing_capabilities=[],
    )

    assert exp.outcome == DetectionOutcome.NO_DETECTION
    assert "Normal filesystem behaviour" in exp.summary
    assert exp.unique_evidence_count == 0
