"""Multi-signal correlation engine for behavioural ransomware detection.

Synthesizes foundational and advanced behavioural signals into deterministic
detection outcomes, separating severity, confidence, coverage, and completeness.
"""

from collections.abc import Sequence

from kuyebiko.detection.advanced.contracts import TelemetryCapability
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.correlation.evidence import (
    DeduplicatedEvidence,
    deduplicate_evidence,
)
from kuyebiko.detection.correlation.explainability import (
    DetectionExplanation,
    ExplainabilityEngine,
)
from kuyebiko.detection.correlation.relationships import (
    BehaviourCategory,
    SignalRelationshipModel,
)
from kuyebiko.detection.models import (
    DetectionOutcome,
    SignalFamily,
    SignalResult,
)


class CorrelationEngine:
    """Deterministic multi-signal correlation engine with explainability."""

    def __init__(
        self,
        relationship_model: SignalRelationshipModel | None = None,
        explainability_engine: ExplainabilityEngine | None = None,
        detection_family_threshold: int = 2,
    ) -> None:
        self._relationship_model = relationship_model or SignalRelationshipModel()
        self._explainability_engine = explainability_engine or ExplainabilityEngine(
            self._relationship_model
        )
        self._detection_family_threshold = detection_family_threshold

    @property
    def relationship_model(self) -> SignalRelationshipModel:
        """Return the active relationship model."""
        return self._relationship_model

    def evaluate_correlation(
        self,
        context: DetectionContext,
        signal_results: Sequence[SignalResult],
        evaluation_errors: list[str] | None = None,
    ) -> tuple[
        DetectionOutcome,
        float,  # confidence_score
        float,  # severity_score
        float,  # telemetry_coverage
        float,  # evidence_completeness
        DeduplicatedEvidence,
        DetectionExplanation,
    ]:
        """Correlate evaluated signals into a coherent detection outcome."""
        errors = evaluation_errors or []
        triggered = [sr for sr in signal_results if sr.triggered]
        triggered_ids = [sr.signal_id for sr in triggered]

        # 1. Deduplicate evidence
        evidence = deduplicate_evidence(signal_results)

        # 2. Compute telemetry coverage
        # Core capabilities standard to Kuyebiko architecture
        standard_caps = {
            TelemetryCapability.FILESYSTEM_METADATA,
            TelemetryCapability.PROCESS_EXECUTION,
            TelemetryCapability.EVENT_LOG,
            TelemetryCapability.FILESYSTEM_READ_ACCESS,
        }
        available_caps = {TelemetryCapability.FILESYSTEM_METADATA}
        if context.config.get("process_events"):
            available_caps.add(TelemetryCapability.PROCESS_EXECUTION)
        if context.config.get("event_log_events"):
            available_caps.add(TelemetryCapability.EVENT_LOG)
        if context.config.get("discovery_events"):
            available_caps.add(TelemetryCapability.FILESYSTEM_READ_ACCESS)

        missing_caps = [cap.value for cap in standard_caps if cap not in available_caps]
        telemetry_coverage = len(available_caps) / len(standard_caps)

        # 3. Calculate Severity Score
        if not triggered:
            base_severity = 0.0
        else:
            base_severity = max(sr.severity_score for sr in triggered)
            # Corroboration boost for multi-family presence
            independent_families = self._relationship_model.get_independent_families(
                triggered_ids
            )
            family_boost = max(0, len(independent_families) - 1) * 0.05
            base_severity = min(1.0, base_severity + family_boost)

        severity_score = round(base_severity, 3)

        # 4. Calculate Confidence Score
        confidence_score = self._compute_confidence(
            triggered_results=triggered,
            evidence=evidence,
            context=context,
        )

        # 5. Determine Outcome deterministically
        outcome = self._determine_outcome(
            errors=errors,
            triggered_results=triggered,
            context=context,
            confidence=confidence_score,
        )

        # 6. Generate detailed explanation
        deg_reasons = []
        if context.degradation_reason:
            deg_reasons.append(context.degradation_reason)

        explanation = self._explainability_engine.generate_explanation(
            outcome=outcome,
            signal_results=list(signal_results),
            evidence=evidence,
            confidence_score=confidence_score,
            severity_score=severity_score,
            telemetry_coverage=telemetry_coverage,
            is_telemetry_degraded=context.is_telemetry_degraded,
            degradation_reasons=deg_reasons,
            missing_capabilities=missing_caps,
            evaluation_errors=errors,
        )

        return (
            outcome,
            confidence_score,
            severity_score,
            telemetry_coverage,
            evidence.evidence_completeness,
            evidence,
            explanation,
        )

    def _compute_confidence(
        self,
        triggered_results: list[SignalResult],
        evidence: DeduplicatedEvidence,
        context: DetectionContext,
    ) -> float:
        """Compute detection confidence considering independence and evidence."""
        if not triggered_results:
            return 0.0

        triggered_ids = [sr.signal_id for sr in triggered_results]
        families = self._relationship_model.get_independent_families(triggered_ids)

        # Base confidence from independent families
        if len(families) >= 3:
            conf = 0.90
        elif len(families) == 2:
            conf = 0.75
        else:
            conf = 0.40

        # Overlapping signal evidence penalty:
        # If signals share heavily overlapping evidence without corroboration,
        # discount confidence to prevent collinear false certainty.
        if len(triggered_ids) >= 2 and len(families) <= 2 and evidence.shared_event_ids:
            shared_ratio = len(evidence.shared_event_ids) / max(
                1, evidence.total_unique_events
            )
            overlapping_pairs = self._relationship_model.find_overlapping_pairs(
                triggered_ids
            )
            if overlapping_pairs and shared_ratio > 0.6:
                # Deduct collinear confidence inflation
                conf -= 0.15 * shared_ratio

        # Primary attack indicator bonus
        if self._relationship_model.has_primary_attack_indicator(triggered_ids):
            conf += 0.08

        # Evidence volume confirmation: strong evidence presence reinforces confidence
        if evidence.total_unique_events >= 10:
            conf += 0.05

        # Penalise if telemetry is degraded (uncertainty introduced by drops)
        if context.is_telemetry_degraded:
            conf -= 0.20
            if context.uncounted_kernel_loss:
                conf -= 0.10

        # Bound confidence between 0.05 and 1.0
        return round(max(0.05, min(1.0, conf)), 3)

    def _determine_outcome(
        self,
        errors: list[str],
        triggered_results: list[SignalResult],
        context: DetectionContext,
        confidence: float,
    ) -> DetectionOutcome:
        """Evaluate deterministic outcome based on signals, confidence, and context."""
        if errors:
            return DetectionOutcome.EVALUATION_ERROR

        if not triggered_results:
            if context.is_telemetry_degraded:
                return DetectionOutcome.INSUFFICIENT_TELEMETRY
            return DetectionOutcome.NO_DETECTION

        triggered_ids = [sr.signal_id for sr in triggered_results]
        families = self._relationship_model.get_independent_families(triggered_ids)
        categories = self._relationship_model.get_independent_categories(triggered_ids)

        # 3 or more independent families -> definitive DETECTION
        if len(families) >= 3:
            return DetectionOutcome.DETECTION

        # 2 independent families with sufficient confidence and attack indicators
        if len(families) >= self._detection_family_threshold:
            has_transformation = (
                SignalFamily.FILE_TRANSFORMATION in families
                or BehaviourCategory.TRANSFORMATION in categories
            )
            has_rename_burst = (
                "FS_BURST_WRITE" in triggered_ids and "FS_RENAME_RATIO" in triggered_ids
            )
            has_recovery_and_destruction = (
                "FS_RECOVERY_INHIBITION" in triggered_ids
                and (
                    "FS_DATA_DESTRUCTION" in triggered_ids
                    or "FS_DELETE_RATIO" in triggered_ids
                )
            )
            has_primary_indicator = (
                self._relationship_model.has_primary_attack_indicator(triggered_ids)
            )

            # High-risk combinations
            if (
                has_transformation or has_rename_burst or has_recovery_and_destruction
            ) and (has_primary_indicator or confidence >= 0.65):
                # If degraded, only trigger DETECTION if confidence >= 0.55
                if context.is_telemetry_degraded and confidence < 0.55:
                    return DetectionOutcome.SUSPICIOUS_ACTIVITY
                return DetectionOutcome.DETECTION

        # Specific synergistic pair: Low-and-slow + Extension convergence
        if (
            "FS_LOW_AND_SLOW_ACTIVITY" in triggered_ids
            and "FS_EXTENSION_CONVERGENCE" in triggered_ids
        ):
            return DetectionOutcome.DETECTION

        # Otherwise, individual or non-corroborating signals represent suspicious
        return DetectionOutcome.SUSPICIOUS_ACTIVITY
