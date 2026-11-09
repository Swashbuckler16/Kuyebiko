"""Explainability engine for behavioural detection correlation.

Generates human-readable, evidence-backed explanations describing detection
classifications, contributing signals, evidence overlap, and uncertainties.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.detection.correlation.evidence import DeduplicatedEvidence
from kuyebiko.detection.correlation.relationships import SignalRelationshipModel
from kuyebiko.detection.models import DetectionOutcome, SignalResult


class DetectionExplanation(BaseModel):
    """Detailed explainability payload accompanying a detection evaluation."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    summary: str = Field(min_length=1)
    outcome: DetectionOutcome
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_rationale: str = Field(min_length=1)
    severity_score: float = Field(ge=0.0, le=1.0)
    severity_rationale: str = Field(min_length=1)
    telemetry_coverage: float = Field(ge=0.0, le=1.0)
    telemetry_state: dict[str, str] = Field(default_factory=dict)
    missing_capabilities: list[str] = Field(default_factory=list)
    known_uncertainties: list[str] = Field(default_factory=list)
    triggered_signals: list[str] = Field(default_factory=list)
    independent_families: list[str] = Field(default_factory=list)
    independent_categories: list[str] = Field(default_factory=list)
    contributing_event_ids: list[str] = Field(default_factory=list)
    shared_evidence_count: int = Field(default=0, ge=0)
    unique_evidence_count: int = Field(default=0, ge=0)
    overlapping_signal_pairs: list[dict[str, Any]] = Field(default_factory=list)
    classification_rationale: str = Field(min_length=1)

    def to_markdown(self) -> str:
        """Render a formatted markdown summary for security analyst review."""
        missing_str = (
            ", ".join(self.missing_capabilities)
            if self.missing_capabilities
            else "None"
        )
        lines = [
            f"### Detection Outcome: **{self.outcome.value.upper()}**",
            f"**Summary:** {self.summary}",
            "",
            "#### Metrics",
            f"- **Severity:** {self.severity_score:.2f} — {self.severity_rationale}",
            (
                f"- **Confidence:** {self.confidence_score:.2f} — "
                f"{self.confidence_rationale}"
            ),
            (
                f"- **Telemetry Coverage:** {self.telemetry_coverage:.0%} — "
                f"Missing: {missing_str}"
            ),
            "",
            "#### Contributing Signals",
        ]
        if self.triggered_signals:
            for sig in self.triggered_signals:
                lines.append(f"- `{sig}`")
        else:
            lines.append("- *No behavioural signals triggered.*")

        lines.extend(
            [
                "",
                "#### Evidence Accounting",
                f"- Unique Events: {self.unique_evidence_count}",
                f"- Shared Events across Signals: {self.shared_evidence_count}",
            ]
        )

        if self.overlapping_signal_pairs:
            lines.append("- Overlapping Pairs:")
            for pair in self.overlapping_signal_pairs:
                lines.append(
                    f"  - `{pair['signal_a']}` and `{pair['signal_b']}` share "
                    f"{pair['shared_events']} event(s) ({pair['relation_type']})"
                )

        if self.known_uncertainties:
            lines.extend(["", "#### Known Uncertainties"])
            for unc in self.known_uncertainties:
                lines.append(f"- {unc}")

        return "\n".join(lines)


class ExplainabilityEngine:
    """Constructs structured explanations from correlation analysis results."""

    def __init__(
        self, relationship_model: SignalRelationshipModel | None = None
    ) -> None:
        self._relationship_model = relationship_model or SignalRelationshipModel()

    def generate_explanation(
        self,
        outcome: DetectionOutcome,
        signal_results: list[SignalResult],
        evidence: DeduplicatedEvidence,
        confidence_score: float,
        severity_score: float,
        telemetry_coverage: float,
        is_telemetry_degraded: bool,
        degradation_reasons: list[str],
        missing_capabilities: list[str],
        evaluation_errors: list[str] | None = None,
    ) -> DetectionExplanation:
        """Produce a comprehensive, evidence-grounded DetectionExplanation."""
        triggered = [sr for sr in signal_results if sr.triggered]
        triggered_ids = [sr.signal_id for sr in triggered]

        families = sorted(
            [
                f.value
                for f in self._relationship_model.get_independent_families(
                    triggered_ids
                )
            ]
        )
        categories = sorted(
            [
                c.value
                for c in self._relationship_model.get_independent_categories(
                    triggered_ids
                )
            ]
        )

        # Overlapping pairs analysis
        overlapping_pairs: list[dict[str, Any]] = []
        for i, s1 in enumerate(triggered_ids):
            for s2 in triggered_ids[i + 1 :]:
                shared_count = evidence.overlap_matrix.get(s1, {}).get(s2, 0)
                is_related = self._relationship_model.are_signals_related(s1, s2)
                if shared_count > 0 or is_related:
                    overlapping_pairs.append(
                        {
                            "signal_a": s1,
                            "signal_b": s2,
                            "shared_events": shared_count,
                            "relation_type": (
                                "correlated_category"
                                if is_related
                                else "shared_evidence"
                            ),
                        }
                    )

        # Uncertainties identification
        uncertainties: list[str] = []
        if is_telemetry_degraded:
            reasons_str = (
                ", ".join(degradation_reasons) if degradation_reasons else "unspecified"
            )
            uncertainties.append(
                f"Observation window experienced telemetry degradation: {reasons_str}"
            )

        if missing_capabilities:
            caps_str = ", ".join(missing_capabilities)
            uncertainties.append(
                f"Missing auxiliary telemetry capabilities: {caps_str}. "
                "Certain behavioural facets could not be independently inspected."
            )

        if evaluation_errors:
            err_str = "; ".join(evaluation_errors)
            uncertainties.append(f"Evaluator errors: {err_str}")

        # Severity rationale
        if severity_score >= 0.8:
            sev_rationale = (
                "Critical destructive or irreversible transformations observed"
            )
        elif severity_score >= 0.5:
            sev_rationale = "Moderate suspicious modifications or high activity bursts"
        elif severity_score > 0.0:
            sev_rationale = "Low-severity activity or isolated anomalies"
        else:
            sev_rationale = "No anomalous activity detected"

        # Confidence rationale
        if outcome == DetectionOutcome.DETECTION:
            conf_rationale = (
                f"High confidence ({confidence_score:.2f}) established by "
                f"{len(families)} independent families corroborating attack."
            )
        elif outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY:
            conf_rationale = (
                f"Moderate confidence ({confidence_score:.2f}) from "
                f"{len(families)} signal family/families."
            )
        elif outcome == DetectionOutcome.INSUFFICIENT_TELEMETRY:
            conf_rationale = "Low confidence due to degraded observation context."
        elif outcome == DetectionOutcome.EVALUATION_ERROR:
            conf_rationale = "Uncertain due to evaluator execution errors."
        else:
            conf_rationale = "High confidence of benign state."

        # Summary and classification rationale
        if outcome == DetectionOutcome.DETECTION:
            summary = (
                f"Ransomware behaviour detected across {len(families)} independent "
                f"families ({', '.join(families)}) with {evidence.total_unique_events} "
                "contributing event(s)."
            )
            classification_rationale = (
                "Activity meets multi-family corroboration criteria with primary "
                "attack indicators, exceeding composite detection thresholds."
            )
        elif outcome == DetectionOutcome.SUSPICIOUS_ACTIVITY:
            summary = (
                f"Suspicious activity observed ({', '.join(triggered_ids)}). "
                "Lacks sufficient multi-vector independence for definitive detection."
            )
            classification_rationale = (
                "Single-vector or overlapping signals observed without sufficient "
                "independent family corroboration to classify as ransomware."
            )
        elif outcome == DetectionOutcome.INSUFFICIENT_TELEMETRY:
            summary = (
                "Telemetry insufficient or degraded to reach a definitive verdict."
            )
            classification_rationale = (
                "Degradation or absence of telemetry sources prevented observation."
            )
        elif outcome == DetectionOutcome.EVALUATION_ERROR:
            summary = "Detection evaluation aborted due to component errors."
            classification_rationale = "Exceptions occurred during signal evaluation."
        else:
            summary = "Normal filesystem behaviour observed within window."
            classification_rationale = (
                "All behavioural metrics remained within benign operational thresholds."
            )

        telemetry_state = {
            "filesystem_metadata": "degraded" if is_telemetry_degraded else "clean",
        }
        for cap in missing_capabilities:
            telemetry_state[cap.lower()] = "unavailable"

        return DetectionExplanation(
            summary=summary,
            outcome=outcome,
            confidence_score=round(confidence_score, 3),
            confidence_rationale=conf_rationale,
            severity_score=round(severity_score, 3),
            severity_rationale=sev_rationale,
            telemetry_coverage=round(telemetry_coverage, 3),
            telemetry_state=telemetry_state,
            missing_capabilities=missing_capabilities,
            known_uncertainties=uncertainties,
            triggered_signals=triggered_ids,
            independent_families=families,
            independent_categories=categories,
            contributing_event_ids=evidence.unique_event_ids,
            shared_evidence_count=len(evidence.shared_event_ids),
            unique_evidence_count=evidence.total_unique_events,
            overlapping_signal_pairs=overlapping_pairs,
            classification_rationale=classification_rationale,
        )
