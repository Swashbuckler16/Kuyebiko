"""Evidence deduplication and accounting for behavioural detection correlation.

Ensures event UUIDs contributing to multiple signals are not double-counted,
identifies shared vs independent evidence, and generates evidence overlap metrics.
"""

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.detection.models import SignalResult


class DeduplicatedEvidence(BaseModel):
    """Structured result of deduplicated evidence accounting across signals."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    unique_event_ids: list[str] = Field(default_factory=list)
    total_unique_events: int = Field(default=0, ge=0)
    signal_to_events: dict[str, list[str]] = Field(default_factory=dict)
    event_to_signals: dict[str, list[str]] = Field(default_factory=dict)
    shared_event_ids: list[str] = Field(default_factory=list)
    independent_event_ids: list[str] = Field(default_factory=list)
    overlap_matrix: dict[str, dict[str, int]] = Field(default_factory=dict)
    evidence_completeness: float = Field(default=1.0, ge=0.0, le=1.0)


def deduplicate_evidence(
    signal_results: Sequence[SignalResult],
    max_evidence: int = 1000,
) -> DeduplicatedEvidence:
    """Deduplicate event IDs across all triggered signal results.

    Maintains deterministic ordering, bounds total evidence to `max_evidence`,
    identifies shared and independent events, and computes the pairwise overlap matrix.
    """
    triggered_signals = [sr for sr in signal_results if sr.triggered]

    if not triggered_signals:
        return DeduplicatedEvidence(
            unique_event_ids=[],
            total_unique_events=0,
            signal_to_events={},
            event_to_signals={},
            shared_event_ids=[],
            independent_event_ids=[],
            overlap_matrix={},
            evidence_completeness=1.0,
        )

    signal_to_events: dict[str, list[str]] = {}
    event_to_signals: dict[str, list[str]] = {}
    unique_ids_ordered: list[str] = []
    seen_ids: set[str] = set()

    signals_with_evidence = 0

    for sr in triggered_signals:
        sig_id = sr.signal_id
        # Bound per-signal evidence to max_evidence
        sig_event_ids: list[str] = []
        for eid in sr.evidence_event_ids:
            if eid not in sig_event_ids:
                sig_event_ids.append(eid)
            if len(sig_event_ids) >= max_evidence:
                break

        if sig_event_ids:
            signals_with_evidence += 1

        signal_to_events[sig_id] = sig_event_ids

        for eid in sig_event_ids:
            if eid not in event_to_signals:
                event_to_signals[eid] = []
            if sig_id not in event_to_signals[eid]:
                event_to_signals[eid].append(sig_id)

            if eid not in seen_ids and len(unique_ids_ordered) < max_evidence:
                seen_ids.add(eid)
                unique_ids_ordered.append(eid)

    shared_event_ids: list[str] = []
    independent_event_ids: list[str] = []

    for eid in unique_ids_ordered:
        associated_signals = event_to_signals.get(eid, [])
        if len(associated_signals) > 1:
            shared_event_ids.append(eid)
        else:
            independent_event_ids.append(eid)

    # Compute pairwise overlap matrix
    sig_ids = [sr.signal_id for sr in triggered_signals]
    overlap_matrix: dict[str, dict[str, int]] = {
        s: {other: 0 for other in sig_ids} for s in sig_ids
    }

    for i, s1 in enumerate(sig_ids):
        s1_events = set(signal_to_events.get(s1, []))
        overlap_matrix[s1][s1] = len(s1_events)
        for j in range(i + 1, len(sig_ids)):
            s2 = sig_ids[j]
            s2_events = set(signal_to_events.get(s2, []))
            common_count = len(s1_events.intersection(s2_events))
            overlap_matrix[s1][s2] = common_count
            overlap_matrix[s2][s1] = common_count

    evidence_completeness = (
        float(signals_with_evidence) / float(len(triggered_signals))
        if triggered_signals
        else 1.0
    )

    return DeduplicatedEvidence(
        unique_event_ids=unique_ids_ordered,
        total_unique_events=len(unique_ids_ordered),
        signal_to_events=signal_to_events,
        event_to_signals=event_to_signals,
        shared_event_ids=shared_event_ids,
        independent_event_ids=independent_event_ids,
        overlap_matrix=overlap_matrix,
        evidence_completeness=round(evidence_completeness, 3),
    )
