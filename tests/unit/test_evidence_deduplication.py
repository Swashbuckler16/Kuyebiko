"""Unit tests for evidence deduplication and accounting."""

from datetime import UTC, datetime

from kuyebiko.detection.correlation.evidence import deduplicate_evidence
from kuyebiko.detection.models import SignalFamily, SignalResult


def _make_signal_result(
    signal_id: str,
    family: SignalFamily,
    triggered: bool,
    event_ids: list[str],
) -> SignalResult:
    return SignalResult(
        signal_id=signal_id,
        signal_name=signal_id,
        family=family,
        triggered=triggered,
        severity_score=0.8 if triggered else 0.0,
        observed_metric=10.0 if triggered else 0.0,
        threshold=5.0,
        explanation=f"Signal {signal_id} evaluation",
        evidence_event_ids=event_ids,
        evaluated_at_utc=datetime.now(UTC),
    )


def test_deduplicate_evidence_empty() -> None:
    """Verify evidence deduplication on empty signal results."""
    res = deduplicate_evidence([])
    assert res.total_unique_events == 0
    assert res.unique_event_ids == []
    assert res.shared_event_ids == []
    assert res.evidence_completeness == 1.0


def test_deduplicate_evidence_overlap() -> None:
    """Verify deduplication detects overlapping event UUIDs without duplication."""
    sig1 = _make_signal_result(
        "FS_DELETE_RATIO",
        SignalFamily.RENAME_DELETION,
        True,
        ["e1", "e2", "e3"],
    )
    sig2 = _make_signal_result(
        "FS_DATA_DESTRUCTION",
        SignalFamily.DATA_DESTRUCTION,
        True,
        ["e2", "e3", "e4"],
    )
    sig3 = _make_signal_result(
        "FS_BURST_WRITE",
        SignalFamily.FILESYSTEM_ACTIVITY,
        False,
        ["e5"],  # Not triggered, should not contribute
    )

    dedup = deduplicate_evidence([sig1, sig2, sig3])

    assert dedup.total_unique_events == 4
    assert dedup.unique_event_ids == ["e1", "e2", "e3", "e4"]
    assert set(dedup.shared_event_ids) == {"e2", "e3"}
    assert set(dedup.independent_event_ids) == {"e1", "e4"}

    # Check pairwise overlap matrix
    matrix = dedup.overlap_matrix
    assert matrix["FS_DELETE_RATIO"]["FS_DELETE_RATIO"] == 3
    assert matrix["FS_DATA_DESTRUCTION"]["FS_DATA_DESTRUCTION"] == 3
    assert matrix["FS_DELETE_RATIO"]["FS_DATA_DESTRUCTION"] == 2
    assert matrix["FS_DATA_DESTRUCTION"]["FS_DELETE_RATIO"] == 2


def test_deduplicate_evidence_bounding() -> None:
    """Verify evidence lists are bounded to max_evidence."""
    event_ids = [f"evt_{i}" for i in range(50)]
    sig = _make_signal_result(
        "FS_BURST_WRITE",
        SignalFamily.FILESYSTEM_ACTIVITY,
        True,
        event_ids,
    )

    dedup = deduplicate_evidence([sig], max_evidence=15)
    assert dedup.total_unique_events == 15
    assert len(dedup.unique_event_ids) == 15
