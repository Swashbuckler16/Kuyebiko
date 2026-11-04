from datetime import datetime

import pytest
from pydantic import ValidationError

from kuyebiko.models.incidents import (
    IncidentConfidence,
    IncidentSeverity,
    IncidentStatus,
    SecurityIncident,
)


def create_incident(**overrides):
    data = {
        "root_id": "root-001",
        "title": "Suspicious file activity",
        "description": "Unusual file modification activity detected.",
        "severity": IncidentSeverity.HIGH,
        "confidence": IncidentConfidence.MODERATE,
        "risk_score": 75,
        "evidence_event_ids": ["event-001", "event-002"],
        "signal_families": ["modification_burst", "file_rename"],
    }

    data.update(overrides)
    return SecurityIncident(**data)


def test_valid_incident():
    incident = create_incident()

    assert incident.root_id == "root-001"
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.risk_score == 75


def test_incident_id_is_generated():
    first = create_incident()
    second = create_incident()

    assert first.incident_id != second.incident_id


def test_default_status_is_open():
    incident = create_incident()

    assert incident.status == IncidentStatus.OPEN


def test_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        create_incident(risk_score=101)


def test_negative_risk_score_rejected():
    with pytest.raises(ValidationError):
        create_incident(risk_score=-1)


def test_duplicate_evidence_ids_rejected():
    with pytest.raises(ValidationError):
        create_incident(evidence_event_ids=["event-001", "event-001"])


def test_duplicate_signal_families_rejected():
    with pytest.raises(ValidationError):
        create_incident(signal_families=["modification_burst", "modification_burst"])


def test_invalid_timeline_rejected():
    with pytest.raises(ValidationError):
        create_incident(
            first_seen="2026-11-04T12:00:00Z",
            last_seen="2026-11-04T10:00:00Z",
        )


def test_empty_title_rejected():
    with pytest.raises(ValidationError):
        create_incident(title="")


def test_incident_status_can_be_updated():
    incident = create_incident()

    incident.status = IncidentStatus.ACKNOWLEDGED

    assert incident.status == IncidentStatus.ACKNOWLEDGED


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        create_incident(first_seen=datetime(2026, 11, 4, 12, 0, 0))

    with pytest.raises(ValidationError):
        create_incident(last_seen=datetime(2026, 11, 4, 12, 0, 0))


def test_empty_evidence_event_id_rejected():
    with pytest.raises(ValidationError):
        create_incident(evidence_event_ids=[""])

    with pytest.raises(ValidationError):
        create_incident(signal_families=["   "])
