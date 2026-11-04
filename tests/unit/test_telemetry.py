from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from kuyebiko.models.telemetry import (
    CollectorStatus,
    MonitoringStatus,
    TelemetrySnapshot,
)


def create_snapshot(**overrides):
    data = {
        "collector_id": "collector-001",
        "root_id": "root-001",
        "monitoring_status": MonitoringStatus.RUNNING,
        "collector_status": CollectorStatus.ACTIVE,
        "events_received": 100,
        "events_dropped": 2,
        "queue_capacity": 10000,
        "queue_depth": 50,
        "collection_errors": 0,
    }

    data.update(overrides)
    return TelemetrySnapshot(**data)


def test_valid_telemetry_snapshot():
    snapshot = create_snapshot()

    assert snapshot.root_id == "root-001"
    assert snapshot.monitoring_status == MonitoringStatus.RUNNING
    assert snapshot.events_received == 100


def test_snapshot_id_is_generated():
    first = create_snapshot()
    second = create_snapshot()

    assert first.snapshot_id != second.snapshot_id


def test_default_queue_values():
    snapshot = TelemetrySnapshot(
        collector_id="collector-001",
        root_id="root-001",
    )

    assert snapshot.queue_capacity == 10000
    assert snapshot.queue_depth == 0


def test_negative_event_count_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(events_received=-1)


def test_negative_dropped_count_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(events_dropped=-1)


def test_queue_depth_cannot_exceed_capacity():
    with pytest.raises(ValidationError):
        create_snapshot(
            queue_capacity=100,
            queue_depth=150,
        )


def test_negative_collection_errors_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(collection_errors=-1)


def test_naive_heartbeat_timestamp_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(last_heartbeat="2026-11-04T12:00:00")


def test_empty_degradation_reason_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(degradation_reasons=["", "Queue overflow"])


def test_duplicate_degradation_reasons_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(
            degradation_reasons=[
                "Queue overflow",
                "Queue overflow",
            ]
        )


def test_timezone_conversion_to_utc():
    tz_plus_5 = timezone(timedelta(hours=5))
    local_time = datetime(2026, 11, 4, 15, 0, 0, tzinfo=tz_plus_5)
    snapshot = create_snapshot(last_heartbeat=local_time)

    assert snapshot.last_heartbeat.tzinfo == UTC
    assert snapshot.last_heartbeat.hour == 10


def test_whitespace_only_degradation_reason_rejected():
    with pytest.raises(ValidationError):
        create_snapshot(degradation_reasons=["   "])
