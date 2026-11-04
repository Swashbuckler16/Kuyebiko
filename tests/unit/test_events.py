from datetime import datetime

import pytest
from pydantic import ValidationError

from kuyebiko.models.events import (
    EventSource,
    EventType,
    FileEvent,
    TelemetryQuality,
)


def create_event(**overrides):
    data = {
        "root_id": "root-001",
        "file_path": "documents/report.pdf",
        "event_type": EventType.MODIFIED,
        "monotonic_ns": 123456789,
        "source": EventSource.WINDOWS_WATCHER,
    }

    data.update(overrides)
    return FileEvent(**data)


def test_valid_file_event():
    event = create_event()

    assert event.root_id == "root-001"
    assert event.event_type == EventType.MODIFIED
    assert event.quality == TelemetryQuality.NORMAL
    assert event.timestamp_utc.tzinfo is not None


def test_event_id_is_generated():
    first = create_event()
    second = create_event()

    assert first.event_id != second.event_id


def test_negative_monotonic_timestamp_rejected():
    with pytest.raises(ValidationError):
        create_event(monotonic_ns=-1)


def test_absolute_path_rejected():
    with pytest.raises(ValidationError):
        create_event(file_path="C:\\Users\\test.txt")


def test_path_traversal_rejected():
    with pytest.raises(ValidationError):
        create_event(file_path="../secret.txt")


def test_rename_event_requires_both_paths():
    with pytest.raises(ValidationError):
        create_event(event_type=EventType.RENAMED)


def test_valid_rename_event():
    event = create_event(
        event_type=EventType.RENAMED,
        file_path="documents/new.pdf",
        old_path="documents/old.pdf",
        new_path="documents/new.pdf",
    )

    assert event.old_path == "documents/old.pdf"
    assert event.new_path == "documents/new.pdf"


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        create_event(timestamp_utc=datetime(2026, 11, 4, 12, 0, 0))


def test_leading_slash_path_rejected():
    with pytest.raises(ValidationError):
        create_event(file_path="/documents/report.pdf")

    with pytest.raises(ValidationError):
        create_event(file_path="//network/report.pdf")


def test_rename_event_path_mismatch_rejected():
    with pytest.raises(ValidationError):
        create_event(
            event_type=EventType.RENAMED,
            file_path="documents/mismatch.pdf",
            old_path="documents/old.pdf",
            new_path="documents/new.pdf",
        )


def test_non_rename_event_with_paths_rejected():
    with pytest.raises(ValidationError):
        create_event(
            event_type=EventType.MODIFIED,
            old_path="documents/old.pdf",
        )

    with pytest.raises(ValidationError):
        create_event(
            event_type=EventType.MODIFIED,
            new_path="documents/new.pdf",
        )
