from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from kuyebiko.collectors.models import (
    MonitoredRoot,
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.models.events import EventType, FileEvent


def test_valid_monitored_root(tmp_path: Path):
    root = MonitoredRoot(
        root_id="test-root-01",
        path=tmp_path,
        recursive=True,
        enabled=True,
    )

    assert root.root_id == "test-root-01"
    assert root.path == tmp_path
    assert root.recursive is True
    assert root.enabled is True
    assert root.resolved_path() == tmp_path.resolve()


def test_monitored_root_rejects_relative_path():
    with pytest.raises(ValidationError, match="must be absolute"):
        MonitoredRoot(
            root_id="test-root-01",
            path=Path("relative/path/to/dir"),
        )


def test_monitored_root_rejects_nonexistent_directory(tmp_path: Path):
    nonexistent = tmp_path / "does_not_exist_folder"
    with pytest.raises(ValidationError, match="does not exist"):
        MonitoredRoot(
            root_id="test-root-01",
            path=nonexistent,
        )


def test_monitored_root_rejects_file_path(tmp_path: Path):
    file_path = tmp_path / "regular_file.txt"
    file_path.write_text("content", encoding="utf-8")

    with pytest.raises(ValidationError, match="must be a directory"):
        MonitoredRoot(
            root_id="test-root-01",
            path=file_path,
        )


def test_monitored_root_resolve_and_validate(tmp_path: Path):
    root = MonitoredRoot(root_id="test-root-01", path=tmp_path)
    assert root.resolve_and_validate() == tmp_path.resolve()


def test_monitored_root_is_frozen(tmp_path: Path):
    root = MonitoredRoot(root_id="test-root-01", path=tmp_path)
    with pytest.raises(ValidationError):
        root.enabled = False  # type: ignore[misc]


def test_monitored_root_rejects_extra_fields(tmp_path: Path):
    with pytest.raises(ValidationError):
        MonitoredRoot(
            root_id="test-root-01",
            path=tmp_path,
            unexpected_field="disallowed",  # type: ignore[call-arg]
        )


def test_all_five_windows_file_actions():
    assert WindowsFileAction.ADDED == 1
    assert WindowsFileAction.REMOVED == 2
    assert WindowsFileAction.MODIFIED == 3
    assert WindowsFileAction.RENAMED_OLD_NAME == 4
    assert WindowsFileAction.RENAMED_NEW_NAME == 5


def test_valid_raw_file_notification():
    now = datetime.now(UTC)
    notification = RawFileNotification(
        root_id="root-101",
        relative_path="docs/subfolder/file.pdf",
        action=WindowsFileAction.ADDED,
        observed_at=now,
        monotonic_ns=123456789,
    )

    assert notification.root_id == "root-101"
    assert notification.relative_path == "docs/subfolder/file.pdf"
    assert notification.action == WindowsFileAction.ADDED
    assert notification.observed_at == now
    assert notification.monotonic_ns == 123456789


def test_raw_notification_normalizes_backslashes():
    notification = RawFileNotification(
        root_id="root-101",
        relative_path="docs\\subfolder\\nested\\file.txt",
        action=WindowsFileAction.MODIFIED,
        monotonic_ns=1000,
    )
    assert notification.relative_path == "docs/subfolder/nested/file.txt"


def test_raw_notification_rejects_absolute_path():
    with pytest.raises(ValidationError, match="must be relative"):
        RawFileNotification(
            root_id="root-101",
            relative_path="/var/log/file.txt",
            action=WindowsFileAction.ADDED,
            monotonic_ns=1000,
        )


def test_raw_notification_rejects_drive_qualified_path():
    with pytest.raises(ValidationError, match="Drive-qualified paths"):
        RawFileNotification(
            root_id="root-101",
            relative_path="C:\\Windows\\System32\\file.txt",
            action=WindowsFileAction.ADDED,
            monotonic_ns=1000,
        )


def test_raw_notification_rejects_path_traversal():
    with pytest.raises(ValidationError, match="Path traversal"):
        RawFileNotification(
            root_id="root-101",
            relative_path="documents/../../etc/passwd",
            action=WindowsFileAction.MODIFIED,
            monotonic_ns=1000,
        )


def test_raw_notification_rejects_empty_path():
    err_pattern = r"(cannot be empty|at least 1 character)"
    with pytest.raises(ValidationError, match=err_pattern):
        RawFileNotification(
            root_id="root-101",
            relative_path="   ",
            action=WindowsFileAction.MODIFIED,
            monotonic_ns=1000,
        )
    with pytest.raises(ValidationError, match=err_pattern):
        RawFileNotification(
            root_id="root-101",
            relative_path="",
            action=WindowsFileAction.MODIFIED,
            monotonic_ns=1000,
        )


def test_raw_notification_rejects_naive_timestamp():
    with pytest.raises(ValidationError, match="timezone information"):
        RawFileNotification(
            root_id="root-101",
            relative_path="file.txt",
            action=WindowsFileAction.MODIFIED,
            observed_at=datetime(2026, 11, 5, 12, 0, 0),
            monotonic_ns=1000,
        )


def test_raw_notification_converts_non_utc_timezone():
    tz_plus_4 = timezone(timedelta(hours=4))
    non_utc_time = datetime(2026, 11, 5, 16, 0, 0, tzinfo=tz_plus_4)

    notification = RawFileNotification(
        root_id="root-101",
        relative_path="file.txt",
        action=WindowsFileAction.MODIFIED,
        observed_at=non_utc_time,
        monotonic_ns=1000,
    )

    assert notification.observed_at.tzinfo == UTC
    assert notification.observed_at.hour == 12


def test_raw_notification_to_file_event():
    notification = RawFileNotification(
        root_id="root-101",
        relative_path="documents/budget.xlsx",
        action=WindowsFileAction.ADDED,
        monotonic_ns=55555,
    )

    event = notification.to_file_event(sequence_number=10)
    assert isinstance(event, FileEvent)
    assert event.root_id == "root-101"
    assert event.file_path == "documents/budget.xlsx"
    assert event.event_type == EventType.CREATED
    assert event.sequence_number == 10
