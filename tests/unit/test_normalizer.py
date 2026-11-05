import pytest

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.core.exceptions import NormalizationError
from kuyebiko.models.events import EventType, FileEvent, TelemetryQuality


def test_normalizer_creates_valid_file_events_for_crud():
    normalizer = EventNormalizer()

    added = RawFileNotification(
        root_id="root-1",
        relative_path="docs/file.txt",
        action=WindowsFileAction.ADDED,
        monotonic_ns=1000,
    )
    event_add = normalizer.normalize_notification(added)
    assert isinstance(event_add, FileEvent)
    assert event_add.event_type == EventType.CREATED
    assert event_add.file_path == "docs/file.txt"
    assert event_add.old_path is None
    assert event_add.new_path is None
    assert event_add.sequence_number == 1

    modified = RawFileNotification(
        root_id="root-1",
        relative_path="docs/file.txt",
        action=WindowsFileAction.MODIFIED,
        monotonic_ns=2000,
    )
    event_mod = normalizer.normalize_notification(modified)
    assert event_mod is not None
    assert event_mod.event_type == EventType.MODIFIED
    assert event_mod.sequence_number == 2

    removed = RawFileNotification(
        root_id="root-1",
        relative_path="docs/file.txt",
        action=WindowsFileAction.REMOVED,
        monotonic_ns=3000,
    )
    event_rem = normalizer.normalize_notification(removed)
    assert event_rem is not None
    assert event_rem.event_type == EventType.DELETED
    assert event_rem.sequence_number == 3


def test_normalizer_event_id_uniqueness():
    normalizer = EventNormalizer()
    notif = RawFileNotification(
        root_id="root-1",
        relative_path="test.txt",
        action=WindowsFileAction.MODIFIED,
        monotonic_ns=1000,
    )

    e1 = normalizer.normalize_notification(notif)
    e2 = normalizer.normalize_notification(notif)

    assert e1 is not None and e2 is not None
    assert e1.event_id != e2.event_id
    assert e1.sequence_number < e2.sequence_number


def test_normalizer_correlates_renames_with_rename_correlator():
    correlator = RenameCorrelator()
    normalizer = EventNormalizer(rename_correlator=correlator)

    old_notif = RawFileNotification(
        root_id="root-1",
        relative_path="old.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1000,
    )
    new_notif = RawFileNotification(
        root_id="root-1",
        relative_path="new.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=2000,
    )

    # First notification is buffered, returns None
    assert normalizer.normalize_notification(old_notif) is None

    # Second notification triggers correlation and emits complete RENAMED FileEvent
    event = normalizer.normalize_notification(new_notif)
    assert isinstance(event, FileEvent)
    assert event.event_type == EventType.RENAMED
    assert event.old_path == "old.txt"
    assert event.new_path == "new.txt"
    assert event.file_path == "new.txt"


def test_normalizer_explicit_paths_rename():
    normalizer = EventNormalizer()
    notif = RawFileNotification(
        root_id="root-1",
        relative_path="final.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=1000,
    )

    event = normalizer.normalize_notification(
        notif,
        old_path="draft.txt",
        new_path="final.txt",
    )
    assert isinstance(event, FileEvent)
    assert event.event_type == EventType.RENAMED
    assert event.old_path == "draft.txt"
    assert event.new_path == "final.txt"


def test_normalizer_rejects_incomplete_rename_without_correlator():
    normalizer = EventNormalizer()  # No correlator
    notif = RawFileNotification(
        root_id="root-1",
        relative_path="draft.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1000,
    )

    with pytest.raises(NormalizationError, match="without both old_path and new_path"):
        normalizer.normalize_notification(notif)


def test_normalizer_preserves_custom_quality_and_directory_flag():
    normalizer = EventNormalizer()
    notif = RawFileNotification(
        root_id="root-1",
        relative_path="MyFolder",
        action=WindowsFileAction.ADDED,
        monotonic_ns=1000,
        is_directory=True,
    )

    event = normalizer.normalize_notification(
        notif,
        quality=TelemetryQuality.DEGRADED,
    )
    assert event is not None
    assert event.quality == TelemetryQuality.DEGRADED
    assert event.is_directory is True


def test_normalizer_file_event_json_serialization():
    normalizer = EventNormalizer()
    notif = RawFileNotification(
        root_id="root-json",
        relative_path="documents/test.json",
        action=WindowsFileAction.ADDED,
        monotonic_ns=5000,
    )
    event = normalizer.normalize_notification(notif)
    assert event is not None

    json_str = event.model_dump_json()
    assert "root-json" in json_str
    assert "documents/test.json" in json_str
    assert "created" in json_str


def test_processing_package_exports_normalizer():
    from kuyebiko.processing import EventNormalizer as ProcessingNormalizer

    assert ProcessingNormalizer is EventNormalizer
