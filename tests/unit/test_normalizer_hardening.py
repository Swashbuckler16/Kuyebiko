import threading
from datetime import UTC, datetime

import pytest

from kuyebiko.collectors.models import (
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.rename_correlator import (
    CorrelatedRenameNotification,
    RenameCorrelator,
)
from kuyebiko.core.exceptions import NormalizationError
from kuyebiko.models.events import (
    EventType,
    TelemetryQuality,
)


def _make_notification(
    path: str = "test.txt",
    root_id: str = "root-1",
    action: WindowsFileAction = WindowsFileAction.ADDED,
    monotonic_ns: int = 123_456_789,
    observed_at: datetime | None = None,
    is_directory: bool = False,
) -> RawFileNotification:
    return RawFileNotification(
        root_id=root_id,
        relative_path=path,
        action=action,
        observed_at=observed_at or datetime.now(UTC),
        monotonic_ns=monotonic_ns,
        is_directory=is_directory,
    )


def test_normalizer_preserves_timestamps_and_monotonic():
    normalizer = EventNormalizer()
    obs_time = datetime(2026, 11, 7, 10, 30, 0, tzinfo=UTC)
    notif = _make_notification(
        observed_at=obs_time,
        monotonic_ns=999_888_777,
    )

    event = normalizer.normalize_notification(notif)
    assert event is not None
    assert event.timestamp_utc == obs_time
    assert event.monotonic_ns == 999_888_777


def test_normalizer_event_id_uniqueness():
    normalizer = EventNormalizer()
    num_events = 500
    ids = set()

    for i in range(num_events):
        notif = _make_notification(path=f"file_{i}.txt", monotonic_ns=i)
        event = normalizer.normalize_notification(notif)
        assert event is not None
        assert event.event_id not in ids
        ids.add(event.event_id)

    assert len(ids) == num_events


def test_normalizer_sequence_numbers_monotonic():
    normalizer = EventNormalizer()
    seqs = []

    for i in range(20):
        notif = _make_notification(path=f"file_{i}.txt", monotonic_ns=i)
        event = normalizer.normalize_notification(notif)
        assert event is not None
        seqs.append(event.sequence_number)

    assert seqs == list(range(1, 21))


def test_normalizer_sequence_numbers_thread_safety():
    normalizer = EventNormalizer()
    num_threads = 8
    events_per_thread = 50
    all_seqs = []
    lock = threading.Lock()

    def worker(thread_idx: int) -> None:
        thread_seqs = []
        for i in range(events_per_thread):
            notif = _make_notification(
                path=f"t{thread_idx}/f{i}.txt",
                monotonic_ns=i,
            )
            event = normalizer.normalize_notification(notif)
            assert event is not None
            thread_seqs.append(event.sequence_number)
        with lock:
            all_seqs.extend(thread_seqs)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_events = num_threads * events_per_thread
    assert len(all_seqs) == total_events
    # All sequence numbers must be unique integers from 1 to total_events
    assert sorted(all_seqs) == list(range(1, total_events + 1))


def test_normalizer_quality_propagation():
    normalizer = EventNormalizer()

    for q in [
        TelemetryQuality.NORMAL,
        TelemetryQuality.DEGRADED,
        TelemetryQuality.DELAYED,
        TelemetryQuality.RECOVERED,
    ]:
        notif = _make_notification()
        event = normalizer.normalize_notification(notif, quality=q)
        assert event is not None
        assert event.quality == q


def test_normalizer_action_mappings():
    normalizer = EventNormalizer()

    # ADDED -> CREATED
    e_add = normalizer.normalize_notification(
        _make_notification(action=WindowsFileAction.ADDED)
    )
    assert e_add is not None and e_add.event_type == EventType.CREATED

    # MODIFIED -> MODIFIED
    e_mod = normalizer.normalize_notification(
        _make_notification(action=WindowsFileAction.MODIFIED)
    )
    assert e_mod is not None and e_mod.event_type == EventType.MODIFIED

    # REMOVED -> DELETED
    e_del = normalizer.normalize_notification(
        _make_notification(action=WindowsFileAction.REMOVED)
    )
    assert e_del is not None and e_del.event_type == EventType.DELETED


def test_normalizer_rename_without_correlator_requires_explicit_paths():
    normalizer = EventNormalizer(rename_correlator=None)
    notif = _make_notification(action=WindowsFileAction.RENAMED_NEW_NAME)

    with pytest.raises(NormalizationError, match="without both old_path and new_path"):
        normalizer.normalize_notification(notif)

    # With explicit paths
    event = normalizer.normalize_notification(
        notif, old_path="old.txt", new_path="new.txt"
    )
    assert event is not None
    assert event.event_type == EventType.RENAMED
    assert event.old_path == "old.txt"
    assert event.new_path == "new.txt"
    assert event.file_path == "new.txt"


def test_normalizer_incomplete_rename_returns_none_never_fakes():
    correlator = RenameCorrelator()
    normalizer = EventNormalizer(rename_correlator=correlator)

    # 1. Old name arrives -> returns None
    old_notif = _make_notification(
        path="orig.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
    )
    assert normalizer.normalize_notification(old_notif) is None

    # 2. Uncorrelated new name for different root -> returns None
    new_notif_diff_root = _make_notification(
        path="dest.txt",
        root_id="root-other",
        action=WindowsFileAction.RENAMED_NEW_NAME,
    )
    assert normalizer.normalize_notification(new_notif_diff_root) is None


def test_normalizer_complete_rename_via_correlator():
    correlator = RenameCorrelator()
    normalizer = EventNormalizer(rename_correlator=correlator)

    old_notif = _make_notification(
        path="file_old.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1000,
    )
    new_notif = _make_notification(
        path="file_new.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=2000,
    )

    assert normalizer.normalize_notification(old_notif) is None
    event = normalizer.normalize_notification(new_notif)

    assert event is not None
    assert event.event_type == EventType.RENAMED
    assert event.old_path == "file_old.txt"
    assert event.new_path == "file_new.txt"


def test_normalizer_unsupported_action_raises():
    normalizer = EventNormalizer()
    notif = _make_notification()

    # Create dummy notification with invalid action
    class FakeAction:
        name = "UNSUPPORTED"

    object.__setattr__(notif, "action", FakeAction())
    with pytest.raises(NormalizationError, match="Unsupported notification action"):
        normalizer.normalize_notification(notif)


def test_normalizer_correlate_rename_validation_failure():
    normalizer = EventNormalizer()
    # Malformed correlated rename with invalid path (e.g. traversal '..')
    correlated = CorrelatedRenameNotification(
        root_id="root-1",
        old_path="../invalid_old.txt",
        new_path="new.txt",
        observed_at=datetime.now(UTC),
        monotonic_ns=100,
    )
    with pytest.raises(NormalizationError, match="rename validation failed"):
        normalizer.normalize_correlated_rename(correlated)
