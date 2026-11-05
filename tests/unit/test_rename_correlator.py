from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.collectors.rename_correlator import (
    CorrelatedRenameNotification,
    RenameCorrelator,
)


def test_correlator_matches_old_and_new_rename():
    correlator = RenameCorrelator(correlation_window_ns=1_000_000_000)

    old_notif = RawFileNotification(
        root_id="root-1",
        relative_path="docs/draft.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000_000,
    )
    new_notif = RawFileNotification(
        root_id="root-1",
        relative_path="docs/final.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=1_050_000,
    )

    result_old = correlator.process_notification(old_notif)
    assert result_old is None
    assert correlator.pending_count("root-1") == 1

    result_new = correlator.process_notification(new_notif)
    assert isinstance(result_new, CorrelatedRenameNotification)
    assert result_new.root_id == "root-1"
    assert result_new.old_path == "docs/draft.txt"
    assert result_new.new_path == "docs/final.txt"
    assert result_new.old_notification == old_notif
    assert result_new.new_notification == new_notif
    assert correlator.pending_count("root-1") == 0


def test_correlator_enforces_root_isolation():
    correlator = RenameCorrelator()

    old_notif = RawFileNotification(
        root_id="root-alpha",
        relative_path="file.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000_000,
    )
    new_notif = RawFileNotification(
        root_id="root-beta",
        relative_path="file_renamed.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=1_010_000,
    )

    correlator.process_notification(old_notif)
    # new_notif belongs to root-beta, must NOT correlate with root-alpha
    result = correlator.process_notification(new_notif)
    assert result is None
    assert correlator.pending_count("root-alpha") == 1
    assert correlator.pending_count("root-beta") == 0


def test_correlator_rejects_expired_pending_rename():
    # 500ms window = 500_000_000 ns
    correlator = RenameCorrelator(correlation_window_ns=500_000_000)

    old_notif = RawFileNotification(
        root_id="root-1",
        relative_path="old.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000_000,
    )
    # Arrives 1.5 seconds later (> 500ms window)
    new_notif = RawFileNotification(
        root_id="root-1",
        relative_path="new.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=1_500_000_000 + 1_000_000,
    )

    correlator.process_notification(old_notif)
    result = correlator.process_notification(new_notif)
    assert result is None
    assert correlator.pending_count("root-1") == 0


def test_correlator_rejects_identical_old_and_new_path():
    correlator = RenameCorrelator()

    old_notif = RawFileNotification(
        root_id="root-1",
        relative_path="same_name.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000,
    )
    new_notif = RawFileNotification(
        root_id="root-1",
        relative_path="same_name.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=2_000,
    )

    correlator.process_notification(old_notif)
    result = correlator.process_notification(new_notif)
    assert result is None


def test_correlator_capacity_eviction():
    correlator = RenameCorrelator(max_pending_per_root=2)

    n1 = RawFileNotification(
        root_id="r1",
        relative_path="f1.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=100,
    )
    n2 = RawFileNotification(
        root_id="r1",
        relative_path="f2.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=200,
    )
    n3 = RawFileNotification(
        root_id="r1",
        relative_path="f3.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=300,
    )

    correlator.process_notification(n1)
    correlator.process_notification(n2)
    correlator.process_notification(n3)

    # Should only retain max 2 (f2 and f3, f1 evicted)
    assert correlator.pending_count("r1") == 2


def test_correlator_evict_expired_method():
    correlator = RenameCorrelator(correlation_window_ns=200_000_000)

    n1 = RawFileNotification(
        root_id="r1",
        relative_path="expired.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000,
    )
    n2 = RawFileNotification(
        root_id="r1",
        relative_path="fresh.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=500_000_000,
    )

    correlator.process_notification(n1)
    correlator.process_notification(n2)

    evicted = correlator.evict_expired(current_monotonic_ns=550_000_000)
    assert len(evicted) == 1
    assert evicted[0].relative_path == "expired.txt"
    assert correlator.pending_count("r1") == 1


def test_correlator_directory_rename():
    correlator = RenameCorrelator()

    old_dir = RawFileNotification(
        root_id="r1",
        relative_path="MyFolder_Old",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000,
        is_directory=True,
    )
    new_dir = RawFileNotification(
        root_id="r1",
        relative_path="MyFolder_New",
        action=WindowsFileAction.RENAMED_NEW_NAME,
        monotonic_ns=2_000,
        is_directory=True,
    )

    correlator.process_notification(old_dir)
    res = correlator.process_notification(new_dir)

    assert res is not None
    assert res.old_path == "MyFolder_Old"
    assert res.new_path == "MyFolder_New"
    assert res.is_directory is True


def test_correlator_clear():
    correlator = RenameCorrelator()

    old_notif = RawFileNotification(
        root_id="r1",
        relative_path="test.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
        monotonic_ns=1_000,
    )
    correlator.process_notification(old_notif)
    assert correlator.pending_count("r1") == 1

    correlator.clear("r1")
    assert correlator.pending_count("r1") == 0
