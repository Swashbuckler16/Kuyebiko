import sys
import time
from pathlib import Path

import pytest

from kuyebiko.collectors.models import (
    MonitoredRoot,
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.collectors.registry import MonitoredRootRegistry
from kuyebiko.collectors.windows.watcher import WindowsDirectoryWatcher

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Requires native Windows ReadDirectoryChangesW",
)


def wait_for_events(
    collected: list[RawFileNotification],
    min_count: int,
    timeout: float = 3.0,
) -> bool:
    """Poll with bounded timeout for expected event count."""
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        if len(collected) >= min_count:
            return True
        time.sleep(0.05)
    return len(collected) >= min_count


def test_native_watcher_file_crud_lifecycle(tmp_path: Path):
    """Verify that create, modify, delete, and rename events are captured."""
    root = MonitoredRoot(root_id="crud-root", path=tmp_path, recursive=True)
    events: list[RawFileNotification] = []

    watcher = WindowsDirectoryWatcher(root=root, callback=lambda n: events.append(n))
    watcher.start()
    time.sleep(0.15)  # Allow watcher worker to establish ReadDirectoryChangesW

    try:
        # 1. Create a file
        test_file = tmp_path / "lifecycle_doc.txt"
        test_file.write_text("initial content", encoding="utf-8")
        assert wait_for_events(events, 1), "Did not receive ADDED event"
        assert any(
            e.action == WindowsFileAction.ADDED
            and "lifecycle_doc.txt" in e.relative_path
            for e in events
        )

        # 2. Modify the file
        current_count = len(events)
        test_file.write_text("updated content modifying file", encoding="utf-8")
        assert wait_for_events(events, current_count + 1), "Did not receive MODIFIED"
        assert any(
            e.action == WindowsFileAction.MODIFIED
            and "lifecycle_doc.txt" in e.relative_path
            for e in events[current_count:]
        )

        # 3. Rename the file
        current_count = len(events)
        renamed_file = tmp_path / "renamed_doc.txt"
        test_file.rename(renamed_file)
        assert wait_for_events(events, current_count + 1), "Did not receive rename"
        # Windows reports renames as RENAMED_OLD_NAME and/or RENAMED_NEW_NAME
        rename_actions = {
            WindowsFileAction.RENAMED_OLD_NAME,
            WindowsFileAction.RENAMED_NEW_NAME,
        }
        assert any(e.action in rename_actions for e in events[current_count:])

        # 4. Delete the file
        current_count = len(events)
        renamed_file.unlink()
        assert wait_for_events(events, current_count + 1), "Did not receive REMOVED"
        assert any(
            e.action == WindowsFileAction.REMOVED
            and "renamed_doc.txt" in e.relative_path
            for e in events[current_count:]
        )

    finally:
        watcher.stop()


def test_native_watcher_recursive_vs_non_recursive(tmp_path: Path):
    """Verify recursive capture and non-recursive filtering."""
    sub_dir = tmp_path / "nested_dir"
    sub_dir.mkdir()

    # A. Recursive watcher captures subfolder events
    rec_events: list[RawFileNotification] = []
    rec_root = MonitoredRoot(root_id="rec-root", path=tmp_path, recursive=True)
    rec_watcher = WindowsDirectoryWatcher(
        root=rec_root, callback=lambda n: rec_events.append(n)
    )
    rec_watcher.start()
    time.sleep(0.15)

    try:
        nested_file = sub_dir / "nested_item.txt"
        nested_file.write_text("deep content", encoding="utf-8")
        assert wait_for_events(rec_events, 1), "Recursive missed nested file"
        assert any("nested_dir/nested_item.txt" in e.relative_path for e in rec_events)
    finally:
        rec_watcher.stop()

    # B. Non-recursive watcher does not monitor nested items
    non_rec_events: list[RawFileNotification] = []
    non_rec_root = MonitoredRoot(root_id="non-rec-root", path=tmp_path, recursive=False)
    non_rec_watcher = WindowsDirectoryWatcher(
        root=non_rec_root, callback=lambda n: non_rec_events.append(n)
    )
    non_rec_watcher.start()
    time.sleep(0.15)

    try:
        # Action in subdirectory
        nested_file2 = sub_dir / "nested_item_2.txt"
        nested_file2.write_text("should be ignored by non-recursive", encoding="utf-8")
        time.sleep(0.3)
        assert not any(
            "nested_item_2.txt" in e.relative_path for e in non_rec_events
        ), "Non-recursive watcher captured subdirectory file"

        # Action in top-level directory must be captured
        top_file = tmp_path / "top_level.txt"
        top_file.write_text("top content", encoding="utf-8")
        assert wait_for_events(non_rec_events, 1), "Non-recursive missed top-level"
        assert any("top_level.txt" in e.relative_path for e in non_rec_events)
    finally:
        non_rec_watcher.stop()


def test_native_watcher_stops_delivering_after_stop(tmp_path: Path):
    """Verify that after stop() is called, no further events are delivered."""
    root = MonitoredRoot(root_id="stop-test", path=tmp_path)
    events: list[RawFileNotification] = []

    watcher = WindowsDirectoryWatcher(root=root, callback=lambda n: events.append(n))
    watcher.start()
    time.sleep(0.15)

    f1 = tmp_path / "first.txt"
    f1.write_text("first", encoding="utf-8")
    assert wait_for_events(events, 1)

    # Stop monitoring
    watcher.stop()
    assert watcher.is_running() is False
    current_count = len(events)

    # Write file after stop
    f2 = tmp_path / "second.txt"
    f2.write_text("second", encoding="utf-8")
    time.sleep(0.3)

    assert len(events) == current_count, "Events delivered after watcher was stopped"


def test_multi_root_live_directory_isolation(tmp_path: Path):
    """Verify that multiple simultaneous live watchers attribute events correctly."""
    dir_alpha = tmp_path / "alpha_dir"
    dir_beta = tmp_path / "beta_dir"
    dir_alpha.mkdir()
    dir_beta.mkdir()

    alpha_events: list[RawFileNotification] = []
    beta_events: list[RawFileNotification] = []

    registry = MonitoredRootRegistry()
    registry.register(
        MonitoredRoot(root_id="alpha", path=dir_alpha),
        callback=lambda n: alpha_events.append(n),
    )
    registry.register(
        MonitoredRoot(root_id="beta", path=dir_beta),
        callback=lambda n: beta_events.append(n),
    )

    registry.start_all()
    time.sleep(0.2)

    try:
        # Create file only in Alpha
        file_a = dir_alpha / "doc_alpha.txt"
        file_a.write_text("alpha data", encoding="utf-8")

        # Create file only in Beta
        file_b = dir_beta / "doc_beta.txt"
        file_b.write_text("beta data", encoding="utf-8")

        assert wait_for_events(alpha_events, 1), "Alpha did not receive event"
        assert wait_for_events(beta_events, 1), "Beta did not receive event"

        # Verify strict isolation
        assert all(e.root_id == "alpha" for e in alpha_events)
        assert any("doc_alpha.txt" in e.relative_path for e in alpha_events)
        assert not any("doc_beta.txt" in e.relative_path for e in alpha_events)

        assert all(e.root_id == "beta" for e in beta_events)
        assert any("doc_beta.txt" in e.relative_path for e in beta_events)
        assert not any("doc_alpha.txt" in e.relative_path for e in beta_events)

    finally:
        registry.stop_all()
