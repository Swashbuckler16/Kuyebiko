import sys
import threading
import time
from pathlib import Path

import pytest

from kuyebiko.collectors.base import WatcherHealth
from kuyebiko.collectors.models import (
    MonitoredRoot,
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.registry import MonitoredRootRegistry
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.collectors.windows.watcher import WindowsDirectoryWatcher
from kuyebiko.models.events import EventType, FileEvent

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


def test_native_watcher_directory_operations(tmp_path: Path):
    """Verify detection of directory creation, rename, nested files, and deletion."""
    root = MonitoredRoot(root_id="dir-ops", path=tmp_path, recursive=True)
    events: list[RawFileNotification] = []

    watcher = WindowsDirectoryWatcher(root=root, callback=lambda n: events.append(n))
    watcher.start()
    time.sleep(0.15)

    try:
        # 1. Create subdirectory
        sub_dir = tmp_path / "test_folder"
        sub_dir.mkdir()
        assert wait_for_events(events, 1), "Did not receive folder ADDED"
        assert any(
            e.action == WindowsFileAction.ADDED and "test_folder" in e.relative_path
            for e in events
        )

        # 2. Rename subdirectory
        current_count = len(events)
        renamed_sub = tmp_path / "renamed_folder"
        sub_dir.rename(renamed_sub)
        assert wait_for_events(events, current_count + 1), "Folder rename missed"
        rename_actions = {
            WindowsFileAction.RENAMED_OLD_NAME,
            WindowsFileAction.RENAMED_NEW_NAME,
        }
        assert any(e.action in rename_actions for e in events[current_count:])

        # 3. Create file inside renamed directory
        current_count = len(events)
        nested_file = renamed_sub / "inner_file.txt"
        nested_file.write_text("inner payload", encoding="utf-8")
        assert wait_for_events(events, current_count + 1), "Nested file ADDED missed"
        assert any(
            e.action == WindowsFileAction.ADDED and "inner_file.txt" in e.relative_path
            for e in events[current_count:]
        )

        # 4. Delete nested file and directory
        current_count = len(events)
        nested_file.unlink()
        renamed_sub.rmdir()
        assert wait_for_events(events, current_count + 1), "Folder REMOVED missed"
        assert any(
            e.action == WindowsFileAction.REMOVED for e in events[current_count:]
        )
    finally:
        watcher.stop()


def test_native_watcher_rapid_filesystem_burst(tmp_path: Path):
    """Verify watcher resilience and event delivery under bursty file activity."""
    root = MonitoredRoot(root_id="burst-root", path=tmp_path, recursive=True)
    events: list[RawFileNotification] = []

    watcher = WindowsDirectoryWatcher(root=root, callback=lambda n: events.append(n))
    watcher.start()
    time.sleep(0.15)

    num_files = 25
    created_files: list[Path] = []
    try:
        # Burst creations
        for i in range(num_files):
            f = tmp_path / f"burst_{i:03d}.txt"
            f.write_text(f"content {i}", encoding="utf-8")
            created_files.append(f)

        # Burst modifications on subset
        for f in created_files[:10]:
            f.write_text("modified burst payload", encoding="utf-8")

        # Burst deletions on subset
        for f in created_files[10:15]:
            f.unlink()

        # Bounded polling for burst events (25 creates + 10 mods + 5 dels = 40 ops)
        assert wait_for_events(events, 30, timeout=6.0), (
            f"Expected at least 30 burst events, got {len(events)}"
        )
        assert watcher.health in (WatcherHealth.HEALTHY, WatcherHealth.DEGRADED)
    finally:
        watcher.stop()

    assert watcher.is_running() is False
    assert watcher.health == WatcherHealth.STOPPED


def test_native_watcher_shutdown_during_concurrent_activity(tmp_path: Path):
    """Verify clean shutdown when filesystem operations are occurring concurrently."""
    root = MonitoredRoot(root_id="shutdown-race", path=tmp_path, recursive=True)
    events: list[RawFileNotification] = []

    watcher = WindowsDirectoryWatcher(root=root, callback=lambda n: events.append(n))
    watcher.start()
    time.sleep(0.15)

    stop_hammering = threading.Event()
    worker_error: list[Exception] = []

    def hammer_filesystem() -> None:
        idx = 0
        try:
            while not stop_hammering.is_set():
                p = tmp_path / f"hammer_{idx}.tmp"
                p.write_text("hammer", encoding="utf-8")
                if p.exists():
                    p.unlink(missing_ok=True)
                idx += 1
                time.sleep(0.005)
        except Exception as err:
            worker_error.append(err)

    hammer_thread = threading.Thread(target=hammer_filesystem, daemon=True)
    hammer_thread.start()

    # Allow hammer to generate events
    time.sleep(0.1)

    # Stop watcher while hammering is underway
    try:
        watcher.stop()
    finally:
        stop_hammering.set()
        hammer_thread.join(timeout=3.0)

    assert not hammer_thread.is_alive()
    assert watcher.is_running() is False
    assert watcher.health == WatcherHealth.STOPPED


def test_native_watcher_end_to_end_normalization_pipeline(tmp_path: Path):
    """Verify live Win32 events flow through RenameCorrelator and EventNormalizer."""
    root = MonitoredRoot(root_id="e2e-root", path=tmp_path, recursive=True)
    correlator = RenameCorrelator(correlation_window_ns=2_000_000_000)
    normalizer = EventNormalizer()
    normalized_events: list[FileEvent] = []

    def pipeline_callback(notif: RawFileNotification) -> None:
        correlated = correlator.process_notification(notif)
        if correlated is not None:
            normalized = normalizer.normalize_correlated_rename(correlated)
            normalized_events.append(normalized)
        elif notif.action not in (
            WindowsFileAction.RENAMED_OLD_NAME,
            WindowsFileAction.RENAMED_NEW_NAME,
        ):
            normalized = normalizer.normalize_notification(notif)
            normalized_events.append(normalized)

    watcher = WindowsDirectoryWatcher(root=root, callback=pipeline_callback)
    watcher.start()
    time.sleep(0.15)

    try:
        # 1. Create file
        f = tmp_path / "e2e_target.txt"
        f.write_text("initial e2e content", encoding="utf-8")

        # 2. Modify file
        f.write_text("updated e2e content", encoding="utf-8")

        # 3. Rename file
        f_renamed = tmp_path / "e2e_renamed.txt"
        f.rename(f_renamed)

        # 4. Delete file
        f_renamed.unlink()

        # Bounded wait for all 4 distinct normalized operations
        start = time.perf_counter()
        while time.perf_counter() - start < 5.0:
            types_seen = {e.event_type for e in normalized_events}
            if {
                EventType.CREATED,
                EventType.MODIFIED,
                EventType.RENAMED,
                EventType.DELETED,
            }.issubset(types_seen):
                break
            time.sleep(0.05)

        types_seen = {e.event_type for e in normalized_events}
        assert EventType.CREATED in types_seen, f"Missing CREATED: {types_seen}"
        assert EventType.MODIFIED in types_seen, f"Missing MODIFIED: {types_seen}"
        assert EventType.RENAMED in types_seen, f"Missing RENAMED: {types_seen}"
        assert EventType.DELETED in types_seen, f"Missing DELETED: {types_seen}"

        # Verify monotonic sequence numbers
        seq_nums = [e.sequence_number for e in normalized_events]
        assert seq_nums == sorted(seq_nums)
        assert len(set(seq_nums)) == len(seq_nums)

        # Verify rename event details
        rename_event = next(
            e for e in normalized_events if e.event_type == EventType.RENAMED
        )
        assert rename_event.old_path is not None
        assert rename_event.new_path is not None
        assert "e2e_target.txt" in str(rename_event.old_path)
        assert "e2e_renamed.txt" in str(rename_event.new_path)

        # Verify telemetry snapshot
        assert watcher.events_observed >= 4
        assert watcher.health in (WatcherHealth.HEALTHY, WatcherHealth.DEGRADED)
        snap = watcher.get_telemetry_snapshot()
        assert snap.events_received >= 4
    finally:
        watcher.stop()
