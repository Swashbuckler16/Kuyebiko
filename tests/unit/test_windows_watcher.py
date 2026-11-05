import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.unit.test_windows_parser import make_entry

from kuyebiko.collectors.base import WatcherHealth
from kuyebiko.collectors.models import MonitoredRoot, WindowsFileAction
from kuyebiko.collectors.windows.api import (
    ERROR_NOTIFY_ENUM_DIR,
    ERROR_OPERATION_ABORTED,
)
from kuyebiko.collectors.windows.watcher import WindowsDirectoryWatcher
from kuyebiko.core.exceptions import WatcherError
from kuyebiko.models.telemetry import CollectorStatus, MonitoringStatus


def test_watcher_properties(tmp_path: Path):
    root = MonitoredRoot(root_id="root-prop", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    assert watcher.root == root
    assert watcher.root_id == "root-prop"
    assert watcher.is_running() is False
    assert watcher.is_degraded is False
    assert watcher.degradation_reason is None
    assert watcher.health == WatcherHealth.STOPPED
    assert watcher.overflow_count == 0
    assert watcher.gap_count == 0


def test_watcher_duplicate_start_prevented(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-dup", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    hang_event = threading.Event()

    def mock_read(*args, **kwargs):
        hang_event.wait(timeout=2.0)
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 1234,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: True,
    )

    try:
        watcher.start()
        assert watcher.is_running() is True
        assert watcher.health == WatcherHealth.HEALTHY

        with pytest.raises(WatcherError, match="already running"):
            watcher.start()
    finally:
        hang_event.set()
        watcher.stop()
        assert watcher.is_running() is False
        assert watcher.health == WatcherHealth.STOPPED


def test_watcher_open_handle_failure(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-fail", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    def fail_open(p):
        raise OSError(5, "Access is denied")

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        fail_open,
    )

    with pytest.raises(WatcherError, match="Failed to open directory handle"):
        watcher.start()

    assert watcher.is_running() is False
    assert watcher.health == WatcherHealth.STOPPED


def test_watcher_dispatches_notification(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-notify", path=tmp_path)
    received = []

    def on_event(n):
        received.append(n)

    raw_buf = make_entry(0, 1, "created_doc.txt")
    call_count = 0

    def mock_read(handle, buffer, buffer_length, recursive, notify_filter):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            buffer[: len(raw_buf)] = raw_buf
            return True, len(raw_buf), 0
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 4321,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: True,
    )

    watcher = WindowsDirectoryWatcher(root=root, callback=on_event)
    try:
        watcher.start()
        time.sleep(0.1)
        assert len(received) == 1
        assert received[0].relative_path == "created_doc.txt"
        assert received[0].action == WindowsFileAction.ADDED
        assert watcher.events_observed == 1
    finally:
        watcher.stop()


def test_watcher_handles_buffer_overflow_degradation(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-degraded", path=tmp_path)
    call_count = 0

    def mock_read(handle, buffer, buffer_length, recursive, notify_filter):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return False, 0, ERROR_NOTIFY_ENUM_DIR
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 999,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: True,
    )

    watcher = WindowsDirectoryWatcher(root=root)
    try:
        watcher.start()
        time.sleep(0.15)
        assert watcher.is_degraded is True
        assert "ERROR_NOTIFY_ENUM_DIR" in watcher.degradation_reason
        assert watcher.overflow_count >= 1
        assert watcher.gap_count >= 1
    finally:
        watcher.stop()


def test_watcher_callback_exception_does_not_crash_thread(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-cb-err", path=tmp_path)
    callback_mock = MagicMock(side_effect=RuntimeError("Faulty user callback"))

    raw_buf = make_entry(0, 3, "modified.txt")
    call_count = 0

    def mock_read(handle, buffer, buffer_length, recursive, notify_filter):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            buffer[: len(raw_buf)] = raw_buf
            return True, len(raw_buf), 0
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 100,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: True,
    )

    watcher = WindowsDirectoryWatcher(root=root, callback=callback_mock)
    try:
        watcher.start()
        time.sleep(0.15)
        assert callback_mock.call_count >= 1
    finally:
        watcher.stop()


def test_watcher_safe_repeated_stop(tmp_path: Path):
    root = MonitoredRoot(root_id="root-stop", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    watcher.stop()
    watcher.stop()
    assert watcher.is_running() is False


def test_watcher_buffer_size_validation(tmp_path: Path):
    root = MonitoredRoot(root_id="root-buf", path=tmp_path)

    with pytest.raises(ValueError, match="at least 4096 bytes"):
        WindowsDirectoryWatcher(root=root, buffer_size=1024)

    with pytest.raises(ValueError, match="cannot exceed 65536 bytes"):
        WindowsDirectoryWatcher(root=root, buffer_size=70000)

    with pytest.raises(ValueError, match="4-byte"):
        WindowsDirectoryWatcher(root=root, buffer_size=4097)

    with pytest.raises(ValueError, match="must be an integer"):
        WindowsDirectoryWatcher(root=root, buffer_size="65536")  # type: ignore

    with pytest.raises(ValueError, match="must be an integer"):
        WindowsDirectoryWatcher(root=root, buffer_size=True)  # type: ignore

    valid_watcher = WindowsDirectoryWatcher(root=root, buffer_size=8192)
    assert valid_watcher._buffer_size == 8192


def test_watcher_stop_times_out_and_raises_without_closing_handle(
    tmp_path: Path, monkeypatch
):
    root = MonitoredRoot(root_id="root-timeout", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    closed_handles = []
    hang_in_read = threading.Event()
    hang_in_join = threading.Event()

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 777,
    )

    def mock_read(*args, **kwargs):
        hang_in_read.wait(timeout=2.0)
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: closed_handles.append(h),
    )

    orig_join = threading.Thread.join

    def fast_timeout_join(thread_self, timeout=None):
        if not hang_in_join.is_set():
            return
        orig_join(thread_self, timeout=timeout)

    monkeypatch.setattr(threading.Thread, "join", fast_timeout_join)

    try:
        watcher.start()
        assert watcher.is_running() is True

        with pytest.raises(WatcherError, match="failed to terminate within timeout"):
            watcher.stop()

        assert watcher.is_degraded is True
        assert "use-after-close" in watcher.degradation_reason
        assert len(closed_handles) == 0

        hang_in_join.set()
        hang_in_read.set()
        time.sleep(0.05)

        watcher.stop()
        assert len(closed_handles) == 1
        assert closed_handles[0] == 777
        assert watcher.is_running() is False
    finally:
        hang_in_join.set()
        hang_in_read.set()


def test_watcher_thread_start_failure_transactional_cleanup(
    tmp_path: Path, monkeypatch
):
    root = MonitoredRoot(root_id="root-thread-fail", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    closed_handles = []
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 888,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: closed_handles.append(h),
    )

    def fail_thread_start(self):
        raise RuntimeError("Out of system thread resources")

    monkeypatch.setattr(threading.Thread, "start", fail_thread_start)

    with pytest.raises(WatcherError, match="Failed to start worker thread"):
        watcher.start()

    # Crucial assertion: Handle 888 MUST have been closed cleanly!
    assert len(closed_handles) == 1
    assert closed_handles[0] == 888
    assert watcher.is_running() is False
    assert watcher._handle is None
    assert watcher.health == WatcherHealth.STOPPED


def test_watcher_thread_start_failure_and_cleanup_failure(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-cleanup-fail", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 888,
    )

    def fail_close(h):
        raise OSError(6, "The handle is invalid")

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        fail_close,
    )

    def fail_thread_start(self):
        raise RuntimeError("Out of thread resources")

    monkeypatch.setattr(threading.Thread, "start", fail_thread_start)

    with pytest.raises(WatcherError, match="AND handle cleanup failed"):
        watcher.start()

    # Watcher state must reflect ERROR and retain handle for recovery/inspection
    assert watcher.health == WatcherHealth.ERROR
    assert watcher._handle == 888


def test_watcher_zero_bytes_success_marks_degraded(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-zero-bytes", path=tmp_path)
    call_count = 0

    def mock_read(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return True, 0, 0
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 101,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: True,
    )

    watcher = WindowsDirectoryWatcher(root=root)
    try:
        watcher.start()
        time.sleep(0.1)
        assert watcher.is_degraded is True
        assert watcher.gap_count >= 1
    finally:
        watcher.stop()


def test_watcher_telemetry_snapshot_generation(tmp_path: Path, monkeypatch):
    root = MonitoredRoot(root_id="root-snap", path=tmp_path)
    watcher = WindowsDirectoryWatcher(root=root)

    snap_stopped = watcher.get_telemetry_snapshot()
    assert snap_stopped.root_id == "root-snap"
    assert snap_stopped.monitoring_status == MonitoringStatus.STOPPED
    assert snap_stopped.collector_status == CollectorStatus.INACTIVE

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.open_directory_handle",
        lambda p: 101,
    )
    hang_event = threading.Event()

    def mock_read(*args, **kwargs):
        hang_event.wait(timeout=2.0)
        return False, 0, ERROR_OPERATION_ABORTED

    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.read_directory_changes",
        mock_read,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.cancel_io_for_handle",
        lambda h: True,
    )
    monkeypatch.setattr(
        "kuyebiko.collectors.windows.watcher.close_directory_handle",
        lambda h: True,
    )

    try:
        watcher.start()
        snap_running = watcher.get_telemetry_snapshot()
        assert snap_running.monitoring_status == MonitoringStatus.RUNNING
        assert snap_running.collector_status == CollectorStatus.ACTIVE

        # Mark degradation
        watcher._mark_degraded("Simulated buffer overflow")
        snap_deg = watcher.get_telemetry_snapshot()
        assert snap_deg.monitoring_status == MonitoringStatus.DEGRADED
        assert snap_deg.collector_status == CollectorStatus.DEGRADED
        assert len(snap_deg.degradation_reasons) >= 1
    finally:
        hang_event.set()
        watcher.stop()
