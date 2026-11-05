import ctypes
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

from kuyebiko.collectors.base import BaseWatcher
from kuyebiko.collectors.models import MonitoredRoot, RawFileNotification
from kuyebiko.collectors.windows.api import (
    DEFAULT_BUFFER_SIZE,
    DEFAULT_NOTIFY_FILTER,
    ERROR_ACCESS_DENIED,
    ERROR_NOTIFY_ENUM_DIR,
    ERROR_OPERATION_ABORTED,
    cancel_io_for_handle,
    close_directory_handle,
    is_valid_handle,
    open_directory_handle,
    read_directory_changes,
)
from kuyebiko.collectors.windows.parser import parse_file_notify_information
from kuyebiko.core.exceptions import BufferParseError, WatcherError

logger = logging.getLogger("kuyebiko.collectors.windows")


class WindowsDirectoryWatcher(BaseWatcher):
    """Native Windows filesystem watcher backed by ReadDirectoryChangesW."""

    def __init__(
        self,
        root: MonitoredRoot,
        callback: Callable[[RawFileNotification], None] | None = None,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
        notify_filter: int = DEFAULT_NOTIFY_FILTER,
    ) -> None:
        self._root = root
        self._callback = callback
        self._buffer_size = max(4096, buffer_size)
        self._notify_filter = notify_filter

        self._handle: int | None = None
        self._thread: threading.Thread | None = None
        self._is_running = threading.Event()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self._degraded = False
        self._degradation_reason: str | None = None

    @property
    def root(self) -> MonitoredRoot:
        return self._root

    @property
    def root_id(self) -> str:
        return self._root.root_id

    @property
    def is_degraded(self) -> bool:
        return self._degraded

    @property
    def degradation_reason(self) -> str | None:
        return self._degradation_reason

    def is_running(self) -> bool:
        return self._is_running.is_set()

    def start(self) -> None:
        """Start the background monitoring thread.

        Raises:
            WatcherError: If monitoring is already active or cannot be started.
        """
        with self._lock:
            if self.is_running():
                raise WatcherError(
                    f"Watcher for root '{self.root_id}' is already running"
                )

            # Validate that directory exists and is accessible
            try:
                validated_path = self._root.resolve_and_validate()
            except Exception as err:
                raise WatcherError(
                    f"Failed to validate monitored root '{self.root_id}': {err}"
                ) from err

            # Open Windows directory handle
            try:
                handle = open_directory_handle(str(validated_path))
            except Exception as err:
                raise WatcherError(
                    f"Failed to open directory handle for '{validated_path}': {err}"
                ) from err

            self._handle = handle
            self._stop_event.clear()
            self._is_running.set()
            self._degraded = False
            self._degradation_reason = None

            self._thread = threading.Thread(
                target=self._worker_loop,
                name=f"kuyebiko-watcher-{self.root_id}",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Started native Windows watcher for root '%s' on '%s' (recursive=%s)",
                self.root_id,
                validated_path,
                self._root.recursive,
            )

    def stop(self) -> None:
        """Cleanly cancel pending reads and stop the background monitoring thread."""
        with self._lock:
            if not self.is_running() and self._thread is None:
                return

            self._stop_event.set()

            # Signal cancellation to any pending ReadDirectoryChangesW call
            if self._handle is not None and is_valid_handle(self._handle):
                cancel_io_for_handle(self._handle)

        # Wait for worker thread outside the lock to avoid deadlock
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning(
                    "Watcher thread for root '%s' did not terminate within timeout",
                    self.root_id,
                )

        with self._lock:
            if self._handle is not None and is_valid_handle(self._handle):
                close_directory_handle(self._handle)
                self._handle = None

            self._thread = None
            self._is_running.clear()
            logger.info("Stopped watcher for root '%s'", self.root_id)

    def _mark_degraded(self, reason: str) -> None:
        self._degraded = True
        self._degradation_reason = reason
        logger.warning(
            "Telemetry degraded for watcher '%s': %s",
            self.root_id,
            reason,
        )

    def _worker_loop(self) -> None:
        """Dedicated background thread loop polling ReadDirectoryChangesW."""
        buffer = ctypes.create_string_buffer(self._buffer_size)

        while not self._stop_event.is_set():
            if self._handle is None or not is_valid_handle(self._handle):
                break

            success, bytes_returned, error_code = read_directory_changes(
                handle=self._handle,
                buffer=buffer,
                buffer_length=self._buffer_size,
                recursive=self._root.recursive,
                notify_filter=self._notify_filter,
            )

            # Check if stop was requested while blocked in ReadDirectoryChangesW
            if self._stop_event.is_set():
                break

            if not success:
                if error_code == ERROR_OPERATION_ABORTED:
                    # CancelIoEx was called
                    break

                if error_code == ERROR_NOTIFY_ENUM_DIR:
                    self._mark_degraded(
                        "Notification buffer overflow (ERROR_NOTIFY_ENUM_DIR). "
                        "Filesystem events were dropped by Windows kernel."
                    )
                    continue

                if error_code == ERROR_ACCESS_DENIED:
                    self._mark_degraded(
                        f"Access denied to monitored directory '{self._root.path}'"
                    )
                    break

                self._mark_degraded(
                    f"ReadDirectoryChangesW failed with error code: {error_code}"
                )
                # Sleep briefly to prevent high CPU loop on persistent errors
                time.sleep(0.1)
                continue

            # Zero bytes on success indicates possible buffer overflow
            if bytes_returned == 0:
                self._mark_degraded(
                    "ReadDirectoryChangesW returned 0 bytes with success. "
                    "Notification buffer may have overflowed."
                )
                continue

            # Capture accurate timing immediately upon receiving notifications
            observed_at = datetime.now(UTC)
            monotonic_ns = time.monotonic_ns()

            try:
                parsed_entries = parse_file_notify_information(
                    buffer.raw, bytes_returned
                )
            except BufferParseError as err:
                self._mark_degraded(f"Failed to parse notification buffer: {err}")
                continue

            for entry in parsed_entries:
                try:
                    notification = RawFileNotification(
                        root_id=self.root_id,
                        relative_path=entry.relative_path,
                        action=entry.action,
                        observed_at=observed_at,
                        monotonic_ns=monotonic_ns,
                    )
                    self._dispatch(notification)
                except Exception as err:
                    logger.error(
                        "Failed to construct RawFileNotification for '%s': %s",
                        entry.relative_path,
                        err,
                    )

        self._is_running.clear()

    def _dispatch(self, notification: RawFileNotification) -> None:
        """Deliver a notification to the registered consumer safely."""
        if self._callback is None:
            return

        try:
            self._callback(notification)
        except Exception as err:
            logger.exception(
                "Unhandled error in watcher callback for '%s': %s",
                self.root_id,
                err,
            )
