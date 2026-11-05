import ctypes
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

from kuyebiko.collectors.base import BaseWatcher, WatcherHealth
from kuyebiko.collectors.models import MonitoredRoot, RawFileNotification
from kuyebiko.collectors.windows.api import (
    DEFAULT_BUFFER_SIZE,
    DEFAULT_NOTIFY_FILTER,
    ERROR_ACCESS_DENIED,
    ERROR_NOTIFY_ENUM_DIR,
    ERROR_OPERATION_ABORTED,
    MAX_BUFFER_SIZE,
    MIN_BUFFER_SIZE,
    cancel_io_for_handle,
    close_directory_handle,
    is_valid_handle,
    open_directory_handle,
    read_directory_changes,
)
from kuyebiko.collectors.windows.parser import parse_file_notify_information
from kuyebiko.core.exceptions import BufferParseError, WatcherError
from kuyebiko.models.telemetry import (
    CollectorStatus,
    MonitoringStatus,
    TelemetrySnapshot,
)

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
        if not isinstance(buffer_size, int) or isinstance(buffer_size, bool):
            raise ValueError(
                f"buffer_size must be an integer, got {type(buffer_size).__name__}"
            )
        if buffer_size < MIN_BUFFER_SIZE:
            raise ValueError(
                f"buffer_size must be at least {MIN_BUFFER_SIZE} bytes, "
                f"got {buffer_size}"
            )
        if buffer_size > MAX_BUFFER_SIZE:
            raise ValueError(
                f"buffer_size cannot exceed {MAX_BUFFER_SIZE} bytes, got {buffer_size}"
            )
        if buffer_size % 4 != 0:
            raise ValueError(
                f"buffer_size must be 4-byte (DWORD) aligned, got {buffer_size}"
            )

        self._root = root
        self._callback = callback
        self._buffer_size = buffer_size
        self._notify_filter = notify_filter

        self._handle: int | None = None
        self._thread: threading.Thread | None = None
        self._is_running = threading.Event()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Operational telemetry and degradation accounting
        self._health: WatcherHealth = WatcherHealth.STOPPED
        self._degraded = False
        self._degradation_reason: str | None = None
        self._degradation_history: list[str] = []
        self._overflow_count = 0
        self._gap_count = 0
        self._malformed_buffer_count = 0
        self._parser_failure_count = 0
        self._events_observed = 0
        self._last_event_at: datetime | None = None
        self._last_recovered_at: datetime | None = None

    @property
    def root(self) -> MonitoredRoot:
        return self._root

    @property
    def root_id(self) -> str:
        return self._root.root_id

    @property
    def health(self) -> WatcherHealth:
        with self._lock:
            return self._health

    @property
    def is_degraded(self) -> bool:
        with self._lock:
            return self._degraded

    @property
    def degradation_reason(self) -> str | None:
        with self._lock:
            return self._degradation_reason

    @property
    def overflow_count(self) -> int:
        with self._lock:
            return self._overflow_count

    @property
    def gap_count(self) -> int:
        with self._lock:
            return self._gap_count

    @property
    def events_observed(self) -> int:
        with self._lock:
            return self._events_observed

    @property
    def malformed_buffer_count(self) -> int:
        with self._lock:
            return self._malformed_buffer_count

    @property
    def parser_failure_count(self) -> int:
        with self._lock:
            return self._parser_failure_count

    def is_running(self) -> bool:
        return self._is_running.is_set()

    def start(self) -> None:
        """Start the background monitoring thread transactionally.

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

            # Assign handle and reset shutdown controls
            self._handle = handle
            self._stop_event.clear()

            # Transactional thread startup: if Thread.start() raises,
            # we MUST close the newly opened directory handle to prevent leaks.
            try:
                thread = threading.Thread(
                    target=self._worker_loop,
                    name=f"kuyebiko-watcher-{self.root_id}",
                    daemon=True,
                )
                thread.start()
                self._thread = thread
                self._is_running.set()
                self._health = WatcherHealth.HEALTHY
                logger.info(
                    "Started native Windows watcher for root '%s' on '%s' (rec=%s)",
                    self.root_id,
                    validated_path,
                    self._root.recursive,
                )
            except Exception as thread_err:
                cleanup_err: Exception | None = None
                try:
                    close_directory_handle(handle)
                    self._handle = None
                except Exception as close_err:
                    cleanup_err = close_err
                    logger.critical(
                        "Failed to close handle %d on thread start error for '%s': %s",
                        handle,
                        self.root_id,
                        close_err,
                    )

                self._thread = None
                self._is_running.clear()
                if cleanup_err is not None:
                    self._health = WatcherHealth.ERROR
                    raise WatcherError(
                        f"Thread start failed ({thread_err}) AND handle cleanup "
                        f"failed ({cleanup_err}) for root '{self.root_id}'"
                    ) from thread_err

                self._health = WatcherHealth.STOPPED
                raise WatcherError(
                    f"Failed to start worker thread for root '{self.root_id}': "
                    f"{thread_err}"
                ) from thread_err

    def stop(self) -> None:
        """Cleanly cancel pending reads and stop the background monitoring thread.

        Raises:
            WatcherError: If the worker thread fails to terminate within the timeout.
        """
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
                self._mark_degraded(
                    f"Watcher thread for root '{self.root_id}' did not terminate "
                    "within timeout; handle retained to prevent use-after-close race."
                )
                raise WatcherError(
                    f"Watcher thread for root '{self.root_id}' failed to terminate "
                    "within timeout; handle retained to prevent use-after-close race."
                )

        with self._lock:
            if self._handle is not None and is_valid_handle(self._handle):
                close_directory_handle(self._handle)
                self._handle = None

            self._thread = None
            self._is_running.clear()
            self._health = WatcherHealth.STOPPED
            logger.info("Stopped watcher for root '%s'", self.root_id)

    def _mark_degraded(self, reason: str) -> None:
        self._degraded = True
        self._degradation_reason = reason
        self._degradation_history.append(f"[{datetime.now(UTC).isoformat()}] {reason}")
        self._health = WatcherHealth.DEGRADED
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
                    with self._lock:
                        self._overflow_count += 1
                        self._gap_count += 1
                        self._mark_degraded(
                            "Notification buffer overflow (ERROR_NOTIFY_ENUM_DIR). "
                            "Filesystem events were dropped by Windows kernel."
                        )
                    # Brief backoff to allow kernel buffer pressure to subside
                    time.sleep(0.05)
                    continue

                if error_code == ERROR_ACCESS_DENIED:
                    with self._lock:
                        self._health = WatcherHealth.ERROR
                        self._mark_degraded(
                            f"Access denied to monitored directory '{self._root.path}'"
                        )
                    break

                with self._lock:
                    self._health = WatcherHealth.ERROR
                    self._mark_degraded(
                        f"ReadDirectoryChangesW failed with error code: {error_code}"
                    )
                time.sleep(0.1)
                continue

            # Zero bytes on success indicates possible buffer overflow
            if bytes_returned == 0:
                with self._lock:
                    self._gap_count += 1
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
                with self._lock:
                    self._parser_failure_count += 1
                    self._malformed_buffer_count += 1
                    self._mark_degraded(f"Failed to parse notification buffer: {err}")
                continue

            # Successful reception and parse of notifications
            with self._lock:
                self._events_observed += len(parsed_entries)
                self._last_event_at = observed_at
                # If previously degraded and now successfully receiving again,
                # mark collection recovery while preserving the historical gap
                if self._degraded:
                    self._last_recovered_at = observed_at
                    self._health = WatcherHealth.HEALTHY

            for entry in parsed_entries:
                try:
                    notification = RawFileNotification(
                        root_id=self.root_id,
                        relative_path=entry.relative_path,
                        action=entry.action,
                        observed_at=observed_at,
                        monotonic_ns=monotonic_ns,
                        is_directory=entry.is_directory,
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

    def get_telemetry_snapshot(self) -> TelemetrySnapshot:
        """Generate an operational health TelemetrySnapshot for this watcher."""
        with self._lock:
            if self._health == WatcherHealth.DEGRADED:
                mon_status = MonitoringStatus.DEGRADED
                col_status = CollectorStatus.DEGRADED
            elif self._health == WatcherHealth.ERROR:
                mon_status = MonitoringStatus.ERROR
                col_status = CollectorStatus.ERROR
            elif self.is_running():
                mon_status = MonitoringStatus.RUNNING
                col_status = CollectorStatus.ACTIVE
            else:
                mon_status = MonitoringStatus.STOPPED
                col_status = CollectorStatus.INACTIVE

            # Build list of distinct non-empty degradation reasons
            reasons: list[str] = []
            if self._degradation_reason:
                reasons.append(self._degradation_reason)
            for item in self._degradation_history:
                if item not in reasons:
                    reasons.append(item)

            return TelemetrySnapshot(
                collector_id=f"windows-watcher-{self.root_id}",
                root_id=self.root_id,
                monitoring_status=mon_status,
                collector_status=col_status,
                events_received=self._events_observed,
                events_dropped=0,  # Kernel overflow dropped count is unknown
                collection_errors=self._overflow_count + self._parser_failure_count,
                last_event_at=self._last_event_at,
                last_heartbeat=datetime.now(UTC),
                observed_at=datetime.now(UTC),
                degradation_reasons=reasons,
            )
