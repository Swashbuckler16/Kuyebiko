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
    ERROR_INVALID_HANDLE,
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
        self._stop_lock = threading.Lock()

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

    def has_active_resources(self) -> bool:
        """Return True if native resources (OS handle or thread) remain allocated."""
        with self._lock:
            handle_active = self._handle is not None and is_valid_handle(self._handle)
            thread_active = self._thread is not None and self._thread.is_alive()
            return handle_active or thread_active

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

            # Safely initialize state BEFORE the worker thread starts executing
            self._handle = handle
            self._stop_event.clear()
            self._is_running.set()
            self._health = WatcherHealth.HEALTHY

            thread = threading.Thread(
                target=self._worker_loop,
                name=f"kuyebiko-watcher-{self.root_id}",
                daemon=True,
            )
            self._thread = thread

            # Transactional thread startup: if Thread.start() raises,
            # we MUST close the newly opened directory handle to prevent leaks.
            try:
                thread.start()
                logger.info(
                    "Started native Windows watcher for root '%s' on '%s' (rec=%s)",
                    self.root_id,
                    validated_path,
                    self._root.recursive,
                )
            except Exception as thread_err:
                self._thread = None
                self._is_running.clear()

                cleanup_err: Exception | None = None
                try:
                    closed = close_directory_handle(handle)
                    if closed:
                        self._handle = None
                    else:
                        cleanup_err = OSError(
                            f"CloseHandle returned FALSE for handle {handle}"
                        )
                        logger.critical(
                            "CloseHandle failed for handle %d on '%s'",
                            handle,
                            self.root_id,
                        )
                except Exception as close_err:
                    cleanup_err = close_err
                    logger.critical(
                        "Exception closing handle %d for '%s': %s",
                        handle,
                        self.root_id,
                        close_err,
                    )

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

        Thread-safe against concurrent stop invocations.

        Raises:
            WatcherError: If the worker thread fails to terminate within the timeout
                or if closing the native handle fails.
        """
        with self._stop_lock:
            with self._lock:
                # If neither running nor holding resources, nothing to stop
                if (
                    not self.is_running()
                    and self._thread is None
                    and (self._handle is None or not is_valid_handle(self._handle))
                ):
                    return

                self._stop_event.set()
                target_handle = self._handle
                target_thread = self._thread

                # Signal cancellation to any pending ReadDirectoryChangesW call
                if target_handle is not None and is_valid_handle(target_handle):
                    cancel_io_for_handle(target_handle)

            # Wait for worker thread outside the state lock to avoid deadlock
            if target_thread is not None and target_thread.is_alive():
                target_thread.join(timeout=5.0)
                if target_thread.is_alive():
                    msg = (
                        f"Watcher thread for root '{self.root_id}' failed to terminate "
                        "within timeout; handle retained to prevent use-after-close."
                    )
                    self._mark_degraded(msg, is_error=True)
                    raise WatcherError(msg)

            with self._lock:
                self._thread = None
                self._is_running.clear()

                # Cleanly close the directory handle
                if self._handle is not None and is_valid_handle(self._handle):
                    handle_val = self._handle
                    try:
                        closed = close_directory_handle(handle_val)
                    except Exception as err:
                        msg = (
                            f"Error closing handle {handle_val} for '{self.root_id}': "
                            f"{err}"
                        )
                        self._mark_degraded(msg, is_error=True)
                        raise WatcherError(
                            f"Exception closing handle for root '{self.root_id}': {err}"
                        ) from err

                    if closed:
                        self._handle = None
                        if self._health != WatcherHealth.ERROR:
                            self._health = WatcherHealth.STOPPED
                        logger.info("Stopped watcher for root '%s'", self.root_id)
                    else:
                        # Retain handle reference for later retry!
                        msg = (
                            f"CloseHandle failed on handle {handle_val} for "
                            f"'{self.root_id}'"
                        )
                        self._mark_degraded(msg, is_error=True)
                        raise WatcherError(
                            f"CloseHandle failed for root '{self.root_id}'"
                        )
                else:
                    if self._health != WatcherHealth.ERROR:
                        self._health = WatcherHealth.STOPPED
                    logger.info("Stopped watcher for root '%s'", self.root_id)

    def _mark_degraded(self, reason: str, is_error: bool = False) -> None:
        self._degraded = True
        self._degradation_reason = reason
        self._degradation_history.append(f"[{datetime.now(UTC).isoformat()}] {reason}")
        if is_error:
            self._health = WatcherHealth.ERROR
            logger.error("Error recorded for watcher '%s': %s", self.root_id, reason)
        else:
            if self._health != WatcherHealth.ERROR:
                self._health = WatcherHealth.DEGRADED
            logger.warning(
                "Telemetry degraded for watcher '%s': %s",
                self.root_id,
                reason,
            )

    def _worker_loop(self) -> None:
        """Dedicated background thread loop polling ReadDirectoryChangesW."""
        buffer = ctypes.create_string_buffer(self._buffer_size)
        consecutive_errors = 0

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
                    # CancelIoEx was called for clean shutdown
                    break

                if error_code == ERROR_NOTIFY_ENUM_DIR:
                    consecutive_errors = 0
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

                if error_code in (ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE):
                    with self._lock:
                        self._mark_degraded(
                            f"Fatal error ({error_code}) on '{self._root.path}'",
                            is_error=True,
                        )
                    break

                consecutive_errors += 1
                with self._lock:
                    self._mark_degraded(
                        f"ReadDirectoryChangesW failed with error code: {error_code}",
                        is_error=(consecutive_errors >= 3),
                    )

                if consecutive_errors >= 3:
                    logger.critical(
                        "Terminating worker for '%s' after %d unexpected errors",
                        self.root_id,
                        consecutive_errors,
                    )
                    break

                # Bounded backoff for transient unexpected errors
                time.sleep(0.05 * consecutive_errors)
                continue

            consecutive_errors = 0

            # Zero bytes on success indicates possible buffer overflow / gap
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
                # Only recover to HEALTHY if not in fatal ERROR state
                if self._degraded and self._health != WatcherHealth.ERROR:
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
                events_dropped=0,  # Exact drop count is unknown; kernel does not count
                uncounted_event_loss=(self._overflow_count > 0 or self._gap_count > 0),
                gap_count=self._gap_count,
                overflow_count=self._overflow_count,
                collection_errors=self._overflow_count + self._parser_failure_count,
                last_event_at=self._last_event_at,
                last_heartbeat=datetime.now(UTC),
                observed_at=datetime.now(UTC),
                degradation_reasons=reasons,
            )
