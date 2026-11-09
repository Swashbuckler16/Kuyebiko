import logging
import threading
from uuid import uuid4

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.collectors.rename_correlator import (
    CorrelatedRenameNotification,
    RenameCorrelator,
)
from kuyebiko.core.exceptions import NormalizationError
from kuyebiko.models.events import (
    CorrelationProvenanceType,
    EventSource,
    EventType,
    FileEvent,
    TelemetryQuality,
    sign_provenance_payload,
)

logger = logging.getLogger("kuyebiko.collectors.normalizer")


class EventNormalizer:
    """Normalizes raw filesystem notifications and rename pairs into FileEvent models.

    Maintains a thread-safe monotonic sequence counter and integrates with
    an optional RenameCorrelator to correlate Windows two-part rename notifications.
    """

    def __init__(
        self,
        rename_correlator: RenameCorrelator | None = None,
        source: EventSource = EventSource.WINDOWS_WATCHER,
    ) -> None:
        self._correlator = rename_correlator
        self._source = source
        self._sequence_counter = 0
        self._lock = threading.Lock()

    def _next_sequence(self) -> int:
        with self._lock:
            self._sequence_counter += 1
            return self._sequence_counter

    def normalize_notification(
        self,
        notification: RawFileNotification,
        quality: TelemetryQuality = TelemetryQuality.NORMAL,
        old_path: str | None = None,
        new_path: str | None = None,
    ) -> FileEvent | None:
        """Convert a single RawFileNotification into a normalized FileEvent.

        If a RenameCorrelator is configured and the notification is a rename action:
            Delegates to correlator.
            If a complete pair is formed, emits the RENAMED FileEvent.
            If the pair is still pending (e.g. RENAMED_OLD_NAME), returns None.
            If an un-correlated new rename arrives without an old rename, returns None.

        If old_path and new_path are explicitly provided for a rename action:
            Directly produces a RENAMED FileEvent without needing the correlator.

        For ADDED, MODIFIED, REMOVED:
            Immediately normalizes to CREATED, MODIFIED, DELETED FileEvent.

        Raises:
            NormalizationError: If fields are invalid, paths malformed, or rename
                is incomplete without a correlator.
        """
        # If correlator is configured, let it handle two-part rename notifications
        if (
            self._correlator is not None
            and notification.action
            in (
                WindowsFileAction.RENAMED_OLD_NAME,
                WindowsFileAction.RENAMED_NEW_NAME,
            )
            and (not old_path or not new_path)
        ):
            correlated = self._correlator.process_notification(notification)
            if correlated is None:
                return None
            return self.normalize_correlated_rename(correlated, quality=quality)

        action_mapping = {
            WindowsFileAction.ADDED: EventType.CREATED,
            WindowsFileAction.MODIFIED: EventType.MODIFIED,
            WindowsFileAction.REMOVED: EventType.DELETED,
        }

        if notification.action in (
            WindowsFileAction.RENAMED_OLD_NAME,
            WindowsFileAction.RENAMED_NEW_NAME,
        ):
            if not old_path or not new_path:
                msg = (
                    f"Cannot normalize raw rename ({notification.action.name}) "
                    "without both old_path and new_path provided or correlated."
                )
                logger.error(msg)
                raise NormalizationError(msg)
            event_type = EventType.RENAMED
            event_path = new_path
            event_old = old_path
            event_new = new_path
        elif notification.action in action_mapping:
            event_type = action_mapping[notification.action]
            event_path = notification.relative_path
            event_old = None
            event_new = None
        else:
            msg = f"Unsupported notification action: {notification.action}"
            logger.error(msg)
            raise NormalizationError(msg)

        seq = self._next_sequence()

        provenance = (
            f"explicit_pair:{event_old}->{event_new}"
            if event_type == EventType.RENAMED
            else None
        )

        try:
            return FileEvent(
                event_id=str(uuid4()),
                root_id=notification.root_id,
                file_path=event_path,
                event_type=event_type,
                old_path=event_old,
                new_path=event_new,
                is_directory=notification.is_directory,
                timestamp_utc=notification.observed_at,
                monotonic_ns=notification.monotonic_ns,
                source=self._source,
                sequence_number=seq,
                quality=quality,
                correlation_provenance=provenance,
            )
        except Exception as err:
            logger.error("Failed to construct normalized FileEvent: %s", err)
            raise NormalizationError(f"FileEvent validation failed: {err}") from err

    def normalize_correlated_rename(
        self,
        correlated: CorrelatedRenameNotification,
        quality: TelemetryQuality = TelemetryQuality.NORMAL,
    ) -> FileEvent:
        """Convert a CorrelatedRenameNotification into a validated RENAMED FileEvent."""
        seq = self._next_sequence()

        try:
            return FileEvent(
                event_id=str(uuid4()),
                root_id=correlated.root_id,
                file_path=correlated.new_path,
                event_type=EventType.RENAMED,
                old_path=correlated.old_path,
                new_path=correlated.new_path,
                is_directory=correlated.is_directory,
                timestamp_utc=correlated.observed_at,
                monotonic_ns=correlated.monotonic_ns,
                source=self._source,
                sequence_number=seq,
                quality=quality,
                correlation_provenance=sign_provenance_payload(
                    CorrelationProvenanceType.PHASE3_CORRELATOR,
                    correlated.old_path,
                    correlated.new_path,
                ),
            )
        except Exception as err:
            logger.error("Failed to construct normalized rename FileEvent: %s", err)
            raise NormalizationError(
                f"FileEvent rename validation failed: {err}"
            ) from err
