"""Conservative duplicate event detection for Kuyebiko event processing.

Enforces conservative deduplication to filter identical notification deliveries
without suppressing legitimate rapid filesystem modifications, multi-chunk writes,
or create-modify-rename sequences essential for ransomware behavior detection.
"""

import logging
import threading
from collections import OrderedDict
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction

logger = logging.getLogger("kuyebiko.processing.deduplication")


class EventFingerprint(NamedTuple):
    """Immutable fingerprint uniquely identifying a notification instance."""

    root_id: str
    relative_path: str
    action: WindowsFileAction
    is_directory: bool | None
    monotonic_ns: int


class DeduplicationMetrics(BaseModel):
    """Snapshot of duplicate event filter metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_examined: int = Field(ge=0)
    duplicates_suppressed: int = Field(ge=0)
    cache_size: int = Field(ge=0)
    cache_evictions: int = Field(ge=0)
    deduplication_errors: int = Field(ge=0)


class EventDeduplicator:
    """Thread-safe conservative deduplicator for raw filesystem notifications.

    Only filters true duplicate notifications (identical root, path, action,
    and observation monotonic timestamp). Never suppresses successive writes,
    distinct modifications, or create-modify progressions across time.
    """

    def __init__(
        self,
        max_cache_size: int = 1000,
        enabled: bool = True,
    ) -> None:
        """Initialize the deduplicator.

        Args:
            max_cache_size: Maximum entries retained in the bounded fingerprint cache.
            enabled: If False, all notifications pass through without suppression.
        """
        if max_cache_size < 1:
            raise ValueError(f"max_cache_size must be at least 1, got {max_cache_size}")

        self._max_cache_size = max_cache_size
        self._enabled = enabled
        self._cache: OrderedDict[EventFingerprint, None] = OrderedDict()
        self._lock = threading.Lock()

        # Operational metrics
        self._total_examined = 0
        self._duplicates_suppressed = 0
        self._cache_evictions = 0
        self._deduplication_errors = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    def is_duplicate(self, notification: RawFileNotification) -> bool:
        """Evaluate whether a notification is an exact duplicate.

        Args:
            notification: The RawFileNotification to inspect.

        Returns:
            True if the notification is a suppressed duplicate, False otherwise.
        """
        if not self._enabled:
            with self._lock:
                self._total_examined += 1
            return False

        if not isinstance(notification, RawFileNotification):
            with self._lock:
                self._deduplication_errors += 1
            return False

        fingerprint = EventFingerprint(
            root_id=notification.root_id,
            relative_path=notification.relative_path,
            action=notification.action,
            is_directory=notification.is_directory,
            monotonic_ns=notification.monotonic_ns,
        )

        with self._lock:
            self._total_examined += 1

            if fingerprint in self._cache:
                self._duplicates_suppressed += 1
                logger.debug(
                    "Suppressed exact duplicate notification in root '%s': "
                    "%s (action=%s)",
                    notification.root_id,
                    notification.relative_path,
                    notification.action.name,
                )
                return True

            # Insert into bounded cache
            if len(self._cache) >= self._max_cache_size:
                self._cache.popitem(last=False)
                self._cache_evictions += 1

            self._cache[fingerprint] = None
            return False

    def clear(self) -> None:
        """Clear the internal fingerprint cache."""
        with self._lock:
            self._cache.clear()

    def get_metrics(self) -> DeduplicationMetrics:
        """Return a thread-safe snapshot of deduplication metrics."""
        with self._lock:
            return DeduplicationMetrics(
                total_examined=self._total_examined,
                duplicates_suppressed=self._duplicates_suppressed,
                cache_size=len(self._cache),
                cache_evictions=self._cache_evictions,
                deduplication_errors=self._deduplication_errors,
            )
