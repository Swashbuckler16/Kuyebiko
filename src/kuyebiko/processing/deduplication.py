"""Conservative duplicate event detection for Kuyebiko event processing.

Enforces conservative deduplication to filter identical notification deliveries
without suppressing legitimate rapid filesystem modifications, multi-chunk writes,
or create-modify-rename sequences essential for ransomware behavior detection.
"""

import logging
import threading
import time
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
    cache_expirations: int = Field(default=0, ge=0)
    deduplication_errors: int = Field(ge=0)


class EventDeduplicator:
    """Thread-safe conservative deduplicator for raw filesystem notifications.

    Only filters true duplicate notifications (identical root, path, action,
    and observation monotonic timestamp). Evicts stale entries based on a
    time-to-live (TTL) window and bounds memory capacity with FIFO eviction.
    """

    def __init__(
        self,
        max_cache_size: int = 1000,
        ttl_seconds: float = 5.0,
        enabled: bool = True,
    ) -> None:
        """Initialize the deduplicator.

        Args:
            max_cache_size: Maximum entries retained in the bounded fingerprint cache.
            ttl_seconds: Time-to-live in seconds before cache entries expire.
            enabled: If False, all notifications pass through without suppression.
        """
        if max_cache_size < 1:
            raise ValueError(f"max_cache_size must be at least 1, got {max_cache_size}")
        if ttl_seconds <= 0.0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds}")

        self._max_cache_size = max_cache_size
        self._ttl_ns = int(ttl_seconds * 1_000_000_000)
        self._enabled = enabled
        # Maps EventFingerprint -> inserted_monotonic_ns
        self._cache: OrderedDict[EventFingerprint, int] = OrderedDict()
        self._lock = threading.Lock()

        # Operational metrics
        self._total_examined = 0
        self._duplicates_suppressed = 0
        self._cache_evictions = 0
        self._cache_expirations = 0
        self._deduplication_errors = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_ns / 1_000_000_000.0

    def _evict_expired(self, now_ns: int) -> None:
        """Evict stale entries that exceeded the TTL window."""
        while self._cache:
            first_fingerprint, inserted_ns = next(iter(self._cache.items()))
            if now_ns - inserted_ns > self._ttl_ns:
                self._cache.popitem(last=False)
                self._cache_expirations += 1
            else:
                break

    def is_duplicate(
        self,
        notification: RawFileNotification,
        current_monotonic_ns: int | None = None,
    ) -> bool:
        """Evaluate whether a notification is an exact duplicate.

        Args:
            notification: The RawFileNotification to inspect.
            current_monotonic_ns: Optional current monotonic timestamp for testing.

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

        now_ns = (
            current_monotonic_ns
            if current_monotonic_ns is not None
            else time.monotonic_ns()
        )

        fingerprint = EventFingerprint(
            root_id=notification.root_id,
            relative_path=notification.relative_path,
            action=notification.action,
            is_directory=notification.is_directory,
            monotonic_ns=notification.monotonic_ns,
        )

        with self._lock:
            self._total_examined += 1

            # Evict expired entries before checking
            self._evict_expired(now_ns)

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

            # Insert into bounded cache with FIFO eviction on capacity overflow
            if len(self._cache) >= self._max_cache_size:
                self._cache.popitem(last=False)
                self._cache_evictions += 1

            self._cache[fingerprint] = now_ns
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
                cache_expirations=self._cache_expirations,
                deduplication_errors=self._deduplication_errors,
            )
