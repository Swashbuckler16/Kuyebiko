from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import StrEnum

from kuyebiko.collectors.models import MonitoredRoot, RawFileNotification
from kuyebiko.models.telemetry import (
    CollectorStatus,
    MonitoringStatus,
    TelemetrySnapshot,
)

NotificationCallback = Callable[[RawFileNotification], None]


class WatcherHealth(StrEnum):
    """Operational health state of a filesystem watcher."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    ERROR = "error"


class BaseWatcher(ABC):
    """Abstract base class defining the filesystem watcher interface."""

    @property
    @abstractmethod
    def root(self) -> MonitoredRoot:
        """The monitored root configuration associated with this watcher."""

    @property
    @abstractmethod
    def root_id(self) -> str:
        """Unique identifier of the monitored root."""

    @abstractmethod
    def start(self) -> None:
        """Start directory monitoring on a background worker thread.

        Raises:
            WatcherError: If monitoring fails to start or is already active.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop directory monitoring cleanly and release all allocated resources."""

    @abstractmethod
    def is_running(self) -> bool:
        """Return True if the background watcher worker is currently running."""

    @property
    @abstractmethod
    def is_degraded(self) -> bool:
        """Return True if the watcher has encountered telemetry degradation."""

    @property
    @abstractmethod
    def degradation_reason(self) -> str | None:
        """Return diagnostic explanation if the watcher is in a degraded state."""

    @property
    def health(self) -> WatcherHealth:
        """Return current operational health state."""
        return WatcherHealth.HEALTHY if self.is_running() else WatcherHealth.STOPPED

    @property
    def overflow_count(self) -> int:
        """Return number of kernel notification buffer overflow events."""
        return 0

    @property
    def gap_count(self) -> int:
        """Return number of telemetry gap / event loss conditions."""
        return 0

    @property
    def events_observed(self) -> int:
        """Return total count of filesystem events observed by this watcher."""
        return 0

    def get_telemetry_snapshot(self) -> TelemetrySnapshot:
        """Return a TelemetrySnapshot model capturing the current health state."""
        mon_status = (
            MonitoringStatus.RUNNING if self.is_running() else MonitoringStatus.STOPPED
        )
        col_status = (
            CollectorStatus.ACTIVE if self.is_running() else CollectorStatus.INACTIVE
        )
        reasons = [self.degradation_reason] if self.degradation_reason else []

        return TelemetrySnapshot(
            collector_id=f"watcher-{self.root_id}",
            root_id=self.root_id,
            monitoring_status=mon_status,
            collector_status=col_status,
            events_received=self.events_observed,
            events_dropped=0,
            collection_errors=self.overflow_count,
            degradation_reasons=reasons,
        )
