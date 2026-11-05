from abc import ABC, abstractmethod
from collections.abc import Callable

from kuyebiko.collectors.models import MonitoredRoot, RawFileNotification

NotificationCallback = Callable[[RawFileNotification], None]


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

