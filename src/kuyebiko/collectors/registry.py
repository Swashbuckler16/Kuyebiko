import logging
import threading
from collections.abc import Callable
from enum import Enum, auto
from pathlib import Path

from kuyebiko.collectors.base import BaseWatcher, NotificationCallback
from kuyebiko.collectors.models import MonitoredRoot, RawFileNotification
from kuyebiko.collectors.windows.watcher import WindowsDirectoryWatcher
from kuyebiko.core.exceptions import RegistryError

logger = logging.getLogger("kuyebiko.collectors.registry")

WatcherFactory = Callable[[MonitoredRoot, NotificationCallback], BaseWatcher]


class RootLifecycleState(Enum):
    """Lifecycle state of a registered monitored root."""

    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()
    ERROR = auto()


def _default_watcher_factory(
    root: MonitoredRoot,
    callback: NotificationCallback,
) -> BaseWatcher:
    return WindowsDirectoryWatcher(root=root, callback=callback)


class MonitoredRootRegistry:
    """Thread-safe registry for managing multiple monitored roots and their watchers."""

    def __init__(
        self,
        default_callback: NotificationCallback | None = None,
        watcher_factory: WatcherFactory | None = None,
    ) -> None:
        self._roots: dict[str, MonitoredRoot] = {}
        self._canonical_paths: dict[Path, str] = {}  # canonical path -> root_id
        self._watchers: dict[str, BaseWatcher] = {}
        self._states: dict[str, RootLifecycleState] = {}
        self._callbacks: dict[str, NotificationCallback] = {}

        self._default_callback = default_callback
        self._watcher_factory = watcher_factory or _default_watcher_factory
        self._lock = threading.RLock()

    def set_default_callback(self, callback: NotificationCallback | None) -> None:
        """Set or update the global fallback notification consumer."""
        with self._lock:
            self._default_callback = callback

    def register(
        self,
        root: MonitoredRoot,
        callback: NotificationCallback | None = None,
    ) -> None:
        """Register a new monitored directory root.

        Args:
            root: MonitoredRoot configuration.
            callback: Optional per-root notification consumer.

        Raises:
            RegistryError: If root_id or directory is already registered.
        """
        with self._lock:
            if root.root_id in self._roots:
                raise RegistryError(f"Root ID '{root.root_id}' is already registered")

            canonical = root.resolved_path()
            if canonical in self._canonical_paths:
                existing_id = self._canonical_paths[canonical]
                raise RegistryError(
                    f"Canonical directory '{canonical}' is already registered "
                    f"under root ID '{existing_id}'"
                )

            self._roots[root.root_id] = root
            self._canonical_paths[canonical] = root.root_id
            self._states[root.root_id] = RootLifecycleState.STOPPED
            if callback is not None:
                self._callbacks[root.root_id] = callback

            logger.info(
                "Registered monitored root '%s' at '%s'",
                root.root_id,
                canonical,
            )

    def unregister(self, root_id: str) -> None:
        """Stop monitoring and unregister a monitored root.

        Args:
            root_id: Unique identifier of the root to remove.

        Raises:
            RegistryError: If root_id is not registered, currently starting or stopping,
                or if stopping the active watcher fails or retains active resources.
        """
        watcher_to_stop: BaseWatcher | None = None

        with self._lock:
            if root_id not in self._roots:
                raise RegistryError(f"Root ID '{root_id}' is not registered")

            state = self._states.get(root_id, RootLifecycleState.STOPPED)
            if state == RootLifecycleState.STARTING:
                raise RegistryError(
                    f"Cannot unregister root '{root_id}' while it is starting"
                )
            if state == RootLifecycleState.STOPPING:
                raise RegistryError(
                    f"Cannot unregister root '{root_id}' while it is stopping"
                )

            root = self._roots[root_id]
            canonical = root.resolved_path()

            self._states[root_id] = RootLifecycleState.STOPPING
            watcher_to_stop = self._watchers.get(root_id)

        # Stop watcher outside the lock if one was active
        if watcher_to_stop is not None:
            try:
                watcher_to_stop.stop()
            except Exception as err:
                with self._lock:
                    if root_id in self._roots:
                        # If worker thread is still running, state is RUNNING.
                        # If worker stopped but handle cleanup failed, state is ERROR.
                        self._states[root_id] = (
                            RootLifecycleState.RUNNING
                            if watcher_to_stop.is_running()
                            else RootLifecycleState.ERROR
                        )
                logger.error(
                    "Error stopping watcher for '%s' during unregister: %s",
                    root_id,
                    err,
                )
                raise RegistryError(
                    f"Failed to stop watcher for root '{root_id}' "
                    f"during unregister: {err}"
                ) from err

            # Verify that watcher released all native resources
            if watcher_to_stop.has_active_resources():
                with self._lock:
                    if root_id in self._roots:
                        self._states[root_id] = RootLifecycleState.ERROR
                raise RegistryError(
                    f"Cannot unregister root '{root_id}': active resources remain"
                )

        # Only clean up root from registry after watcher has stopped successfully
        with self._lock:
            self._roots.pop(root_id, None)
            self._canonical_paths.pop(canonical, None)
            self._callbacks.pop(root_id, None)
            self._watchers.pop(root_id, None)
            self._states.pop(root_id, None)

        logger.info("Unregistered root '%s'", root_id)

    def start(self, root_id: str) -> None:
        """Start monitoring for a specific registered root.

        Args:
            root_id: Identifier of the root to start.

        Raises:
            RegistryError: If the root is unknown, disabled, already active or in error,
                or if the watcher factory or watcher startup fails.
        """
        with self._lock:
            if root_id not in self._roots:
                raise RegistryError(f"Root ID '{root_id}' is not registered")

            root = self._roots[root_id]
            if not root.enabled:
                raise RegistryError(f"Cannot start disabled root '{root_id}'")

            state = self._states.get(root_id, RootLifecycleState.STOPPED)
            if state in (
                RootLifecycleState.STARTING,
                RootLifecycleState.RUNNING,
                RootLifecycleState.ERROR,
            ):
                raise RegistryError(
                    f"Watcher for root '{root_id}' is already {state.name.lower()}"
                )
            if state == RootLifecycleState.STOPPING:
                raise RegistryError(f"Root '{root_id}' is currently stopping")

            self._states[root_id] = RootLifecycleState.STARTING

            try:
                # Build routed notification callback
                def routed_callback(notification: RawFileNotification) -> None:
                    self._dispatch(root_id, notification)

                watcher = self._watcher_factory(root, routed_callback)
                self._watchers[root_id] = watcher

                watcher.start()
                self._states[root_id] = RootLifecycleState.RUNNING
            except Exception as err:
                watcher = self._watchers.get(root_id)
                if watcher is not None and watcher.has_active_resources():
                    # Retain watcher in ERROR state to prevent resource leak
                    # and prevent duplicate watchers on this root.
                    self._states[root_id] = RootLifecycleState.ERROR
                    logger.critical(
                        "Watcher start failed for root '%s' with active resources: %s",
                        root_id,
                        err,
                    )
                else:
                    self._watchers.pop(root_id, None)
                    self._states[root_id] = RootLifecycleState.STOPPED

                logger.error("Failed to start watcher for root '%s': %s", root_id, err)
                raise RegistryError(
                    f"Failed to start watcher for root '{root_id}': {err}"
                ) from err

    def stop(self, root_id: str) -> None:
        """Stop monitoring for a specific root, or retry cleanup if in ERROR state.

        Args:
            root_id: Identifier of the root to stop.

        Raises:
            RegistryError: If the root is currently starting or if stopping fails.
        """
        watcher_to_stop: BaseWatcher | None = None

        with self._lock:
            if root_id not in self._roots:
                return

            state = self._states.get(root_id, RootLifecycleState.STOPPED)
            if state in (RootLifecycleState.STOPPED, RootLifecycleState.STOPPING):
                return
            if state == RootLifecycleState.STARTING:
                raise RegistryError(
                    f"Cannot stop root '{root_id}' while it is starting"
                )

            self._states[root_id] = RootLifecycleState.STOPPING
            watcher_to_stop = self._watchers.get(root_id)

        if watcher_to_stop is not None:
            try:
                watcher_to_stop.stop()
            except Exception as err:
                with self._lock:
                    if root_id in self._roots:
                        # If worker thread is still running, state is RUNNING.
                        # If worker stopped but handle cleanup failed, state is ERROR.
                        self._states[root_id] = (
                            RootLifecycleState.RUNNING
                            if watcher_to_stop.is_running()
                            else RootLifecycleState.ERROR
                        )
                logger.error(
                    "Error stopping watcher for root '%s': %s",
                    root_id,
                    err,
                )
                raise RegistryError(
                    f"Failed to stop watcher for root '{root_id}': {err}"
                ) from err

            # Evaluate whether cleanup was completely successful
            with self._lock:
                if watcher_to_stop.has_active_resources():
                    if root_id in self._roots:
                        self._states[root_id] = RootLifecycleState.ERROR
                else:
                    if root_id in self._roots:
                        self._states[root_id] = RootLifecycleState.STOPPED
                    self._watchers.pop(root_id, None)
        else:
            with self._lock:
                if root_id in self._roots:
                    self._states[root_id] = RootLifecycleState.STOPPED

    def start_all(self) -> dict[str, bool]:
        """Start monitoring on all registered roots that are enabled.

        Returns:
            dict[str, bool]: Map of root_id to startup success boolean.
        """
        with self._lock:
            candidate_roots = [r.root_id for r in self._roots.values() if r.enabled]

        results: dict[str, bool] = {}
        for root_id in candidate_roots:
            try:
                if not self.is_active(root_id):
                    self.start(root_id)
                results[root_id] = True
            except Exception as err:
                logger.error(
                    "Watcher startup failed for enabled root '%s': %s",
                    root_id,
                    err,
                )
                results[root_id] = False

        return results

    def stop_all(self) -> None:
        """Stop all currently active or resource-holding watchers.

        Raises:
            RegistryError: If any watcher fails to stop.
        """
        watchers_to_stop: list[tuple[str, BaseWatcher]] = []

        with self._lock:
            for root_id, watcher in list(self._watchers.items()):
                state = self._states.get(root_id)
                if state in (RootLifecycleState.RUNNING, RootLifecycleState.ERROR):
                    self._states[root_id] = RootLifecycleState.STOPPING
                    watchers_to_stop.append((root_id, watcher))

        failed_roots: list[str] = []
        for root_id, watcher in watchers_to_stop:
            try:
                watcher.stop()
            except Exception as err:
                failed_roots.append(root_id)
                logger.error(
                    "Error stopping watcher '%s' during stop_all: %s",
                    watcher.root_id,
                    err,
                )
                with self._lock:
                    if root_id in self._roots:
                        self._states[root_id] = (
                            RootLifecycleState.RUNNING
                            if watcher.is_running()
                            else RootLifecycleState.ERROR
                        )
            else:
                with self._lock:
                    if watcher.has_active_resources():
                        if root_id in self._roots:
                            self._states[root_id] = RootLifecycleState.ERROR
                        failed_roots.append(root_id)
                    else:
                        if root_id in self._roots:
                            self._states[root_id] = RootLifecycleState.STOPPED
                        self._watchers.pop(root_id, None)

        if failed_roots:
            raise RegistryError(
                f"Failed to stop watchers for roots: {', '.join(failed_roots)}"
            )

    def get_state(self, root_id: str) -> RootLifecycleState:
        """Return the current lifecycle state of a registered root."""
        with self._lock:
            if root_id not in self._roots:
                raise RegistryError(f"Root ID '{root_id}' is not registered")
            return self._states[root_id]

    def get(self, root_id: str) -> MonitoredRoot:
        """Retrieve a registered MonitoredRoot by its ID."""
        with self._lock:
            if root_id not in self._roots:
                raise RegistryError(f"Root ID '{root_id}' is not registered")
            return self._roots[root_id]

    def list_roots(self) -> list[MonitoredRoot]:
        """Return a copy of all registered roots."""
        with self._lock:
            return list(self._roots.values())

    def list_active_watchers(self) -> list[str]:
        """Return list of root IDs that currently have running watchers."""
        with self._lock:
            return [
                root_id
                for root_id, state in self._states.items()
                if state == RootLifecycleState.RUNNING
            ]

    def is_registered(self, root_id: str) -> bool:
        """Check if a root ID is currently registered."""
        with self._lock:
            return root_id in self._roots

    def is_active(self, root_id: str) -> bool:
        """Check if an active watcher is running for the given root ID."""
        with self._lock:
            return self._states.get(root_id) == RootLifecycleState.RUNNING

    def get_watcher(self, root_id: str) -> BaseWatcher | None:
        """Retrieve the active watcher for a root if present."""
        with self._lock:
            return self._watchers.get(root_id)

    def _dispatch(
        self,
        root_id: str,
        notification: RawFileNotification,
    ) -> None:
        """Safely route notification to per-root callback and/or default callback."""
        with self._lock:
            root_cb = self._callbacks.get(root_id)
            default_cb = self._default_callback

        # Call per-root callback
        if root_cb is not None:
            try:
                root_cb(notification)
            except Exception as err:
                logger.exception(
                    "Unhandled exception in per-root callback for '%s': %s",
                    root_id,
                    err,
                )

        # Call default callback
        if default_cb is not None and default_cb != root_cb:
            try:
                default_cb(notification)
            except Exception as err:
                logger.exception(
                    "Unhandled exception in default registry callback for '%s': %s",
                    root_id,
                    err,
                )
