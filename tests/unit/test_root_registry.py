from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kuyebiko.collectors.base import BaseWatcher
from kuyebiko.collectors.models import (
    MonitoredRoot,
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.collectors.registry import MonitoredRootRegistry, RootLifecycleState
from kuyebiko.core.exceptions import RegistryError


class DummyWatcher(BaseWatcher):
    """Controllable test watcher for unit testing MonitoredRootRegistry."""

    def __init__(self, root: MonitoredRoot, callback, should_fail: bool = False):
        self._root = root
        self._callback = callback
        self._running = False
        self._should_fail = should_fail
        self._degraded = False

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
        return "Degraded for testing" if self._degraded else None

    def start(self) -> None:
        if self._should_fail:
            raise RuntimeError("Simulated watcher startup failure")
        self._running = True

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def emit_event(self, path: str, action: WindowsFileAction):
        if self._callback:
            self._callback(
                RawFileNotification(
                    root_id=self.root_id,
                    relative_path=path,
                    action=action,
                    monotonic_ns=1000,
                )
            )


def test_registry_register_and_get(tmp_path: Path):
    registry = MonitoredRootRegistry()
    root = MonitoredRoot(root_id="root-1", path=tmp_path)

    registry.register(root)
    assert registry.is_registered("root-1") is True
    assert registry.get("root-1") == root
    assert len(registry.list_roots()) == 1


def test_registry_rejects_duplicate_root_id(tmp_path: Path):
    registry = MonitoredRootRegistry()
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()

    r1 = MonitoredRoot(root_id="dup-id", path=d1)
    r2 = MonitoredRoot(root_id="dup-id", path=d2)

    registry.register(r1)
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(r2)


def test_registry_rejects_duplicate_canonical_path(tmp_path: Path):
    registry = MonitoredRootRegistry()
    r1 = MonitoredRoot(root_id="root-a", path=tmp_path)
    r2 = MonitoredRoot(root_id="root-b", path=tmp_path)

    registry.register(r1)
    with pytest.raises(RegistryError, match="already registered under root ID"):
        registry.register(r2)


def test_registry_start_and_stop_root(tmp_path: Path):
    created_watchers = {}

    def factory(r, cb):
        w = DummyWatcher(r, cb)
        created_watchers[r.root_id] = w
        return w

    registry = MonitoredRootRegistry(watcher_factory=factory)
    root = MonitoredRoot(root_id="root-1", path=tmp_path)
    registry.register(root)

    registry.start("root-1")
    assert registry.is_active("root-1") is True
    assert "root-1" in registry.list_active_watchers()

    registry.stop("root-1")
    assert registry.is_active("root-1") is False
    assert "root-1" not in registry.list_active_watchers()


def test_registry_rejects_starting_disabled_root(tmp_path: Path):
    registry = MonitoredRootRegistry()
    root = MonitoredRoot(root_id="root-dis", path=tmp_path, enabled=False)
    registry.register(root)

    with pytest.raises(RegistryError, match="Cannot start disabled root"):
        registry.start("root-dis")


def test_registry_start_all_and_stop_all(tmp_path: Path):
    d1 = tmp_path / "dir1"
    d2 = tmp_path / "dir2"
    d3 = tmp_path / "dir3"
    d1.mkdir()
    d2.mkdir()
    d3.mkdir()

    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: DummyWatcher(r, cb))
    registry.register(MonitoredRoot(root_id="r1", path=d1, enabled=True))
    registry.register(MonitoredRoot(root_id="r2", path=d2, enabled=False))
    registry.register(MonitoredRoot(root_id="r3", path=d3, enabled=True))

    results = registry.start_all()
    assert results == {"r1": True, "r3": True}

    assert registry.is_active("r1") is True
    assert registry.is_active("r2") is False
    assert registry.is_active("r3") is True

    registry.stop_all()
    assert registry.is_active("r1") is False
    assert registry.is_active("r3") is False


def test_registry_event_attribution_across_multiple_roots(tmp_path: Path):
    d1 = tmp_path / "dir_a"
    d2 = tmp_path / "dir_b"
    d1.mkdir()
    d2.mkdir()

    watchers: dict[str, DummyWatcher] = {}

    def factory(r, cb):
        w = DummyWatcher(r, cb)
        watchers[r.root_id] = w
        return w

    received_events = []

    def on_event(n: RawFileNotification):
        received_events.append(n)

    registry = MonitoredRootRegistry(
        default_callback=on_event,
        watcher_factory=factory,
    )

    registry.register(MonitoredRoot(root_id="root-a", path=d1))
    registry.register(MonitoredRoot(root_id="root-b", path=d2))
    registry.start_all()

    # Emit event from Root A
    watchers["root-a"].emit_event("doc1.txt", WindowsFileAction.ADDED)
    # Emit event from Root B
    watchers["root-b"].emit_event("photo.jpg", WindowsFileAction.MODIFIED)

    assert len(received_events) == 2
    assert received_events[0].root_id == "root-a"
    assert received_events[0].relative_path == "doc1.txt"

    assert received_events[1].root_id == "root-b"
    assert received_events[1].relative_path == "photo.jpg"

    registry.stop_all()


def test_registry_watcher_failure_isolation(tmp_path: Path):
    d1 = tmp_path / "dir_fail"
    d2 = tmp_path / "dir_ok"
    d1.mkdir()
    d2.mkdir()

    def factory(r, cb):
        should_fail = r.root_id == "failing-root"
        return DummyWatcher(r, cb, should_fail=should_fail)

    registry = MonitoredRootRegistry(watcher_factory=factory)
    registry.register(MonitoredRoot(root_id="failing-root", path=d1))
    registry.register(MonitoredRoot(root_id="ok-root", path=d2))

    results = registry.start_all()
    assert results["failing-root"] is False
    assert results["ok-root"] is True

    assert registry.is_active("failing-root") is False
    assert registry.is_active("ok-root") is True

    registry.stop_all()


def test_registry_unregister_cleans_up_watcher(tmp_path: Path):
    watchers = {}

    def factory(r, cb):
        w = DummyWatcher(r, cb)
        watchers[r.root_id] = w
        return w

    registry = MonitoredRootRegistry(watcher_factory=factory)
    root = MonitoredRoot(root_id="root-unreg", path=tmp_path)
    registry.register(root)
    registry.start("root-unreg")

    watcher = watchers["root-unreg"]
    assert watcher.is_running() is True

    registry.unregister("root-unreg")
    assert registry.is_registered("root-unreg") is False
    assert watcher.is_running() is False


def test_registry_callback_exception_handled_safely(tmp_path: Path):
    watchers = {}

    def factory(r, cb):
        w = DummyWatcher(r, cb)
        watchers[r.root_id] = w
        return w

    faulty_callback = MagicMock(side_effect=ValueError("Consumer failure"))
    registry = MonitoredRootRegistry(
        default_callback=faulty_callback,
        watcher_factory=factory,
    )

    registry.register(MonitoredRoot(root_id="root-cb", path=tmp_path))
    registry.start("root-cb")

    # Should not raise exception
    watchers["root-cb"].emit_event("test.txt", WindowsFileAction.ADDED)
    assert faulty_callback.call_count == 1
    registry.stop_all()


def test_registry_lifecycle_state_transitions(tmp_path: Path):
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: DummyWatcher(r, cb))
    root = MonitoredRoot(root_id="root-state", path=tmp_path)
    registry.register(root)

    assert registry.get_state("root-state") == RootLifecycleState.STOPPED

    registry.start("root-state")
    assert registry.get_state("root-state") == RootLifecycleState.RUNNING

    with pytest.raises(RegistryError, match="already running"):
        registry.start("root-state")

    registry.stop("root-state")
    assert registry.get_state("root-state") == RootLifecycleState.STOPPED


def test_registry_rejects_operations_during_transitional_states(tmp_path: Path):
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: DummyWatcher(r, cb))
    root = MonitoredRoot(root_id="root-trans", path=tmp_path)
    registry.register(root)

    # Manually simulate STARTING state to test concurrency gates
    registry._states["root-trans"] = RootLifecycleState.STARTING

    with pytest.raises(RegistryError, match="while it is starting"):
        registry.stop("root-trans")

    with pytest.raises(RegistryError, match="while it is starting"):
        registry.unregister("root-trans")

    # Manually simulate STOPPING state to test concurrency gates
    registry._states["root-trans"] = RootLifecycleState.STOPPING

    with pytest.raises(RegistryError, match="currently stopping"):
        registry.start("root-trans")
