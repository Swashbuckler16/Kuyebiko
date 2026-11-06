import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kuyebiko.collectors.base import BaseWatcher, WatcherHealth
from kuyebiko.collectors.models import (
    MonitoredRoot,
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.collectors.registry import MonitoredRootRegistry
from kuyebiko.core.exceptions import (
    PipelineLifecycleError,
)
from kuyebiko.processing.contracts import InMemoryEventConsumer
from kuyebiko.processing.deduplication import EventDeduplicator
from kuyebiko.processing.ordering import EventOrderingTracker
from kuyebiko.processing.pipeline import (
    EventPipeline,
    PipelineLifecycleState,
)
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.telemetry import PipelineHealth


class MockWatcher(BaseWatcher):
    """Controllable mock watcher for lifecycle testing."""

    def __init__(self, root: MonitoredRoot, callback, fail_start: bool = False):
        self._root = root
        self._callback = callback
        self.fail_start = fail_start
        self._is_running = False
        self._stopped = False
        self._health = WatcherHealth.STOPPED
        self._overflow_count = 0
        self._events_observed = 0

    @property
    def root(self) -> MonitoredRoot:
        return self._root

    @property
    def root_id(self) -> str:
        return self._root.root_id

    @property
    def is_degraded(self) -> bool:
        return False

    @property
    def degradation_reason(self) -> str | None:
        return None

    @property
    def health(self) -> WatcherHealth:
        return self._health

    @property
    def overflow_count(self) -> int:
        return self._overflow_count

    @property
    def events_observed(self) -> int:
        return self._events_observed

    def start(self) -> None:
        if self.fail_start:
            self._health = WatcherHealth.ERROR
            raise RuntimeError(f"Simulated failure starting watcher for {self.root_id}")
        self._is_running = True
        self._health = WatcherHealth.HEALTHY

    def stop(self) -> None:
        self._is_running = False
        self._stopped = True
        self._health = WatcherHealth.STOPPED

    def is_running(self) -> bool:
        return self._is_running

    def has_active_resources(self) -> bool:
        return self._is_running


def _make_dummy_root(tmp_path: Path, root_id: str = "root-1") -> MonitoredRoot:
    d = tmp_path / root_id
    d.mkdir(parents=True, exist_ok=True)
    return MonitoredRoot(
        root_id=root_id,
        path=str(d),
        recursive=True,
        enabled=True,
    )


def test_pipeline_normal_lifecycle(tmp_path):
    root = _make_dummy_root(tmp_path)
    consumer = InMemoryEventConsumer()

    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: MockWatcher(r, cb))
    pipeline = EventPipeline(
        registry=registry,
        consumer=consumer,
        poll_timeout=0.01,
    )
    pipeline.register_root(root)

    assert pipeline.state == PipelineLifecycleState.STOPPED
    assert pipeline.is_running is False

    # Start
    pipeline.start()
    assert pipeline.state == PipelineLifecycleState.RUNNING
    assert pipeline.is_running is True

    # Submit notification through ingestor
    notif = RawFileNotification(
        root_id=root.root_id,
        relative_path="file.txt",
        action=WindowsFileAction.ADDED,
        observed_at=datetime.now(UTC),
        monotonic_ns=1000,
        is_directory=False,
    )
    pipeline.ingestor.ingest(notif)

    # Allow worker to process
    time.sleep(0.1)

    # Stop with drain
    pipeline.stop(timeout=2.0, drain=True)
    assert pipeline.state == PipelineLifecycleState.STOPPED
    assert pipeline.is_running is False
    assert len(consumer) == 1


def test_pipeline_duplicate_start_prevented(tmp_path):
    root = _make_dummy_root(tmp_path)
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: MockWatcher(r, cb))
    pipeline = EventPipeline(registry=registry, poll_timeout=0.01)
    pipeline.register_root(root)

    pipeline.start()
    with pytest.raises(PipelineLifecycleError, match="Cannot start pipeline"):
        pipeline.start()

    pipeline.stop()
    assert pipeline.state == PipelineLifecycleState.STOPPED


def test_pipeline_idempotent_stop(tmp_path):
    pipeline = EventPipeline(poll_timeout=0.01)
    assert pipeline.state == PipelineLifecycleState.STOPPED

    # Stopping already stopped pipeline is safe no-op
    pipeline.stop()
    assert pipeline.state == PipelineLifecycleState.STOPPED


def test_pipeline_startup_rollback_on_watcher_failure(tmp_path):
    """When a watcher fails to start, previously started components are rolled back."""
    root1 = _make_dummy_root(tmp_path, "root-good")
    root2 = _make_dummy_root(tmp_path, "root-bad")

    def failing_watcher_factory(r: MonitoredRoot, cb):
        if r.root_id == "root-bad":
            return MockWatcher(r, cb, fail_start=True)
        return MockWatcher(r, cb, fail_start=False)

    registry = MonitoredRootRegistry(watcher_factory=failing_watcher_factory)
    pipeline = EventPipeline(registry=registry, poll_timeout=0.01)
    pipeline.register_root(root1)
    pipeline.register_root(root2)

    with pytest.raises(PipelineLifecycleError, match="Pipeline startup aborted"):
        pipeline.start()

    # Pipeline should be in ERROR state after failed rollback
    assert pipeline.state == PipelineLifecycleState.ERROR
    # Worker must have been stopped during rollback
    assert pipeline.worker.is_running() is False


def test_pipeline_shutdown_graceful_drain(tmp_path):
    root = _make_dummy_root(tmp_path)
    consumer = InMemoryEventConsumer()
    queue = BoundedEventQueue(capacity=100)
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: MockWatcher(r, cb))

    pipeline = EventPipeline(
        registry=registry,
        queue=queue,
        consumer=consumer,
        poll_timeout=0.01,
    )
    pipeline.register_root(root)
    pipeline.start()

    # Ingest 10 events
    for i in range(10):
        pipeline.ingestor.ingest(
            RawFileNotification(
                root_id=root.root_id,
                relative_path=f"file_{i}.txt",
                action=WindowsFileAction.ADDED,
                observed_at=datetime.now(UTC),
                monotonic_ns=1000 + i,
                is_directory=False,
            )
        )

    # Stop with drain=True: all 10 events must be processed
    pipeline.stop(timeout=3.0, drain=True)
    assert pipeline.state == PipelineLifecycleState.STOPPED
    assert len(consumer) == 10


def test_pipeline_shutdown_non_draining(tmp_path):
    root = _make_dummy_root(tmp_path)
    consumer = InMemoryEventConsumer()
    queue = BoundedEventQueue(capacity=100)
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: MockWatcher(r, cb))

    pipeline = EventPipeline(
        registry=registry,
        queue=queue,
        consumer=consumer,
        poll_timeout=0.1,  # Slower poll
    )
    pipeline.register_root(root)
    pipeline.start()

    # Immediately stop with drain=False
    pipeline.stop(timeout=2.0, drain=False)
    assert pipeline.state == PipelineLifecycleState.STOPPED
    assert pipeline.worker.is_running() is False


def test_pipeline_restart_clean(tmp_path):
    root = _make_dummy_root(tmp_path)
    consumer = InMemoryEventConsumer()
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: MockWatcher(r, cb))

    pipeline = EventPipeline(
        registry=registry,
        consumer=consumer,
        poll_timeout=0.01,
    )
    pipeline.register_root(root)
    pipeline.start()
    assert pipeline.is_running is True

    # Ingest event in first run
    pipeline.ingestor.ingest(
        RawFileNotification(
            root_id=root.root_id,
            relative_path="first.txt",
            action=WindowsFileAction.ADDED,
            observed_at=datetime.now(UTC),
            monotonic_ns=1000,
            is_directory=False,
        )
    )
    time.sleep(0.1)
    assert len(consumer) == 1

    # Restart
    pipeline.restart(timeout=2.0, drain=True)
    assert pipeline.is_running is True
    assert pipeline.state == PipelineLifecycleState.RUNNING

    # Ingest event after restart
    pipeline.ingestor.ingest(
        RawFileNotification(
            root_id=root.root_id,
            relative_path="second.txt",
            action=WindowsFileAction.ADDED,
            observed_at=datetime.now(UTC),
            monotonic_ns=2000,
            is_directory=False,
        )
    )
    time.sleep(0.1)
    assert len(consumer) == 2

    pipeline.stop()
    assert pipeline.is_running is False


def test_pipeline_concurrent_start_stop(tmp_path):
    """Concurrent start/stop operations do not crash or corrupt internal state."""
    pipeline = EventPipeline(poll_timeout=0.01)

    errors = []

    def op_start():
        try:
            pipeline.start()
        except PipelineLifecycleError:
            pass
        except Exception as e:
            errors.append(e)

    def op_stop():
        try:
            pipeline.stop(timeout=1.0)
        except PipelineLifecycleError:
            pass
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=op_start),
        threading.Thread(target=op_stop),
        threading.Thread(target=op_start),
        threading.Thread(target=op_stop),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert pipeline.state in (
        PipelineLifecycleState.RUNNING,
        PipelineLifecycleState.STOPPED,
    )
    if pipeline.is_running:
        pipeline.stop()


def test_pipeline_telemetry_snapshot_integration(tmp_path):
    root = _make_dummy_root(tmp_path)
    registry = MonitoredRootRegistry(watcher_factory=lambda r, cb: MockWatcher(r, cb))
    dedup = EventDeduplicator(max_cache_size=100)
    ordering = EventOrderingTracker()

    pipeline = EventPipeline(
        registry=registry,
        deduplicator=dedup,
        ordering_tracker=ordering,
        poll_timeout=0.01,
    )
    pipeline.register_root(root)
    pipeline.start()

    notif = RawFileNotification(
        root_id=root.root_id,
        relative_path="hello.txt",
        action=WindowsFileAction.ADDED,
        observed_at=datetime.now(UTC),
        monotonic_ns=1000,
        is_directory=False,
    )
    pipeline.ingestor.ingest(notif)
    time.sleep(0.1)

    snap = pipeline.snapshot()
    assert snap.health == PipelineHealth.HEALTHY
    assert snap.registered_watchers == 1
    assert snap.active_watchers == 1
    assert snap.total_submitted == 1
    assert snap.total_processed == 1
    assert snap.known_application_dropped == 0
    assert snap.kernel_overflow_count == 0

    # Verify subsystem metrics attached
    assert snap.ingestion is not None
    assert snap.queue is not None
    assert snap.worker is not None
    assert snap.ordering is not None
    assert snap.deduplication is not None

    assert snap.ingestion.total_accepted == 1
    assert snap.worker.events_delivered == 1
    assert snap.deduplication.total_examined == 1
    assert snap.ordering.total_tracked == 1

    pipeline.stop()


def test_pipeline_component_properties(tmp_path):
    root = _make_dummy_root(tmp_path)
    dedup = EventDeduplicator(max_cache_size=50)
    ordering = EventOrderingTracker()

    pipeline = EventPipeline(
        deduplicator=dedup,
        ordering_tracker=ordering,
        poll_timeout=0.01,
    )
    pipeline.register_root(root)

    assert pipeline.registry is not None
    assert pipeline.queue is not None
    assert pipeline.ingestor is not None
    assert pipeline.worker is not None
    assert pipeline.consumer is not None
    assert pipeline.normalizer is not None
    assert pipeline.deduplicator is dedup
    assert pipeline.ordering_tracker is ordering
    assert pipeline.telemetry is not None


def test_pipeline_startup_fails_on_nonexistent_root_path(tmp_path):
    d = tmp_path / "deleted_later"
    d.mkdir(parents=True, exist_ok=True)
    bad_root = MonitoredRoot(
        root_id="root-missing",
        path=str(d),
        recursive=True,
        enabled=True,
    )
    pipeline = EventPipeline(poll_timeout=0.01)
    pipeline.register_root(bad_root)

    # Delete directory before starting
    d.rmdir()

    with pytest.raises(PipelineLifecycleError, match="validation failed"):
        pipeline.start()

    assert pipeline.state == PipelineLifecycleState.ERROR


def test_pipeline_startup_fails_on_worker_start_error():
    pipeline = EventPipeline(poll_timeout=0.01)

    def failing_start():
        raise RuntimeError("Worker start OS error")

    pipeline.worker.start = failing_start  # type: ignore[method-assign]

    with pytest.raises(
        PipelineLifecycleError, match="Failed to start processing worker"
    ):
        pipeline.start()

    assert pipeline.state == PipelineLifecycleState.ERROR


def test_pipeline_stop_fails_if_worker_remains_alive():
    pipeline = EventPipeline(poll_timeout=0.01)
    pipeline.start()

    # Simulate worker thread hanging / refusing to exit
    pipeline.worker.is_running = lambda: True  # type: ignore[method-assign]

    with pytest.raises(PipelineLifecycleError, match="remained alive"):
        pipeline.stop(timeout=0.1)

    assert pipeline.state == PipelineLifecycleState.ERROR


def test_pipeline_stop_fails_if_watcher_raises_error(tmp_path):
    root = _make_dummy_root(tmp_path)

    class FailingStopWatcher(MockWatcher):
        def stop(self) -> None:
            raise RuntimeError("Watcher stop crash")

    registry = MonitoredRootRegistry(
        watcher_factory=lambda r, cb: FailingStopWatcher(r, cb)
    )
    pipeline = EventPipeline(registry=registry, poll_timeout=0.01)
    pipeline.register_root(root)
    pipeline.start()

    with pytest.raises(PipelineLifecycleError, match="Pipeline stopped with errors"):
        pipeline.stop(timeout=1.0)

    assert pipeline.state == PipelineLifecycleState.ERROR
