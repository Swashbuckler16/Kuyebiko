import threading
import time
from datetime import UTC, datetime

import pytest

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.core.exceptions import NormalizationError, WorkerLifecycleError
from kuyebiko.models.events import EventType, FileEvent
from kuyebiko.processing.contracts import InMemoryEventConsumer
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.worker import (
    EventProcessingWorker,
    WorkerLifecycleState,
    WorkerMetrics,
)


def _make_notification(
    path: str = "test.txt",
    root_id: str = "root-1",
    action: WindowsFileAction = WindowsFileAction.ADDED,
) -> RawFileNotification:
    return RawFileNotification(
        root_id=root_id,
        relative_path=path,
        action=action,
        observed_at=datetime.now(UTC),
        monotonic_ns=1000,
        is_directory=False,
    )


def test_worker_initialization():
    queue = BoundedEventQueue(capacity=10)
    worker = EventProcessingWorker(queue=queue)
    assert worker.state == WorkerLifecycleState.STOPPED
    assert worker.is_running() is False

    metrics = worker.get_metrics()
    assert isinstance(metrics, WorkerMetrics)
    assert metrics.state == WorkerLifecycleState.STOPPED


def test_worker_initialization_invalid_args():
    with pytest.raises(TypeError, match="must be a BoundedEventQueue"):
        EventProcessingWorker(queue="invalid")  # type: ignore[arg-type]

    queue = BoundedEventQueue(capacity=10)
    with pytest.raises(TypeError, match="must implement EventConsumer or be callable"):
        EventProcessingWorker(queue=queue, consumer=12345)  # type: ignore[arg-type]


def test_worker_start_stop_lifecycle():
    queue = BoundedEventQueue(capacity=10)
    worker = EventProcessingWorker(queue=queue)

    worker.start()
    assert worker.is_running() is True
    assert worker.state == WorkerLifecycleState.RUNNING

    # Duplicate start raises error
    with pytest.raises(WorkerLifecycleError, match="already in state 'running'"):
        worker.start()

    worker.stop(timeout=2.0)
    assert worker.is_running() is False
    assert worker.state == WorkerLifecycleState.STOPPED

    # Repeated stop is safe no-op
    worker.stop(timeout=1.0)
    assert worker.state == WorkerLifecycleState.STOPPED


def test_worker_normalizes_and_dispatches_event():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)

    worker.start()

    notif = _make_notification(path="docs/sample.docx", action=WindowsFileAction.ADDED)
    queue.put_notification(notif)

    # Allow worker thread to process
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    events = consumer.get_events()
    assert len(events) == 1
    event = events[0]
    assert event.file_path == "docs/sample.docx"
    assert event.event_type == EventType.CREATED
    assert event.root_id == "root-1"
    assert event.sequence_number == 1

    metrics = worker.get_metrics()
    assert metrics.notifications_received == 1
    assert metrics.notifications_normalized == 1
    assert metrics.events_delivered == 1
    assert metrics.renames_pending == 0
    assert metrics.normalization_errors == 0


def test_worker_rename_correlation_pipeline():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    normalizer = EventNormalizer(rename_correlator=RenameCorrelator())
    worker = EventProcessingWorker(
        queue=queue,
        consumer=consumer,
        normalizer=normalizer,
    )

    worker.start()

    old_notif = _make_notification(
        path="draft.txt",
        action=WindowsFileAction.RENAMED_OLD_NAME,
    )
    new_notif = _make_notification(
        path="final.txt",
        action=WindowsFileAction.RENAMED_NEW_NAME,
    )

    # Put OLD name
    queue.put_notification(old_notif)
    time.sleep(0.1)

    # Consumer should not have any events yet (pending)
    assert len(consumer) == 0
    metrics_mid = worker.get_metrics()
    assert metrics_mid.renames_pending == 1

    # Put NEW name
    queue.put_notification(new_notif)
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    # Now rename event should be formed and delivered
    events = consumer.get_events()
    assert len(events) == 1
    rename_event = events[0]
    assert rename_event.event_type == EventType.RENAMED
    assert rename_event.old_path == "draft.txt"
    assert rename_event.new_path == "final.txt"
    assert rename_event.file_path == "final.txt"

    metrics_final = worker.get_metrics()
    assert metrics_final.notifications_received == 2
    assert metrics_final.notifications_normalized == 1
    assert metrics_final.events_delivered == 1


def test_worker_normalizer_exception_isolation():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()

    class FailingNormalizer(EventNormalizer):
        def normalize_notification(self, notification, **kwargs):
            if "bad" in notification.relative_path:
                raise NormalizationError("Simulated normalization failure")
            return super().normalize_notification(notification, **kwargs)

    worker = EventProcessingWorker(
        queue=queue,
        consumer=consumer,
        normalizer=FailingNormalizer(),
    )
    worker.start()

    # Enqueue a failing item followed by a good item
    queue.put_notification(_make_notification(path="bad_file.txt"))
    queue.put_notification(_make_notification(path="good_file.txt"))

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    events = consumer.get_events()
    assert len(events) == 1
    assert events[0].file_path == "good_file.txt"

    metrics = worker.get_metrics()
    assert metrics.notifications_received == 2
    assert metrics.normalization_errors == 1
    assert metrics.notifications_normalized == 1
    assert metrics.events_delivered == 1


def test_worker_skips_invalid_item_types():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)
    worker.start()

    # Inject an invalid non-RawFileNotification item via put_raw
    queue.put_raw("invalid-payload")
    queue.put_notification(_make_notification(path="valid.txt"))

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    assert len(consumer) == 1
    assert consumer.get_events()[0].file_path == "valid.txt"

    metrics = worker.get_metrics()
    assert metrics.normalization_errors == 1
    assert metrics.events_delivered == 1


def test_worker_consumer_exception_isolation():
    queue = BoundedEventQueue(capacity=10)

    def crashing_consumer(event: FileEvent) -> None:
        if "crash" in event.file_path:
            raise RuntimeError("Consumer crash simulation")

    worker = EventProcessingWorker(queue=queue, consumer=crashing_consumer)
    worker.start()

    queue.put_notification(_make_notification(path="crash_file.txt"))
    queue.put_notification(_make_notification(path="safe_file.txt"))

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    metrics = worker.get_metrics()
    assert metrics.notifications_received == 2
    assert metrics.notifications_normalized == 2
    assert metrics.consumer_errors == 1
    assert metrics.events_delivered == 1


def test_worker_graceful_drain_on_stop():
    queue = BoundedEventQueue(capacity=50)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)

    # Enqueue 10 events BEFORE starting worker
    for i in range(10):
        queue.put_notification(_make_notification(path=f"batch_{i}.txt"))

    worker.start()
    # Stop with drain=True immediately
    worker.stop(timeout=3.0, drain=True)

    # All 10 must be drained and delivered
    assert len(consumer) == 10
    metrics = worker.get_metrics()
    assert metrics.events_delivered == 10
    assert queue.is_empty() is True


def test_worker_stop_timeout_failure(monkeypatch):
    queue = BoundedEventQueue(capacity=10)
    worker = EventProcessingWorker(queue=queue)
    worker.start()

    # Mock thread.is_alive to simulate an un-terminable thread
    original_thread = worker._thread
    assert original_thread is not None

    monkeypatch.setattr(original_thread, "is_alive", lambda: True)

    with pytest.raises(
        WorkerLifecycleError, match="failed to terminate within.*timeout"
    ):
        worker.stop(timeout=0.05)

    assert worker.state == WorkerLifecycleState.ERROR


def test_worker_start_thread_failure(monkeypatch):
    queue = BoundedEventQueue(capacity=10)
    worker = EventProcessingWorker(queue=queue)

    def failing_thread(*args, **kwargs):
        raise RuntimeError("Thread allocation failed")

    monkeypatch.setattr(threading, "Thread", failing_thread)

    with pytest.raises(WorkerLifecycleError, match="Failed to start worker thread"):
        worker.start()

    assert worker.state == WorkerLifecycleState.ERROR


def test_worker_stop_immediate_without_drain():
    queue = BoundedEventQueue(capacity=20)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)

    worker.start()
    worker.stop(timeout=2.0, drain=False)
    assert worker.state == WorkerLifecycleState.STOPPED


def test_worker_stop_when_already_stopping():
    queue = BoundedEventQueue(capacity=10)
    worker = EventProcessingWorker(queue=queue)
    worker._state = WorkerLifecycleState.STOPPING

    # Calling stop() when already stopping returns immediately
    worker.stop(timeout=1.0)
    assert worker._state == WorkerLifecycleState.STOPPING


def test_worker_unexpected_normalizer_exception():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()

    class BuggyNormalizer(EventNormalizer):
        def normalize_notification(self, notification, **kwargs):
            raise TypeError("Simulated unexpected bug in normalizer")

    worker = EventProcessingWorker(
        queue=queue,
        consumer=consumer,
        normalizer=BuggyNormalizer(),
    )
    worker.start()

    queue.put_notification(_make_notification(path="buggy.txt"))
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    metrics = worker.get_metrics()
    assert metrics.notifications_received == 1
    assert metrics.normalization_errors == 1
    assert metrics.events_delivered == 0


def test_worker_unexpected_loop_exception(monkeypatch):
    queue = BoundedEventQueue(capacity=10)
    worker = EventProcessingWorker(queue=queue)
    worker.start()

    # Monkeypatch _process_single_item to raise an unexpected error
    def crashing_item(item):
        raise ZeroDivisionError("Crash inside loop")

    monkeypatch.setattr(worker, "_process_single_item", crashing_item)

    queue.put_notification(_make_notification(path="crash.txt"))
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    metrics = worker.get_metrics()
    assert metrics.unexpected_errors >= 1
