import time
from datetime import UTC, datetime

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.core.exceptions import NormalizationError
from kuyebiko.models.events import FileEvent
from kuyebiko.processing.contracts import InMemoryEventConsumer
from kuyebiko.processing.deduplication import EventDeduplicator
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.worker import (
    EventProcessingWorker,
    WorkerLifecycleState,
)


def _make_notification(
    path: str = "doc.txt",
    root_id: str = "root-1",
    action: WindowsFileAction = WindowsFileAction.ADDED,
    monotonic_ns: int = 1_000_000,
) -> RawFileNotification:
    return RawFileNotification(
        root_id=root_id,
        relative_path=path,
        action=action,
        observed_at=datetime.now(UTC),
        monotonic_ns=monotonic_ns,
        is_directory=False,
    )


def test_worker_continues_after_malformed_notification():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)
    worker.start()

    # Inject malformed item via put_raw
    queue.put_raw("malformed-data")
    queue.put_notification(_make_notification(path="valid.txt"))

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    events = consumer.get_events()
    assert len(events) == 1
    assert events[0].file_path == "valid.txt"

    metrics = worker.get_metrics()
    assert metrics.invalid_notifications == 1
    assert metrics.normalization_failures == 1
    assert metrics.events_delivered == 1


def test_worker_continues_after_normalization_error():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()

    class FailingNormalizer(EventNormalizer):
        def normalize_notification(self, notification, **kwargs):
            if "fail" in notification.relative_path:
                raise NormalizationError("Simulated failure")
            return super().normalize_notification(notification, **kwargs)

    worker = EventProcessingWorker(
        queue=queue,
        consumer=consumer,
        normalizer=FailingNormalizer(),
    )
    worker.start()

    queue.put_notification(_make_notification(path="fail.txt"))
    queue.put_notification(_make_notification(path="ok.txt"))

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    events = consumer.get_events()
    assert len(events) == 1
    assert events[0].file_path == "ok.txt"

    metrics = worker.get_metrics()
    assert metrics.normalization_failures == 1
    assert metrics.events_delivered == 1


def test_worker_consumer_retry_and_permanent_failure():
    queue = BoundedEventQueue(capacity=10)

    def always_failing_consumer(event: FileEvent) -> None:
        raise RuntimeError("Persistent consumer failure")

    worker = EventProcessingWorker(
        queue=queue,
        consumer=always_failing_consumer,
        max_consumer_retries=1,
    )
    worker.start()

    queue.put_notification(_make_notification(path="test.txt"))
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    metrics = worker.get_metrics()
    assert metrics.notifications_received == 1
    assert metrics.notifications_normalized == 1
    assert metrics.consumer_delivery_failures == 2  # 1 initial + 1 retry
    assert metrics.retry_attempts == 1
    assert metrics.permanently_failed_events == 1
    assert metrics.events_delivered == 0


def test_worker_consumer_retry_success():
    queue = BoundedEventQueue(capacity=10)
    consumer_calls = 0

    def transient_failure_consumer(event: FileEvent) -> None:
        nonlocal consumer_calls
        consumer_calls += 1
        if consumer_calls == 1:
            raise RuntimeError("Transient error on first try")

    worker = EventProcessingWorker(
        queue=queue,
        consumer=transient_failure_consumer,
        max_consumer_retries=1,
    )
    worker.start()

    queue.put_notification(_make_notification(path="retry_me.txt"))
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    assert consumer_calls == 2
    metrics = worker.get_metrics()
    assert metrics.consumer_delivery_failures == 1  # 1 failure on initial attempt
    assert metrics.retry_attempts == 1
    assert metrics.events_delivered == 1  # Succeeded on retry!
    assert metrics.permanently_failed_events == 0


def test_worker_restart_after_stop():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)

    worker.start()
    assert worker.is_running() is True
    worker.stop(timeout=2.0)
    assert worker.is_running() is False

    # Restart
    worker.restart(timeout=2.0)
    assert worker.is_running() is True
    assert worker.state == WorkerLifecycleState.RUNNING

    queue.put_notification(_make_notification(path="restarted.txt"))
    time.sleep(0.15)
    worker.stop(timeout=2.0)

    assert len(consumer) == 1
    assert consumer.get_events()[0].file_path == "restarted.txt"


def test_worker_deduplicator_integration():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    dedup = EventDeduplicator(max_cache_size=10)
    worker = EventProcessingWorker(
        queue=queue,
        consumer=consumer,
        deduplicator=dedup,
    )
    worker.start()

    notif = _make_notification(path="dup.txt", monotonic_ns=500)
    # Put identical notification twice
    queue.put_notification(notif)
    queue.put_notification(notif)

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    # Only 1 event delivered downstream
    assert len(consumer) == 1
    metrics = worker.get_metrics()
    assert metrics.duplicates_suppressed == 1
    assert metrics.events_delivered == 1


def test_worker_ordering_tracker_integration():
    queue = BoundedEventQueue(capacity=10)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)
    worker.start()

    n1 = _make_notification(path="f1.txt", monotonic_ns=5_000_000)
    n2 = _make_notification(path="f2.txt", monotonic_ns=3_000_000)  # Late!

    queue.put_notification(n1)
    queue.put_notification(n2)

    time.sleep(0.15)
    worker.stop(timeout=2.0)

    assert len(consumer) == 2
    ordering_metrics = worker.ordering_tracker.get_metrics()
    assert ordering_metrics.total_tracked == 2
    assert ordering_metrics.total_out_of_order == 1
