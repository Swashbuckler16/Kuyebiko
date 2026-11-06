import threading
from datetime import UTC, datetime

import pytest

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.processing.contracts import IngestionOutcome
from kuyebiko.processing.queue import BoundedEventQueue, EventQueueMetrics


def _make_notification(
    path: str = "doc.txt",
    root_id: str = "root-1",
    action: WindowsFileAction = WindowsFileAction.ADDED,
) -> RawFileNotification:
    return RawFileNotification(
        root_id=root_id,
        relative_path=path,
        action=action,
        observed_at=datetime.now(UTC),
        monotonic_ns=100_000_000,
        is_directory=False,
    )


def test_queue_initialization_validation():
    with pytest.raises(ValueError, match="capacity must be at least 1"):
        BoundedEventQueue(capacity=0)

    with pytest.raises(ValueError, match="recovery_threshold_ratio"):
        BoundedEventQueue(capacity=10, recovery_threshold_ratio=0.0)

    with pytest.raises(ValueError, match="recovery_threshold_ratio"):
        BoundedEventQueue(capacity=10, recovery_threshold_ratio=1.5)

    queue = BoundedEventQueue(capacity=50)
    assert queue.capacity == 50
    assert queue.is_empty() is True
    assert queue.is_full() is False
    assert queue.qsize() == 0
    assert queue.is_degraded is False


def test_queue_put_and_get():
    queue = BoundedEventQueue(capacity=10)
    notif = _make_notification()

    outcome = queue.put_notification(notif)
    assert outcome == IngestionOutcome.ACCEPTED
    assert queue.qsize() == 1
    assert queue.is_empty() is False

    retrieved = queue.get(timeout=1.0)
    assert retrieved == notif
    queue.task_done()
    assert queue.qsize() == 0
    assert queue.is_empty() is True


def test_queue_rejects_invalid_type():
    queue = BoundedEventQueue(capacity=10)
    outcome = queue.put_notification("not_a_notification")  # type: ignore[arg-type]
    assert outcome == IngestionOutcome.REJECTED
    assert queue.qsize() == 0

    metrics = queue.get_metrics()
    assert metrics.total_submitted == 1
    assert metrics.total_rejected == 1
    assert metrics.total_accepted == 0


def test_queue_capacity_overflow_and_degradation():
    queue = BoundedEventQueue(capacity=2, recovery_threshold_ratio=0.5)

    n1 = _make_notification(path="file1.txt")
    n2 = _make_notification(path="file2.txt")
    n3 = _make_notification(path="file3.txt")

    assert queue.put_notification(n1) == IngestionOutcome.ACCEPTED
    assert queue.put_notification(n2) == IngestionOutcome.ACCEPTED
    assert queue.is_full() is True
    assert queue.is_degraded is False

    # Overflow on 3rd notification
    assert queue.put_notification(n3) == IngestionOutcome.QUEUE_FULL
    assert queue.is_full() is True
    assert queue.is_degraded is True

    metrics = queue.get_metrics()
    assert metrics.capacity == 2
    assert metrics.size == 2
    assert metrics.total_submitted == 3
    assert metrics.total_accepted == 2
    assert metrics.total_dropped_queue_full == 1
    assert metrics.degraded is True
    assert "exhausted" in (metrics.degradation_reason or "")
    assert metrics.last_overflow_at is not None

    # Dequeue one item: size becomes 1 (which is <= capacity * 0.5 = 1) -> recovers!
    _ = queue.get(timeout=1.0)
    queue.task_done()

    assert queue.is_degraded is False
    metrics_recovered = queue.get_metrics()
    assert metrics_recovered.degraded is False
    assert metrics_recovered.degradation_reason is None
    assert metrics_recovered.last_recovered_at is not None


def test_queue_stop_accepting():
    queue = BoundedEventQueue(capacity=10)
    assert queue.is_accepting() is True

    queue.stop_accepting()
    assert queue.is_accepting() is False

    notif = _make_notification()
    assert queue.put_notification(notif) == IngestionOutcome.SHUTTING_DOWN
    assert queue.qsize() == 0


def test_queue_clear():
    queue = BoundedEventQueue(capacity=10)
    for i in range(5):
        queue.put_notification(_make_notification(path=f"file{i}.txt"))

    assert queue.qsize() == 5
    purged = queue.clear()
    assert purged == 5
    assert queue.qsize() == 0
    assert queue.is_empty() is True


def test_queue_metrics_frozen():
    queue = BoundedEventQueue(capacity=5)
    metrics = queue.get_metrics()
    assert isinstance(metrics, EventQueueMetrics)
    with pytest.raises((TypeError, ValueError)):
        metrics.size = 100  # type: ignore[misc]


def test_queue_concurrent_multi_producers():
    capacity = 1000
    queue = BoundedEventQueue(capacity=capacity)
    num_producers = 8
    items_per_producer = 50

    def producer(thread_id: int) -> None:
        for i in range(items_per_producer):
            notif = _make_notification(
                path=f"thread_{thread_id}/file_{i}.txt",
                root_id=f"root_{thread_id}",
            )
            outcome = queue.put_notification(notif)
            assert outcome == IngestionOutcome.ACCEPTED

    threads = [
        threading.Thread(target=producer, args=(t,)) for t in range(num_producers)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected_total = num_producers * items_per_producer
    assert queue.qsize() == expected_total

    metrics = queue.get_metrics()
    assert metrics.total_accepted == expected_total
    assert metrics.total_submitted == expected_total
    assert metrics.total_rejected == 0
    assert metrics.total_dropped_queue_full == 0
    assert metrics.high_watermark == expected_total
