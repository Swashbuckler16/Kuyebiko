import threading
from datetime import UTC, datetime

import pytest

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.processing.contracts import IngestionOutcome
from kuyebiko.processing.ingestion import EventIngestor
from kuyebiko.processing.queue import BoundedEventQueue


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
        monotonic_ns=123_456,
        is_directory=False,
    )


def test_ingestor_initialization_type_check():
    with pytest.raises(TypeError, match="must be an instance of BoundedEventQueue"):
        EventIngestor("not_a_queue")  # type: ignore[arg-type]

    queue = BoundedEventQueue(capacity=10)
    ingestor = EventIngestor(queue)
    assert ingestor.queue is queue
    assert ingestor.is_active is True


def test_ingestor_accepts_valid_notification():
    queue = BoundedEventQueue(capacity=10)
    ingestor = EventIngestor(queue)
    notif = _make_notification(root_id="root-alpha")

    outcome = ingestor.ingest(notif)
    assert outcome == IngestionOutcome.ACCEPTED

    metrics = ingestor.get_metrics()
    assert metrics.total_received == 1
    assert metrics.total_accepted == 1
    assert metrics.total_rejected == 0
    assert metrics.total_dropped_queue_full == 0
    assert metrics.events_by_root == {"root-alpha": 1}
    assert metrics.is_active is True


def test_ingestor_callable_interface():
    queue = BoundedEventQueue(capacity=10)
    ingestor = EventIngestor(queue)
    notif = _make_notification()

    # Ingestor directly invoked as a callback
    outcome = ingestor(notif)
    assert outcome == IngestionOutcome.ACCEPTED
    assert queue.qsize() == 1


def test_ingestor_rejects_invalid_type():
    queue = BoundedEventQueue(capacity=10)
    ingestor = EventIngestor(queue)

    outcome = ingestor.ingest({"not": "a notification"})  # type: ignore[arg-type]
    assert outcome == IngestionOutcome.REJECTED

    metrics = ingestor.get_metrics()
    assert metrics.total_received == 1
    assert metrics.total_accepted == 0
    assert metrics.total_rejected == 1
    assert queue.qsize() == 0


def test_ingestor_handles_queue_full():
    queue = BoundedEventQueue(capacity=1)
    ingestor = EventIngestor(queue)

    n1 = _make_notification(path="f1.txt")
    n2 = _make_notification(path="f2.txt")

    assert ingestor.ingest(n1) == IngestionOutcome.ACCEPTED
    assert ingestor.ingest(n2) == IngestionOutcome.QUEUE_FULL

    metrics = ingestor.get_metrics()
    assert metrics.total_received == 2
    assert metrics.total_accepted == 1
    assert metrics.total_dropped_queue_full == 1


def test_ingestor_shutdown_behavior():
    queue = BoundedEventQueue(capacity=10)
    ingestor = EventIngestor(queue)
    assert ingestor.is_active is True

    ingestor.shutdown()
    assert ingestor.is_active is False
    assert queue.is_accepting() is False

    notif = _make_notification()
    outcome = ingestor.ingest(notif)
    assert outcome == IngestionOutcome.SHUTTING_DOWN

    metrics = ingestor.get_metrics()
    assert metrics.total_received == 1
    assert metrics.total_accepted == 0
    assert metrics.total_shutting_down == 1


def test_ingestor_handles_queue_stopped_externally():
    queue = BoundedEventQueue(capacity=10)
    ingestor = EventIngestor(queue)
    queue.stop_accepting()
    outcome = ingestor.ingest(_make_notification())
    assert outcome == IngestionOutcome.SHUTTING_DOWN
    metrics = ingestor.get_metrics()
    assert metrics.total_shutting_down == 1


def test_ingestor_concurrent_multi_root_producers():
    queue = BoundedEventQueue(capacity=1000)
    ingestor = EventIngestor(queue)
    num_roots = 4
    producers_per_root = 3
    events_per_producer = 25

    def worker(root_idx: int, prod_idx: int) -> None:
        root_id = f"monitored-root-{root_idx}"
        for i in range(events_per_producer):
            notif = _make_notification(
                path=f"worker_{prod_idx}/file_{i}.txt",
                root_id=root_id,
            )
            res = ingestor(notif)
            assert res == IngestionOutcome.ACCEPTED

    threads = []
    for r in range(num_roots):
        for p in range(producers_per_root):
            threads.append(threading.Thread(target=worker, args=(r, p)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected_total = num_roots * producers_per_root * events_per_producer
    assert queue.qsize() == expected_total

    metrics = ingestor.get_metrics()
    assert metrics.total_accepted == expected_total
    assert metrics.total_received == expected_total
    assert metrics.total_rejected == 0
    assert metrics.total_dropped_queue_full == 0

    for r in range(num_roots):
        root_id = f"monitored-root-{r}"
        expected_root_count = producers_per_root * events_per_producer
        assert metrics.events_by_root[root_id] == expected_root_count
