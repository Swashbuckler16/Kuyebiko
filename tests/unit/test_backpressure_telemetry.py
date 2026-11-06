import threading
from datetime import UTC, datetime

import pytest

from kuyebiko.collectors.base import WatcherHealth
from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.processing.contracts import IngestionOutcome
from kuyebiko.processing.ingestion import EventIngestor
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.telemetry import (
    PipelineTelemetryAggregator,
    PipelineTelemetrySnapshot,
)


def _make_notification(
    path: str = "burst.txt",
    root_id: str = "root-1",
) -> RawFileNotification:
    return RawFileNotification(
        root_id=root_id,
        relative_path=path,
        action=WindowsFileAction.MODIFIED,
        observed_at=datetime.now(UTC),
        monotonic_ns=1_000_000,
        is_directory=False,
    )


def test_separate_kernel_and_application_overflow_counts():
    """Verify kernel and application queue drops are tracked as distinct metrics."""
    queue = BoundedEventQueue(capacity=2)
    ingestor = EventIngestor(queue)

    # 1. Fill queue to induce 2 application queue overflows
    n1 = _make_notification(path="f1.txt")
    n2 = _make_notification(path="f2.txt")
    n3 = _make_notification(path="f3.txt")
    n4 = _make_notification(path="f4.txt")

    assert ingestor.ingest(n1) == IngestionOutcome.ACCEPTED
    assert ingestor.ingest(n2) == IngestionOutcome.ACCEPTED
    assert ingestor.ingest(n3) == IngestionOutcome.QUEUE_FULL
    assert ingestor.ingest(n4) == IngestionOutcome.QUEUE_FULL

    aggregator = PipelineTelemetryAggregator(queue=queue, ingestor=ingestor)

    # 2. Simulate 5 kernel buffer overflows (e.g. from ERROR_NOTIFY_ENUM_DIR)
    snapshot = aggregator.snapshot(external_kernel_overflow_count=5)

    assert isinstance(snapshot, PipelineTelemetrySnapshot)
    assert snapshot.kernel_overflow_count == 5
    assert snapshot.application_queue_overflow_count == 2
    assert snapshot.known_application_dropped == 2
    # Exact known application drops only (not conflated with kernel overflow count)
    assert snapshot.total_dropped == 2
    assert snapshot.uncounted_kernel_loss is True
    assert snapshot.telemetry_degraded is True
    assert any(
        "exhausted" in r or "overflow" in r for r in snapshot.degradation_reasons
    )


def test_backpressure_high_watermark_tracking():
    queue = BoundedEventQueue(capacity=10)
    for i in range(7):
        queue.put_notification(_make_notification(path=f"file_{i}.txt"))

    aggregator = PipelineTelemetryAggregator(queue=queue)
    snapshot = aggregator.snapshot()

    assert snapshot.current_queue_depth == 7
    assert snapshot.peak_queue_depth == 7

    # Dequeue 3 items
    for _ in range(3):
        queue.get(timeout=0.1)
        queue.task_done()

    snapshot_after = aggregator.snapshot()
    assert snapshot_after.current_queue_depth == 4
    # Peak depth must remain at high watermark (7)
    assert snapshot_after.peak_queue_depth == 7


def test_sustained_burst_concurrent_producers_no_silent_loss():
    """Burst test: accepted + dropped must exactly equal submitted."""
    capacity = 100
    queue = BoundedEventQueue(capacity=capacity)
    ingestor = EventIngestor(queue)
    num_threads = 8
    events_per_thread = 50  # Total 400 events into capacity 100 queue

    def producer(t_idx: int) -> None:
        for i in range(events_per_thread):
            notif = _make_notification(
                path=f"thread_{t_idx}/file_{i}.txt",
                root_id=f"root_{t_idx % 2}",
            )
            ingestor.ingest(notif)

    threads = [threading.Thread(target=producer, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    aggregator = PipelineTelemetryAggregator(queue=queue, ingestor=ingestor)
    snapshot = aggregator.snapshot()

    total_expected = num_threads * events_per_thread
    assert snapshot.total_submitted == total_expected
    # Fundamental accounting identity: no silent loss!
    accepted = snapshot.total_submitted - snapshot.application_queue_overflow_count
    assert accepted == queue.get_metrics().total_accepted
    assert snapshot.total_dropped == snapshot.application_queue_overflow_count


def test_telemetry_snapshot_frozen():
    queue = BoundedEventQueue(capacity=10)
    aggregator = PipelineTelemetryAggregator(queue=queue)
    snapshot = aggregator.snapshot()

    with pytest.raises((TypeError, ValueError)):
        snapshot.current_queue_depth = 99  # type: ignore[misc]


def test_telemetry_aggregator_with_degraded_watcher():
    class DummyWatcher:
        def __init__(self):
            self.overflow_count = 3
            self.health = WatcherHealth.DEGRADED
            self.degradation_reasons = ["Kernel buffer overflow in driver"]

    queue = BoundedEventQueue(capacity=10)
    aggregator = PipelineTelemetryAggregator(
        queue=queue,
        watchers=[DummyWatcher()],  # type: ignore[list-item]
    )

    snapshot = aggregator.snapshot(
        extra_degradation_reasons=["Additional diagnostic warning"]
    )
    assert snapshot.kernel_overflow_count == 3
    assert snapshot.telemetry_degraded is True
    assert "Kernel buffer overflow in driver" in snapshot.degradation_reasons
    assert "Additional diagnostic warning" in snapshot.degradation_reasons
