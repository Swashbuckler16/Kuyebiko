import threading
from datetime import UTC, datetime

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.processing.ordering import (
    EventOrderingMetadata,
    EventOrderingTracker,
    OrderingMetrics,
)


def _make_notification(
    path: str = "doc.txt",
    root_id: str = "root-1",
    monotonic_ns: int = 1_000_000,
) -> RawFileNotification:
    return RawFileNotification(
        root_id=root_id,
        relative_path=path,
        action=WindowsFileAction.MODIFIED,
        observed_at=datetime.now(UTC),
        monotonic_ns=monotonic_ns,
        is_directory=False,
    )


def test_ordering_tracker_in_order_events():
    tracker = EventOrderingTracker()
    n1 = _make_notification(monotonic_ns=1_000_000)
    n2 = _make_notification(monotonic_ns=2_000_000)

    meta1 = tracker.track(n1, processed_monotonic_ns=1_500_000)
    assert isinstance(meta1, EventOrderingMetadata)
    assert meta1.is_out_of_order is False
    assert meta1.latency_ns == 500_000
    assert meta1.latency_ms == 0.5

    meta2 = tracker.track(n2, processed_monotonic_ns=2_200_000)
    assert meta2.is_out_of_order is False
    assert meta2.latency_ns == 200_000
    assert meta2.latency_ms == 0.2

    metrics = tracker.get_metrics()
    assert isinstance(metrics, OrderingMetrics)
    assert metrics.total_tracked == 2
    assert metrics.total_out_of_order == 0


def test_ordering_tracker_out_of_order_detection():
    tracker = EventOrderingTracker()
    n1 = _make_notification(root_id="root-A", monotonic_ns=5_000_000)
    # Late arriving notification for root-A with monotonic_ns=3_000_000
    n2 = _make_notification(root_id="root-A", monotonic_ns=3_000_000)

    meta1 = tracker.track(n1, processed_monotonic_ns=5_100_000)
    assert meta1.is_out_of_order is False

    meta2 = tracker.track(n2, processed_monotonic_ns=5_200_000)
    assert meta2.is_out_of_order is True
    assert meta2.observed_monotonic_ns == 3_000_000

    metrics = tracker.get_metrics()
    assert metrics.total_tracked == 2
    assert metrics.total_out_of_order == 1
    assert metrics.out_of_order_by_root == {"root-A": 1}
    assert metrics.last_seen_monotonic_by_root["root-A"] == 5_000_000


def test_ordering_tracker_multi_root_isolation():
    tracker = EventOrderingTracker()
    # Root A at 10_000_000
    nA1 = _make_notification(root_id="root-A", monotonic_ns=10_000_000)
    # Root B at 5_000_000 (lower monotonic, but different root!)
    nB1 = _make_notification(root_id="root-B", monotonic_ns=5_000_000)

    metaA = tracker.track(nA1, processed_monotonic_ns=11_000_000)
    metaB = tracker.track(nB1, processed_monotonic_ns=11_100_000)

    assert metaA.is_out_of_order is False
    assert metaB.is_out_of_order is False  # Isolated per root!

    metrics = tracker.get_metrics()
    assert metrics.total_out_of_order == 0
    assert metrics.last_seen_monotonic_by_root["root-A"] == 10_000_000
    assert metrics.last_seen_monotonic_by_root["root-B"] == 5_000_000


def test_ordering_tracker_latency_metrics_aggregation():
    tracker = EventOrderingTracker()
    tracker.track(
        _make_notification(monotonic_ns=1_000_000),
        processed_monotonic_ns=2_000_000,  # latency 1.0 ms
    )
    tracker.track(
        _make_notification(monotonic_ns=2_000_000),
        processed_monotonic_ns=5_000_000,  # latency 3.0 ms
    )

    metrics = tracker.get_metrics()
    assert metrics.total_tracked == 2
    assert metrics.min_latency_ms == 1.0
    assert metrics.max_latency_ms == 3.0
    assert metrics.avg_latency_ms == 2.0


def test_ordering_tracker_concurrent_producers():
    tracker = EventOrderingTracker()
    num_threads = 6
    events_per_thread = 50

    def worker(thread_idx: int) -> None:
        root_id = f"root-{thread_idx}"
        for i in range(events_per_thread):
            notif = _make_notification(
                root_id=root_id,
                monotonic_ns=(i + 1) * 1_000_000,
            )
            tracker.track(
                notif,
                processed_monotonic_ns=(i + 2) * 1_000_000,
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    metrics = tracker.get_metrics()
    assert metrics.total_tracked == num_threads * events_per_thread
    assert metrics.total_out_of_order == 0
