import threading
from datetime import UTC, datetime

import pytest

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction
from kuyebiko.processing.deduplication import (
    DeduplicationMetrics,
    EventDeduplicator,
)


def _make_notification(
    path: str = "doc.txt",
    root_id: str = "root-1",
    action: WindowsFileAction = WindowsFileAction.MODIFIED,
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


def test_deduplicator_initialization_validation():
    with pytest.raises(ValueError, match="max_cache_size must be at least 1"):
        EventDeduplicator(max_cache_size=0)

    dedup = EventDeduplicator(max_cache_size=100)
    assert dedup.enabled is True
    metrics = dedup.get_metrics()
    assert isinstance(metrics, DeduplicationMetrics)
    assert metrics.total_examined == 0
    assert metrics.duplicates_suppressed == 0


def test_deduplicator_exact_duplicate_suppressed():
    dedup = EventDeduplicator(max_cache_size=10)
    notif = _make_notification(monotonic_ns=5_000_000)

    # First time: not a duplicate
    assert dedup.is_duplicate(notif) is False

    # Second time with identical fields and monotonic timestamp: duplicate!
    assert dedup.is_duplicate(notif) is True

    metrics = dedup.get_metrics()
    assert metrics.total_examined == 2
    assert metrics.duplicates_suppressed == 1
    assert metrics.cache_size == 1


def test_deduplicator_preserves_repeated_modifications():
    """CRITICAL: Successive writes to the same file must NEVER be suppressed."""
    dedup = EventDeduplicator(max_cache_size=10)

    # Write chunk 1 at T1
    notif1 = _make_notification(
        path="data.bin", action=WindowsFileAction.MODIFIED, monotonic_ns=100
    )
    # Write chunk 2 at T2
    notif2 = _make_notification(
        path="data.bin", action=WindowsFileAction.MODIFIED, monotonic_ns=200
    )
    # Write chunk 3 at T3
    notif3 = _make_notification(
        path="data.bin", action=WindowsFileAction.MODIFIED, monotonic_ns=300
    )

    assert dedup.is_duplicate(notif1) is False
    assert dedup.is_duplicate(notif2) is False
    assert dedup.is_duplicate(notif3) is False

    metrics = dedup.get_metrics()
    assert metrics.total_examined == 3
    assert metrics.duplicates_suppressed == 0
    assert metrics.cache_size == 3


def test_deduplicator_preserves_create_then_modify():
    dedup = EventDeduplicator(max_cache_size=10)

    n_create = _make_notification(
        path="new.txt", action=WindowsFileAction.ADDED, monotonic_ns=100
    )
    n_modify = _make_notification(
        path="new.txt", action=WindowsFileAction.MODIFIED, monotonic_ns=100
    )

    assert dedup.is_duplicate(n_create) is False
    assert dedup.is_duplicate(n_modify) is False
    assert dedup.get_metrics().duplicates_suppressed == 0


def test_deduplicator_multi_root_isolation():
    dedup = EventDeduplicator(max_cache_size=10)

    nA = _make_notification(path="shared.txt", root_id="root-A", monotonic_ns=100)
    nB = _make_notification(path="shared.txt", root_id="root-B", monotonic_ns=100)

    assert dedup.is_duplicate(nA) is False
    assert dedup.is_duplicate(nB) is False
    assert dedup.get_metrics().duplicates_suppressed == 0


def test_deduplicator_cache_eviction_bounded():
    dedup = EventDeduplicator(max_cache_size=3)

    for i in range(5):
        notif = _make_notification(path=f"file_{i}.txt", monotonic_ns=i)
        assert dedup.is_duplicate(notif) is False

    metrics = dedup.get_metrics()
    assert metrics.cache_size == 3
    assert metrics.cache_evictions == 2
    assert metrics.total_examined == 5


def test_deduplicator_disabled_mode():
    dedup = EventDeduplicator(enabled=False)
    notif = _make_notification(monotonic_ns=100)

    assert dedup.is_duplicate(notif) is False
    assert dedup.is_duplicate(notif) is False
    assert dedup.get_metrics().duplicates_suppressed == 0


def test_deduplicator_invalid_input_type():
    dedup = EventDeduplicator()
    assert dedup.is_duplicate("not_a_notification") is False  # type: ignore[arg-type]
    metrics = dedup.get_metrics()
    assert metrics.deduplication_errors == 1


def test_deduplicator_clear():
    dedup = EventDeduplicator(max_cache_size=10)
    notif = _make_notification(monotonic_ns=100)
    dedup.is_duplicate(notif)
    assert dedup.get_metrics().cache_size == 1

    dedup.clear()
    assert dedup.get_metrics().cache_size == 0
    # After clear, notif is no longer in cache
    assert dedup.is_duplicate(notif) is False


def test_deduplicator_thread_safety():
    dedup = EventDeduplicator(max_cache_size=500)
    num_threads = 6
    events_per_thread = 50

    def worker(t_idx: int) -> None:
        for i in range(events_per_thread):
            notif = _make_notification(
                path=f"thread_{t_idx}/file_{i}.txt",
                monotonic_ns=i,
            )
            dedup.is_duplicate(notif)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert dedup.get_metrics().total_examined == num_threads * events_per_thread


def test_deduplicator_ttl_expiry():
    """Verify that fingerprints older than ttl_seconds are expired and evicted."""
    ttl_s = 2.0
    dedup = EventDeduplicator(max_cache_size=10, ttl_seconds=ttl_s)
    notif = _make_notification(path="doc.txt", monotonic_ns=1_000)

    # Ingest at t = 1.0 second (1_000_000_000 ns)
    t1_ns = 1_000_000_000
    assert dedup.is_duplicate(notif, current_monotonic_ns=t1_ns) is False

    # Within TTL (t = 2.0s, delta 1s < 2s): should be detected as duplicate
    t2_ns = 2_000_000_000
    assert dedup.is_duplicate(notif, current_monotonic_ns=t2_ns) is True
    assert dedup.get_metrics().duplicates_suppressed == 1

    # After TTL has elapsed (t = 4.0s, delta 3s > 2s): expired!
    t3_ns = 4_000_000_000
    # Notification with same fingerprint is now admitted because previous entry expired
    assert dedup.is_duplicate(notif, current_monotonic_ns=t3_ns) is False

    metrics = dedup.get_metrics()
    assert metrics.cache_expirations >= 1
    assert metrics.duplicates_suppressed == 1
