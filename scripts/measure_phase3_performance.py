"""Phase 3 Performance Benchmarking Suite for Kuyebiko Event Processing Pipeline.

Executes reproducible benchmarks covering:
- Scenario 1: Normal filesystem activity (create, modify, delete, rename)
- Scenario 2: High-volume burst & queue saturation
- Scenario 3: Multi-root concurrent activity
- Scenario 4: Deduplication performance (enabled vs disabled)
- Scenario 5: Failure conditions and pipeline restart recovery

Records exact latency percentiles (P50, P95, P99), throughput, CPU time,
memory usage, and queue dynamics.
"""

import logging
import math
import platform
import statistics
import threading
import time
import tracemalloc
from datetime import UTC, datetime

from kuyebiko.collectors.models import (
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.models.events import FileEvent
from kuyebiko.processing.deduplication import EventDeduplicator
from kuyebiko.processing.ingestion import EventIngestor
from kuyebiko.processing.ordering import (
    EventOrderingMetadata,
    EventOrderingTracker,
)
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.worker import EventProcessingWorker


def percentile(data: list[float], pct: float) -> float:
    """Compute the pct percentile (0 to 100) of a sorted float list."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return d0 + d1


class BenchmarkLatencyConsumer:
    """Consumer capturing processing latencies and counts for benchmarking."""

    def __init__(self) -> None:
        self.count = 0
        self.latencies_ms: list[float] = []
        self._lock = threading.Lock()

    def handle_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
    ) -> None:
        with self._lock:
            self.count += 1
            if ordering is not None:
                self.latencies_ms.append(ordering.latency_ms)


def scenario_1_normal_activity(trials: int = 3) -> dict:
    """Benchmark Scenario 1: Normal activity with mixed event types."""
    events_per_trial = 2000
    trial_throughput = []
    trial_latencies: list[float] = []
    trial_cpu_times = []

    for _ in range(trials):
        queue = BoundedEventQueue(capacity=5000)
        consumer = BenchmarkLatencyConsumer()
        worker = EventProcessingWorker(
            queue=queue,
            consumer=consumer,
            poll_timeout=0.005,
        )
        ingestor = EventIngestor(queue)
        worker.start()

        actions = [
            WindowsFileAction.ADDED,
            WindowsFileAction.MODIFIED,
            WindowsFileAction.MODIFIED,
            WindowsFileAction.REMOVED,
        ]

        t0_cpu = time.process_time()
        t0_wall = time.perf_counter()

        for i in range(events_per_trial):
            action = actions[i % len(actions)]
            notif = RawFileNotification(
                root_id="root-bench",
                relative_path=f"folder/doc_{i % 50}.txt",
                action=action,
                observed_at=datetime.now(UTC),
                monotonic_ns=time.monotonic_ns(),
                is_directory=False,
            )
            ingestor.ingest(notif)

        # Wait for queue to drain
        deadline = time.monotonic() + 10.0
        while not queue.is_empty() and time.monotonic() < deadline:
            time.sleep(0.002)

        worker.stop(timeout=2.0, drain=True)
        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()

        elapsed_wall = t1_wall - t0_wall
        elapsed_cpu = t1_cpu - t0_cpu

        throughput = consumer.count / elapsed_wall if elapsed_wall > 0 else 0
        trial_throughput.append(throughput)
        trial_latencies.extend(consumer.latencies_ms)
        trial_cpu_times.append(elapsed_cpu)

    avg_lat = statistics.mean(trial_latencies) if trial_latencies else 0.0

    return {
        "throughput_eps": round(statistics.mean(trial_throughput), 1),
        "avg_latency_ms": round(avg_lat, 3),
        "p50_latency_ms": round(percentile(trial_latencies, 50), 3),
        "p95_latency_ms": round(percentile(trial_latencies, 95), 3),
        "p99_latency_ms": round(percentile(trial_latencies, 99), 3),
        "cpu_time_s": round(statistics.mean(trial_cpu_times), 3),
    }


def scenario_2_high_volume_burst(trials: int = 3) -> dict:
    """Benchmark Scenario 2: High-volume burst causing backpressure and drops."""
    burst_size = 5000
    queue_capacity = 1000

    trial_accepted = []
    trial_dropped = []
    trial_peak_depth = []
    trial_recovery_ms = []

    for _ in range(trials):
        queue = BoundedEventQueue(capacity=queue_capacity)
        consumer = BenchmarkLatencyConsumer()
        worker = EventProcessingWorker(
            queue=queue,
            consumer=consumer,
            poll_timeout=0.005,
        )
        ingestor = EventIngestor(queue)
        worker.start()

        # Generate sudden burst faster than worker can process
        t0 = time.perf_counter()
        for i in range(burst_size):
            notif = RawFileNotification(
                root_id="burst-root",
                relative_path=f"burst_{i}.bin",
                action=WindowsFileAction.ADDED,
                observed_at=datetime.now(UTC),
                monotonic_ns=time.monotonic_ns(),
                is_directory=False,
            )
            ingestor.ingest(notif)

        # Wait for queue to drain back to zero
        while not queue.is_empty():
            time.sleep(0.005)
        t_recovered = time.perf_counter()

        recovery_ms = (t_recovered - t0) * 1000.0
        worker.stop(timeout=2.0, drain=True)

        q_metrics = queue.get_metrics()
        trial_accepted.append(q_metrics.total_accepted)
        trial_dropped.append(q_metrics.total_dropped_queue_full)
        trial_peak_depth.append(q_metrics.high_watermark)
        trial_recovery_ms.append(recovery_ms)

    return {
        "burst_total": burst_size,
        "queue_capacity": queue_capacity,
        "accepted": int(statistics.mean(trial_accepted)),
        "dropped_queue_full": int(statistics.mean(trial_dropped)),
        "peak_queue_depth": int(statistics.mean(trial_peak_depth)),
        "recovery_time_ms": round(statistics.mean(trial_recovery_ms), 1),
    }


def scenario_3_multi_root_concurrency(trials: int = 3) -> dict:
    """Benchmark Scenario 3: 4 concurrent producer threads for multi-root monitoring."""
    num_roots = 4
    events_per_root = 1000
    total_events = num_roots * events_per_root

    trial_throughput = []
    trial_latencies: list[float] = []
    trial_out_of_order = []

    for _ in range(trials):
        queue = BoundedEventQueue(capacity=10000)
        consumer = BenchmarkLatencyConsumer()
        ordering_tracker = EventOrderingTracker()
        worker = EventProcessingWorker(
            queue=queue,
            consumer=consumer,
            ordering_tracker=ordering_tracker,
            poll_timeout=0.005,
        )
        current_ingestor = EventIngestor(queue)
        worker.start()

        def producer_worker(
            root_idx: int,
            ing: EventIngestor = current_ingestor,
        ) -> None:
            r_id = f"root-{root_idx}"
            for i in range(events_per_root):
                notif = RawFileNotification(
                    root_id=r_id,
                    relative_path=f"thread_{root_idx}/file_{i}.txt",
                    action=WindowsFileAction.MODIFIED,
                    observed_at=datetime.now(UTC),
                    monotonic_ns=time.monotonic_ns(),
                    is_directory=False,
                )
                ing.ingest(notif)

        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=producer_worker, args=(r, current_ingestor))
            for r in range(num_roots)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Wait for processing
        while not queue.is_empty():
            time.sleep(0.002)

        worker.stop(timeout=2.0, drain=True)
        t1 = time.perf_counter()

        elapsed = t1 - t0
        trial_throughput.append(total_events / elapsed if elapsed > 0 else 0)
        trial_latencies.extend(consumer.latencies_ms)
        ord_metrics = ordering_tracker.get_metrics()
        trial_out_of_order.append(ord_metrics.total_out_of_order)

    return {
        "num_roots": num_roots,
        "total_events": total_events,
        "throughput_eps": round(statistics.mean(trial_throughput), 1),
        "avg_latency_ms": round(statistics.mean(trial_latencies), 3),
        "p95_latency_ms": round(percentile(trial_latencies, 95), 3),
        "out_of_order_events": int(statistics.mean(trial_out_of_order)),
    }


def scenario_4_deduplication_comparison() -> dict:
    """Benchmark Scenario 4: Compare pipeline performance with deduplication off/on."""
    num_events = 2000
    # Create stream with 40% duplicate bursts (repeated writes)
    raw_stream = []
    base_t = time.monotonic_ns()
    for i in range(num_events):
        path = f"file_{i // 2}.txt"
        m_ns = base_t + (i // 2) * 1000
        raw_stream.append(
            RawFileNotification(
                root_id="root-1",
                relative_path=path,
                action=WindowsFileAction.MODIFIED,
                observed_at=datetime.now(UTC),
                monotonic_ns=m_ns,
                is_directory=False,
            )
        )

    # 1. Dedup Disabled
    q1 = BoundedEventQueue(capacity=5000)
    c1 = BenchmarkLatencyConsumer()
    w1 = EventProcessingWorker(
        queue=q1,
        consumer=c1,
        deduplicator=None,
        poll_timeout=0.005,
    )
    w1.start()
    t0 = time.perf_counter()
    for n in raw_stream:
        q1.put_notification(n)
    while not q1.is_empty():
        time.sleep(0.002)
    w1.stop(timeout=2.0, drain=True)
    t_off = time.perf_counter() - t0

    # 2. Dedup Enabled
    q2 = BoundedEventQueue(capacity=5000)
    c2 = BenchmarkLatencyConsumer()
    dedup = EventDeduplicator(max_cache_size=2000, ttl_seconds=5.0)
    w2 = EventProcessingWorker(
        queue=q2,
        consumer=c2,
        deduplicator=dedup,
        poll_timeout=0.005,
    )
    w2.start()
    t0 = time.perf_counter()
    for n in raw_stream:
        q2.put_notification(n)
    while not q2.is_empty():
        time.sleep(0.002)
    w2.stop(timeout=2.0, drain=True)
    t_on = time.perf_counter() - t0

    dedup_metrics = dedup.get_metrics()
    overhead = round(((t_on - t_off) / t_off) * 100.0, 1) if t_off > 0 else 0.0

    return {
        "events_examined": num_events,
        "dedup_disabled_delivered": c1.count,
        "dedup_disabled_time_s": round(t_off, 3),
        "dedup_enabled_delivered": c2.count,
        "dedup_enabled_time_s": round(t_on, 3),
        "duplicates_suppressed": dedup_metrics.duplicates_suppressed,
        "overhead_percent": overhead,
    }


def scenario_5_failure_and_recovery() -> dict:
    """Benchmark Scenario 5: Fault injection, retry overhead, and restart latency."""
    queue = BoundedEventQueue(capacity=500)
    fail_count = 0

    def intermittently_failing_consumer(event: FileEvent, ordering=None) -> None:
        nonlocal fail_count
        fail_count += 1
        if fail_count % 3 == 0:
            raise RuntimeError("Injected transient consumer failure")

    worker = EventProcessingWorker(
        queue=queue,
        consumer=intermittently_failing_consumer,
        max_consumer_retries=1,
        poll_timeout=0.005,
    )
    worker.start()

    num_events = 300
    for i in range(num_events):
        queue.put_notification(
            RawFileNotification(
                root_id="fault-root",
                relative_path=f"fault_{i}.txt",
                action=WindowsFileAction.ADDED,
                observed_at=datetime.now(UTC),
                monotonic_ns=time.monotonic_ns(),
                is_directory=False,
            )
        )

    while not queue.is_empty():
        time.sleep(0.005)

    w_metrics_before = worker.get_metrics()

    # Measure clean restart time
    t0_restart = time.perf_counter()
    worker.restart(timeout=2.0)
    t_restart = time.perf_counter() - t0_restart
    worker.stop(timeout=1.0, drain=False)

    return {
        "submitted": num_events,
        "delivered": w_metrics_before.events_delivered,
        "retries": w_metrics_before.retry_attempts,
        "permanently_failed": w_metrics_before.permanently_failed_events,
        "restart_time_ms": round(t_restart * 1000.0, 2),
    }


def main() -> None:
    logging.getLogger("kuyebiko").setLevel(logging.CRITICAL)
    print("=" * 70)
    print("KUYEBIKO PHASE 3 PERFORMANCE BENCHMARKING SUITE")
    print("=" * 70)
    os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
    print(f"Platform:      {os_info}")
    print(f"Processor:     {platform.processor() or platform.machine()}")
    py_info = f"{platform.python_version()} ({platform.python_implementation()})"
    print(f"Python:        {py_info}")
    print(f"Date:          {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    tracemalloc.start()

    print("\n[1/5] Running Scenario 1: Normal Activity Baseline (3 trials)...")
    s1 = scenario_1_normal_activity(trials=3)
    print(f"      Throughput:    {s1['throughput_eps']} events/sec")
    print(f"      Avg Latency:   {s1['avg_latency_ms']} ms")
    print(f"      P50 Latency:   {s1['p50_latency_ms']} ms")
    print(f"      P95 Latency:   {s1['p95_latency_ms']} ms")
    print(f"      P99 Latency:   {s1['p99_latency_ms']} ms")
    print(f"      CPU Time:      {s1['cpu_time_s']} s")

    print("\n[2/5] Running Scenario 2: High-Volume Burst & Backpressure (3 trials)...")
    s2 = scenario_2_high_volume_burst(trials=3)
    print(f"      Burst Ingest:  {s2['burst_total']} into cap {s2['queue_capacity']}")
    print(f"      Accepted:      {s2['accepted']}")
    print(f"      Dropped:       {s2['dropped_queue_full']} (exact queue-full drops)")
    print(f"      Peak Depth:    {s2['peak_queue_depth']}")
    print(f"      Recovery Time: {s2['recovery_time_ms']} ms")

    print("\n[3/5] Running Scenario 3: Multi-Root Concurrent Activity (3 trials)...")
    s3 = scenario_3_multi_root_concurrency(trials=3)
    print(f"      Roots:         {s3['num_roots']} parallel threads")
    print(f"      Total Events:  {s3['total_events']}")
    print(f"      Throughput:    {s3['throughput_eps']} events/sec")
    print(f"      Avg Latency:   {s3['avg_latency_ms']} ms")
    print(f"      P95 Latency:   {s3['p95_latency_ms']} ms")
    print(f"      Out-of-Order:  {s3['out_of_order_events']}")

    print("\n[4/5] Running Scenario 4: Deduplication Evaluation...")
    s4 = scenario_4_deduplication_comparison()
    print(f"      Examined:      {s4['events_examined']}")
    print(
        f"      Disabled:      {s4['dedup_disabled_delivered']} in "
        f"{s4['dedup_disabled_time_s']}s"
    )
    print(
        f"      Enabled:       {s4['dedup_enabled_delivered']} in "
        f"{s4['dedup_enabled_time_s']}s"
    )
    print(f"      Suppressed:    {s4['duplicates_suppressed']} duplicates")
    print(f"      CPU Overhead:  {s4['overhead_percent']}%")

    print("\n[5/5] Running Scenario 5: Fault Injection & Restart Recovery...")
    s5 = scenario_5_failure_and_recovery()
    print(f"      Submitted:     {s5['submitted']}")
    print(f"      Delivered:     {s5['delivered']}")
    print(f"      Retried:       {s5['retries']}")
    print(f"      Perm Failed:   {s5['permanently_failed']}")
    print(f"      Restart Time:  {s5['restart_time_ms']} ms")

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n" + "=" * 70)
    print("MEMORY FOOTPRINT")
    print(f"Current Memory: {current_mem / (1024 * 1024):.2f} MB")
    print(f"Peak Memory:    {peak_mem / (1024 * 1024):.2f} MB")
    print("=" * 70)
    print("ALL BENCHMARK SCENARIOS COMPLETED SUCCESSFULLY.")
    print("=" * 70)


if __name__ == "__main__":
    main()
