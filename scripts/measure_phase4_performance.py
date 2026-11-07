"""Phase 4 performance benchmarking suite for Kuyebiko behaviour detection engine.

Evaluates throughput, evaluation latency percentiles, memory consumption, and
multi-root concurrency across 100, 1,000, and 10,000 event workloads with all
five foundational ransomware behaviour signals actively evaluating.
"""

import gc
import platform
import sys
import time
import tracemalloc
from datetime import UTC, datetime

from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.models.events import EventSource, EventType, FileEvent


def generate_benchmark_events(
    count: int,
    root_id: str = "root-bench",
    base_time_ns: int | None = None,
) -> list[FileEvent]:
    base_ns = base_time_ns or time.monotonic_ns()
    now_utc = datetime.now(UTC)
    events = []

    dirs = ["finance", "engineering", "legal", "hr", "operations"]
    exts = ["docx", "pdf", "xlsx", "jpg", "txt", "csv"]

    for i in range(count):
        d = dirs[i % len(dirs)]
        ext = exts[i % len(exts)]
        file_path = f"{d}/record_{i}.{ext}"

        # Mix: 70% modified, 15% renamed, 10% created, 5% deleted
        mod = i % 100
        if mod < 70:
            ev_type = EventType.MODIFIED
            old_path = None
            new_path = None
        elif mod < 85:
            ev_type = EventType.RENAMED
            old_path = f"{d}/record_{i}.old"
            new_path = file_path
        elif mod < 95:
            ev_type = EventType.CREATED
            old_path = None
            new_path = None
        else:
            ev_type = EventType.DELETED
            old_path = None
            new_path = None

        events.append(
            FileEvent(
                event_id=f"bench_{root_id}_{i}",
                root_id=root_id,
                file_path=file_path,
                event_type=ev_type,
                old_path=old_path,
                new_path=new_path,
                monotonic_ns=base_ns + i * 1_000_000,  # 1ms intervals
                timestamp_utc=now_utc,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def run_benchmark(event_count: int, num_roots: int = 1) -> dict:
    engine = DetectionEngine(
        auto_register_default_signals=True,
        detection_family_threshold=2,
    )

    events_per_root = event_count // num_roots
    all_events = []
    base_time = time.monotonic_ns()

    for r in range(num_roots):
        root_name = f"root-{r}"
        all_events.extend(
            generate_benchmark_events(
                events_per_root, root_id=root_name, base_time_ns=base_time
            )
        )

    # Sort interleaved by monotonic_ns to simulate concurrent multi-root arrival
    all_events.sort(key=lambda e: e.monotonic_ns)

    gc.collect()
    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()

    latencies_ms = []
    start_time = time.perf_counter()

    for event in all_events:
        t0 = time.perf_counter()
        engine.process_event(event)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    elapsed_total_sec = time.perf_counter() - start_time
    mem_peak = tracemalloc.get_traced_memory()[1] - mem_before
    tracemalloc.stop()

    latencies_ms.sort()
    avg_latency = sum(latencies_ms) / len(latencies_ms)
    p50_latency = latencies_ms[int(len(latencies_ms) * 0.50)]
    p95_latency = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99_latency = latencies_ms[int(len(latencies_ms) * 0.99)]
    max_latency = latencies_ms[-1]
    throughput = len(all_events) / elapsed_total_sec

    return {
        "event_count": len(all_events),
        "num_roots": num_roots,
        "elapsed_sec": round(elapsed_total_sec, 4),
        "throughput_eps": round(throughput, 1),
        "avg_latency_ms": round(avg_latency, 4),
        "p50_latency_ms": round(p50_latency, 4),
        "p95_latency_ms": round(p95_latency, 4),
        "p99_latency_ms": round(p99_latency, 4),
        "max_latency_ms": round(max_latency, 4),
        "peak_memory_mb": round(mem_peak / (1024 * 1024), 3),
    }


def main():
    print("=" * 80)
    print("KUYEBIKO PHASE 4 DETECTION ENGINE BENCHMARK")
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python:   {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"Time:     {datetime.now(UTC).isoformat()}")
    print("=" * 80)

    scenarios = [
        ("Small Load (100 events, 1 root)", 100, 1),
        ("Medium Load (1,000 events, 1 root)", 1_000, 1),
        ("High Load (10,000 events, 1 root)", 10_000, 1),
        ("Concurrent Multi-Root (4,000 events, 4 roots)", 4_000, 4),
        ("High Volume Multi-Root (10,000 events, 5 roots)", 10_000, 5),
    ]

    for label, count, roots in scenarios:
        print(f"\n--- Running: {label} ---")
        metrics = run_benchmark(count, num_roots=roots)
        print(
            f"  Events:          {metrics['event_count']:,} "
            f"across {metrics['num_roots']} root(s)"
        )
        print(f"  Duration:        {metrics['elapsed_sec']} seconds")
        print(f"  Throughput:      {metrics['throughput_eps']:,} events/second")
        print(f"  Avg Latency:     {metrics['avg_latency_ms']} ms")
        print(f"  P50 Latency:     {metrics['p50_latency_ms']} ms")
        print(f"  P95 Latency:     {metrics['p95_latency_ms']} ms")
        print(f"  P99 Latency:     {metrics['p99_latency_ms']} ms")
        print(f"  Peak Heap:       {metrics['peak_memory_mb']} MB")

    print("\n" + "=" * 80)
    print("BENCHMARK COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
