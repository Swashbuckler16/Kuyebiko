"""Phase 5 performance and quality benchmarking suite for Kuyebiko.

Measures throughput, evaluation latency percentiles (P50, P95, mean), memory usage,
multi-horizon correlation overhead, and multi-root scalability across 1,000 to
10,000 event workloads with all 11 foundational and advanced detection signals.
"""

import gc
import platform
import sys
import time
import tracemalloc
from datetime import UTC, datetime

from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.multi_horizon import MultiHorizonSlidingWindow
from kuyebiko.detection.signals.data_destruction import DataDestructionSignalEvaluator
from kuyebiko.detection.signals.filesystem_discovery import (
    FilesystemDiscoverySignalEvaluator,
)
from kuyebiko.detection.signals.in_place_transformation import (
    InPlaceTransformationSignalEvaluator,
)
from kuyebiko.detection.signals.indicator_removal import IndicatorRemovalSignalEvaluator
from kuyebiko.detection.signals.low_and_slow import LowAndSlowSignalEvaluator
from kuyebiko.detection.signals.recovery_inhibition import (
    RecoveryInhibitionSignalEvaluator,
)
from kuyebiko.models.events import (
    CorrelationProvenanceType,
    EventSource,
    EventType,
    FileEvent,
    sign_provenance_payload,
)


def generate_benchmark_events(
    count: int,
    root_id: str = "root-bench",
    base_time_ns: int | None = None,
) -> list[FileEvent]:
    """Generate realistic synthetic FileEvent stream."""
    base_ns = base_time_ns or time.monotonic_ns()
    now_utc = datetime.now(UTC)
    events: list[FileEvent] = []

    dirs = ["finance", "engineering", "legal", "hr", "operations"]
    exts = ["docx", "pdf", "xlsx", "jpg", "txt", "csv"]

    for i in range(count):
        d = dirs[i % len(dirs)]
        ext = exts[i % len(exts)]
        file_path = f"{d}/record_{i}.{ext}"

        mod = i % 100
        if mod < 60:
            ev_type = EventType.MODIFIED
            old_path = None
            new_path = None
            prov = None
        elif mod < 80:
            ev_type = EventType.RENAMED
            old_path = f"{d}/record_{i}.old"
            new_path = file_path
            prov = sign_provenance_payload(
                CorrelationProvenanceType.PHASE3_CORRELATOR,
                old_path,
                new_path,
            )
        elif mod < 90:
            ev_type = EventType.CREATED
            old_path = None
            new_path = None
            prov = None
        else:
            ev_type = EventType.DELETED
            old_path = None
            new_path = None
            prov = None

        events.append(
            FileEvent(
                event_id=f"bench_{root_id}_{i}",
                root_id=root_id,
                file_path=file_path,
                event_type=ev_type,
                old_path=old_path,
                new_path=new_path,
                correlation_provenance=prov,
                monotonic_ns=base_ns + i * 1_000_000,  # 1ms intervals
                timestamp_utc=now_utc,
                source=EventSource.WINDOWS_WATCHER,
            )
        )
    return events


def build_benchmarked_engine(
    use_multi_horizon: bool = False,
) -> DetectionEngine:
    """Instantiate a DetectionEngine with all 11 signals registered."""
    correlator = MultiHorizonSlidingWindow() if use_multi_horizon else None
    engine = DetectionEngine(
        correlator=correlator,
        auto_register_default_signals=True,
    )
    # Register the 6 advanced evaluators
    engine.registry.register(DataDestructionSignalEvaluator())
    engine.registry.register(FilesystemDiscoverySignalEvaluator())
    engine.registry.register(IndicatorRemovalSignalEvaluator())
    engine.registry.register(InPlaceTransformationSignalEvaluator())
    engine.registry.register(LowAndSlowSignalEvaluator())
    engine.registry.register(RecoveryInhibitionSignalEvaluator())
    return engine


def benchmark_stream_throughput(
    event_counts: list[int] | None = None,
) -> list[dict]:
    """Benchmark end-to-end event stream throughput and memory consumption."""
    counts = event_counts or [1000, 5000, 10000]
    results = []

    for count in counts:
        engine = build_benchmarked_engine(use_multi_horizon=True)
        events = generate_benchmark_events(count, "root-throughput")

        gc.collect()
        tracemalloc.start()
        start_time = time.perf_counter()

        for ev in events:
            engine.process_event(ev)

        elapsed = time.perf_counter() - start_time
        _current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        rate = count / elapsed if elapsed > 0 else 0.0

        results.append(
            {
                "event_count": count,
                "elapsed_seconds": round(elapsed, 4),
                "events_per_second": round(rate, 1),
                "peak_memory_mb": round(peak_mem / (1024 * 1024), 2),
            }
        )

    return results


def benchmark_evaluation_latency(iterations: int = 100) -> dict:
    """Benchmark evaluation cycle latency percentiles across all 11 signals."""
    engine = build_benchmarked_engine(use_multi_horizon=True)
    events = generate_benchmark_events(500, "root-latency")
    for ev in events:
        engine.process_event(ev)

    latencies_ms: list[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.evaluate_root("root-latency")
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    latencies_ms.sort()
    p50 = latencies_ms[int(len(latencies_ms) * 0.50)]
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    mean_lat = sum(latencies_ms) / len(latencies_ms)

    return {
        "iterations": iterations,
        "mean_latency_ms": round(mean_lat, 3),
        "p50_latency_ms": round(p50, 3),
        "p95_latency_ms": round(p95, 3),
        "min_latency_ms": round(latencies_ms[0], 3),
        "max_latency_ms": round(latencies_ms[-1], 3),
    }


def benchmark_multi_root_scaling(
    root_counts: list[int] | None = None,
) -> list[dict]:
    """Benchmark multi-root isolation and concurrency scaling."""
    r_counts = root_counts or [1, 4, 16]
    results = []

    for r_count in r_counts:
        engine = build_benchmarked_engine(use_multi_horizon=True)
        events_per_root = 500
        all_events = []
        for r_idx in range(r_count):
            all_events.extend(
                generate_benchmark_events(events_per_root, f"root-scale-{r_idx}")
            )

        gc.collect()
        t0 = time.perf_counter()
        for ev in all_events:
            engine.process_event(ev)
        elapsed = time.perf_counter() - t0

        total_evts = len(all_events)
        throughput = total_evts / elapsed if elapsed > 0 else 0.0

        results.append(
            {
                "root_count": r_count,
                "total_events": total_evts,
                "elapsed_seconds": round(elapsed, 4),
                "events_per_second": round(throughput, 1),
            }
        )

    return results


def main() -> None:
    print("=" * 72)
    print("KUYEBIKO PHASE 5 BENCHMARKING & VALIDATION SUITE")
    print("=" * 72)
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python: {sys.version.split()[0]} ({platform.python_implementation()})")
    print("Active Signals: 11 (5 foundational + 6 advanced modules)")
    print("Multi-Horizon Windows: Enabled (10s, 60s, 300s)")
    print("-" * 72)

    print("\n[1/3] Benchmarking Event Stream Throughput & Memory...")
    tp_results = benchmark_stream_throughput()
    hdr = (
        f"{'Events':>8} | {'Elapsed (s)':>12} | "
        f"{'Throughput (evt/s)':>20} | {'Peak Mem (MB)':>14}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in tp_results:
        print(
            f"{r['event_count']:>8} | {r['elapsed_seconds']:>12.4f} | "
            f"{r['events_per_second']:>20.1f} | {r['peak_memory_mb']:>14.2f}"
        )

    print("\n[2/3] Benchmarking Evaluation Cycle Latency (11 Active Signals)...")
    lat_res = benchmark_evaluation_latency(100)
    print(f"Iterations: {lat_res['iterations']}")
    print(f"Mean Latency: {lat_res['mean_latency_ms']:.3f} ms")
    print(f"P50  Latency: {lat_res['p50_latency_ms']:.3f} ms")
    print(f"P95  Latency: {lat_res['p95_latency_ms']:.3f} ms")
    print(f"Min  Latency: {lat_res['min_latency_ms']:.3f} ms")
    print(f"Max  Latency: {lat_res['max_latency_ms']:.3f} ms")

    print("\n[3/3] Benchmarking Multi-Root Scalability...")
    mr_results = benchmark_multi_root_scaling()
    hdr_mr = (
        f"{'Roots':>8} | {'Total Events':>14} | "
        f"{'Elapsed (s)':>12} | {'Throughput (evt/s)':>20}"
    )
    print(hdr_mr)
    print("-" * len(hdr_mr))
    for r in mr_results:
        print(
            f"{r['root_count']:>8} | {r['total_events']:>14} | "
            f"{r['elapsed_seconds']:>12.4f} | {r['events_per_second']:>20.1f}"
        )

    print("\n" + "=" * 72)
    print("ALL PHASE 5 BENCHMARKS COMPLETED SUCCESSFULLY")
    print("=" * 72)


if __name__ == "__main__":
    main()
