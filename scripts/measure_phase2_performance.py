import pprint
import shutil
import tempfile
import time
import tracemalloc
from pathlib import Path

from kuyebiko.collectors.models import (
    MonitoredRoot,
    RawFileNotification,
    WindowsFileAction,
)
from kuyebiko.collectors.normalizer import EventNormalizer
from kuyebiko.collectors.registry import MonitoredRootRegistry
from kuyebiko.collectors.rename_correlator import RenameCorrelator
from kuyebiko.collectors.windows.watcher import WindowsDirectoryWatcher


def measure_performance() -> dict:
    results = {}
    temp_dir = Path(tempfile.mkdtemp(prefix="kuyebiko_perf_"))

    try:
        # 1. Notification Delivery Latency
        root = MonitoredRoot(root_id="perf-root", path=temp_dir, recursive=True)
        delivered_latencies_ms = []
        file_event_timestamp = None

        def on_latency_notif(notif: RawFileNotification):
            nonlocal file_event_timestamp
            if file_event_timestamp is not None:
                now_ns = time.perf_counter_ns()
                delta_ms = (now_ns - file_event_timestamp) / 1e6
                delivered_latencies_ms.append(delta_ms)
                file_event_timestamp = None

        watcher = WindowsDirectoryWatcher(root=root, callback=on_latency_notif)
        watcher.start()
        time.sleep(0.15)  # Settle

        for i in range(20):
            p = temp_dir / f"latency_{i}.tmp"
            file_event_timestamp = time.perf_counter_ns()
            p.write_text("latency test", encoding="utf-8")
            start_wait = time.perf_counter()
            while (
                file_event_timestamp is not None
                and time.perf_counter() - start_wait < 0.5
            ):
                time.sleep(0.002)

        if delivered_latencies_ms:
            avg_latency = sum(delivered_latencies_ms) / len(delivered_latencies_ms)
            min_latency = min(delivered_latencies_ms)
            max_latency = max(delivered_latencies_ms)
        else:
            avg_latency = min_latency = max_latency = 0.0

        results["delivery_latency_avg_ms"] = round(avg_latency, 3)
        results["delivery_latency_min_ms"] = round(min_latency, 3)
        results["delivery_latency_max_ms"] = round(max_latency, 3)

        # 2. Event Normalization & Rename Correlation Overhead
        correlator = RenameCorrelator()
        normalizer = EventNormalizer()

        notif_added = RawFileNotification(
            root_id="perf-root",
            relative_path="sample/document.txt",
            action=WindowsFileAction.ADDED,
            monotonic_ns=time.monotonic_ns(),
        )

        n_iter = 1000
        start_t = time.perf_counter_ns()
        for _ in range(n_iter):
            normalizer.normalize_notification(notif_added)
        elapsed_ns = time.perf_counter_ns() - start_t
        results["normalization_overhead_us"] = round((elapsed_ns / n_iter) / 1000, 3)

        notif_old = RawFileNotification(
            root_id="perf-root",
            relative_path="sample/old.txt",
            action=WindowsFileAction.RENAMED_OLD_NAME,
            monotonic_ns=1000,
        )
        notif_new = RawFileNotification(
            root_id="perf-root",
            relative_path="sample/new.txt",
            action=WindowsFileAction.RENAMED_NEW_NAME,
            monotonic_ns=1010,
        )

        start_corr = time.perf_counter_ns()
        for _ in range(n_iter):
            correlator.process_notification(notif_old)
            correlator.process_notification(notif_new)
        elapsed_corr = time.perf_counter_ns() - start_corr
        results["rename_correlation_overhead_us"] = round(
            (elapsed_corr / n_iter) / 1000, 3
        )

        # 3. Memory & CPU Usage During Burst (100 files CRUD)
        tracemalloc.start()
        cpu_start = time.process_time()
        wall_start = time.perf_counter()

        burst_files = []
        for i in range(100):
            bf = temp_dir / f"burst_{i}.dat"
            bf.write_text(f"content {i}", encoding="utf-8")
            burst_files.append(bf)

        for bf in burst_files[:50]:
            bf.write_text("modified content", encoding="utf-8")

        for bf in burst_files[50:75]:
            renamed = bf.with_suffix(".renamed")
            bf.rename(renamed)

        for bf in burst_files[75:]:
            bf.unlink()

        time.sleep(0.3)

        cpu_elapsed = time.process_time() - cpu_start
        wall_elapsed = time.perf_counter() - wall_start
        _, mem_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        results["burst_wall_time_s"] = round(wall_elapsed, 3)
        results["burst_process_cpu_time_s"] = round(cpu_elapsed, 4)
        results["memory_peak_kib"] = round(mem_peak / 1024, 2)
        results["events_observed_burst"] = watcher.events_observed

        # 4. Idle CPU Overhead
        idle_cpu_start = time.process_time()
        time.sleep(0.5)
        idle_cpu_time = time.process_time() - idle_cpu_start
        results["idle_cpu_time_500ms_s"] = round(idle_cpu_time, 5)

        # 5. Shutdown Duration
        stop_start = time.perf_counter_ns()
        watcher.stop()
        stop_elapsed_ms = (time.perf_counter_ns() - stop_start) / 1e6
        results["shutdown_duration_ms"] = round(stop_elapsed_ms, 3)

        # 6. Multi-Root Behavior Check
        mr_dir1 = temp_dir / "mr_root1"
        mr_dir2 = temp_dir / "mr_root2"
        mr_dir3 = temp_dir / "mr_root3"
        mr_dir1.mkdir()
        mr_dir2.mkdir()
        mr_dir3.mkdir()

        registry = MonitoredRootRegistry()
        registry.register(MonitoredRoot(root_id="mr1", path=mr_dir1))
        registry.register(MonitoredRoot(root_id="mr2", path=mr_dir2))
        registry.register(MonitoredRoot(root_id="mr3", path=mr_dir3))

        start_all_res = registry.start_all()
        time.sleep(0.1)

        results["multi_root_started_all"] = all(start_all_res.values())
        results["multi_root_count"] = len(registry.list_active_watchers())

        # Interleaved writes
        (mr_dir1 / "f1.txt").write_text("r1", encoding="utf-8")
        (mr_dir2 / "f2.txt").write_text("r2", encoding="utf-8")
        (mr_dir3 / "f3.txt").write_text("r3", encoding="utf-8")
        time.sleep(0.1)

        stop_all_start = time.perf_counter_ns()
        registry.stop_all()
        stop_all_elapsed = (time.perf_counter_ns() - stop_all_start) / 1e6
        results["multi_root_stop_all_duration_ms"] = round(stop_all_elapsed, 3)
        results["multi_root_active_after_stop"] = len(registry.list_active_watchers())

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results


if __name__ == "__main__":
    data = measure_performance()
    pprint.pprint(data)
