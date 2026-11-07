# Kuyebiko — Phase 4 (Steps 4.1 to 4.5) Implementation & Audit Fixes Report

**Platform:** Local-First Windows Ransomware Behaviour Monitoring & Investigation  
**Author & Code Owner:** Atharva Ghag ([@Swashbuckler16](https://github.com/Swashbuckler16))  
**License:** GNU General Public License v3.0 (GNU GPL v3.0)  
**Date:** 2026-11-07  
**Scope:** Phase 4 Steps 4.1–4.5 Core Detection Engine + Comprehensive Engineering Audit Fixes  
**Test Suite:** 302 passed in 9.54s (100% pass rate)  
**Code Coverage:** 93% statement coverage across 3,010 statements  

---

## 1. Executive Summary & Audit Resolution

Following the initial implementation of Phase 4 Steps 4.1–4.5, a comprehensive engineering audit identified six critical and high-priority behavioural issues. All six have been resolved, verified with automated tests, benchmarked, and documented:

### Audit Issues Addressed & Resolved:
1. **Critical — Out-of-Order Event Handling (`window.py`):**
   - *Previous Defect:* Window expiration assumed events were appended chronologically. Retrograde events arriving behind newer events could remain stuck in the window past their expiration.
   - *Fix:* `RootSlidingWindow` now maintains strictly sorted chronological storage using monotonic timestamps (`bisect.bisect_right`). Events arriving out-of-order that are already older than the window horizon are dropped immediately without polluting the window. Because storage is strictly sorted, `self._events[0]` is guaranteed to be the oldest event, ensuring deterministic O(k) expiration at the exact due time.
2. **Critical — Performance Scaling & Evaluator Pre-Screening (`engine.py`, signals):**
   - *Previous Defect:* Every incoming event triggered full evaluation of all 5 signals, repeatedly scanning complete event collections.
   - *Fix:* Added O(1) statistical pre-screening guards to all five evaluators using `context.stats`. If precomputed counts (writes, deletes, renames, unique directories, unique paths) cannot meet signal thresholds, evaluators exit immediately in O(1) without iterating over `context.events`. Added configurable evaluation interval throttling (`eval_interval_events: int = 1`).
3. **High — Window Capacity Degradation Recovery (`window.py`):**
   - *Previous Defect:* `capacity_dropped_events` remained cumulative, causing a root to stay marked as degraded permanently even after affected events expired.
   - *Fix:* Replaced static cumulative counter with sliding-horizon drop tracking (`_capacity_drop_timestamps: deque[int]`). Drops expire as monotonic clock moves past `window_duration_seconds`. Once active drops reach 0, telemetry quality recovers automatically (`is_telemetry_degraded = False`).
4. **High — Active-Root Eviction Telemetry Loss (`window.py`):**
   - *Previous Defect:* When `max_active_roots` capacity was reached, the oldest idle root was silently evicted without preserving telemetry loss provenance.
   - *Fix:* `SlidingWindowCorrelator` now explicitly tracks evicted roots in `_evicted_roots_loss` with timestamps, increments `_total_evicted_roots_count`, logs warning telemetry, and propagates `is_telemetry_degraded = True` with `root_previously_evicted_due_to_capacity_limit` when an evicted root re-appears.
5. **High — Rename Signal Semantic Verification (`rename_ratio.py`):**
   - *Previous Defect:* The rename evaluator required old and new paths, but did not independently verify that its count represented confirmed, distinct file rename pairs.
   - *Fix:* `RenameRatioSignalEvaluator` now enforces independent verification: checks that `old_path != new_path`, verifies both paths are valid relative paths, excludes directory renames, cross-references against `context.stats.rename_pairs_count`, and records verified rename pairs in metadata.
6. **Medium — Detection Thresholds & Benign Workload Distinction (`engine.py`):**
   - *Previous Defect:* Two triggered families naively produced `DETECTION`, falsely flagging benign batch operations (e.g. Burst Write + Traversal during a project build, or Delete Ratio + Traversal during folder cleanup).
   - *Fix:* Refined decision engine semantics: confirmed `DETECTION` requires either >= 3 distinct families, or at least 2 families containing verified file transformation/mutation indicators (`FILE_TRANSFORMATION` via extension convergence or verified rename burst). Combinations typical of benign developer builds or directory cleanups are classified as `SUSPICIOUS_ACTIVITY`.

---

## 2. Updated Architecture & Data Flow

```
[Windows Filesystem Activity]
            |
            v (Kernel ReadDirectoryChangesW)
[WindowsDirectoryWatcher]
            |
            v (RawFileNotification callback)
[EventIngestor] -> [BoundedEventQueue]
            |
            v
[EventProcessingWorker]
  - EventDeduplicator (TTL cache)
  - EventOrderingTracker (monotonic order)
  - EventNormalizer & RenameCorrelator
            |
            v (Normalized FileEvent + EventOrderingMetadata)
[DetectionEngine] (EventConsumer)
            |
            +---> [SlidingWindowCorrelator] (Strict chronological order via bisect)
            |     - Bounded per-root window (5,000 max events)
            |     - O(1) incremental statistics (paths, dirs, exts, counts)
            |     - Recoverable capacity degradation (active horizon drops)
            |     - Active-root eviction telemetry loss tracking
            |
            +---> [SignalRegistry] (Isolated evaluator execution)
                     |
                     +---> FS_BURST_WRITE (O(1) pre-screened)
                     +---> FS_RENAME_RATIO (Verified distinct pairs)
                     +---> FS_DELETE_RATIO (O(1) pre-screened)
                     +---> FS_DIRECTORY_TRAVERSAL (O(1) pre-screened)
                     +---> FS_EXTENSION_CONVERGENCE (O(1) pre-screened)
            |
            v
[DetectionResult: NO_DETECTION | SUSPICIOUS_ACTIVITY | DETECTION | INSUFFICIENT_TELEMETRY | EVALUATION_ERROR]
```

---

## 3. Test Suite Verification

### Test Breakdown (302 passed in 9.54s):
- **Phase 1–3 Tests:** 256 passed
- **Phase 4 Detection Contracts:** 8 passed (`tests/unit/test_detection_contracts.py`)
- **Phase 4 Sliding Window:** 11 passed (`tests/unit/test_sliding_window.py`)
  - Includes out-of-order chronological insertion & expiration test
  - Includes capacity drop degradation recovery test
  - Includes active root eviction telemetry loss test
- **Phase 4 Signal Registry:** 7 passed (`tests/unit/test_signal_registry.py`)
- **Phase 4 Behaviour Signals:** 10 passed (`tests/unit/test_detection_signals.py`)
  - Includes distinct rename pair verification & directory rename rejection
- **Phase 4 Engine Integration:** 10 passed (`tests/integration/test_detection_engine_integration.py`)
  - Includes benign compiler build test (`SUSPICIOUS_ACTIVITY`, not `DETECTION`)
  - Includes confirmed multi-vector ransomware test (`DETECTION`)
  - Includes Scenarios A–E, listener callbacks, and evaluator crash isolation

---

## 4. Empirical Performance Benchmarking (Updated Post-Optimization)

Measured on **Windows 11 (AMD64)** running **Python 3.14.4 (CPython)** via `scripts/measure_phase4_performance.py`:

| Workload Scenario | Event Volume & Roots | Throughput (events/sec) | Avg Latency | P50 Latency | P95 Latency | Peak Heap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small Load** | 100 events, 1 root | **2,118.0 eps** | **0.47 ms** | 0.41 ms | 0.87 ms | **0.075 MB** |
| **Medium Load** | 1,000 events, 1 root | **371.5 eps** | **2.69 ms** | 2.56 ms | 5.02 ms | **0.290 MB** |
| **High Load** | 10,000 events, 1 root | **48.1 eps** | **20.80 ms** | 24.49 ms | 32.77 ms | **2.156 MB** |
| **Concurrent Multi-Root** | 4,000 events, 4 roots | **386.3 eps** | **2.59 ms** | 2.64 ms | 4.85 ms | **0.862 MB** |
| **High-Volume Multi-Root** | 10,000 events, 5 roots | **180.9 eps** | **5.53 ms** | 5.42 ms | 10.81 ms | **2.038 MB** |

### Benchmark Analysis:
- **Optimization Impact:** Multi-root throughput increased from **127.4 eps to 180.9 eps** (+42%), with average processing latency decreasing from **7.85 ms to 5.53 ms** per event.
- **Memory Footprint:** Peak memory remains remarkably low at **~2.04 MB** for 10,000 sustained events across 5 concurrent roots.
