# Kuyebiko — Phase 4 (Steps 4.1 to 4.5) Implementation & Progress Report

**Platform:** Local-First Windows Ransomware Behaviour Monitoring & Investigation  
**Author & Code Owner:** Atharva Ghag ([@Swashbuckler16](https://github.com/Swashbuckler16))  
**License:** GNU General Public License v3.0 (GNU GPL v3.0)  
**Date:** 2026-11-07  
**Scope:** Phase 4 Steps 4.1–4.5 (Core Behaviour Detection Engine)  
**Repository Baseline Commit:** `8ef862f392d7da0e94186e788d8b58ab35641d10`  
**Test Suite:** 299 passed in 10.21s (100% pass rate)  
**Code Coverage:** 94% statement coverage across 2,913 statements  

---

## 1. Architecture Summary

Phase 4 introduces the Core Behaviour Detection Engine (`src/kuyebiko/detection/`), transforming raw, normalized filesystem events (`FileEvent`) emitted by Phase 3 into explainable, multi-factor ransomware detection intelligence without inspecting file contents, executing live malware, or modifying the filesystem.

### Key Architectural Pillars:
1. **Side-Effect Free & Read-Only:** The engine operates strictly on in-memory normalized metadata (`FileEvent`), never invoking Windows file deletion, encryption, process termination, or content inspection.
2. **Per-Root Monotonic Sliding Windows:** Each monitored directory root possesses an isolated `RootSlidingWindow` bounded by capacity (`max_events_per_root`) and expired deterministically via `monotonic_ns` deltas.
3. **O(1) Incremental Statistical Aggregation:** Precomputed event counters (created, modified, deleted, renamed, unique paths, unique directories, unique extensions, rename pairs) avoid expensive repetitive scanning over collections.
4. **Per-Evaluator Exception Isolation:** Failures in individual evaluators are trapped, logged, and isolated in `SignalRegistry.evaluate_all()` without crashing the engine, surfacing as explicit `EVALUATION_ERROR` outcomes.
5. **Multi-Factor Family Independence:** Collinear metrics are grouped into `SignalFamily` categorizations. A confirmed `DETECTION` outcome requires triggers across at least two independent signal families (`detection_family_threshold >= 2`), avoiding false alarms from single-dimension anomalies.
6. **Telemetry Degradation Visibility:** Upstream kernel overflow (`1022`) or application queue backpressure drops propagate directly into `DetectionResult`, preventing dangerous false "all clear" reports when telemetry is compromised.

---

## 2. Files Created and Modified

### Created Modules:
- `src/kuyebiko/detection/contracts.py`: Protocols for `SignalEvaluator` and `DetectionEngineProtocol`.
- `src/kuyebiko/detection/models.py`: Domain models for `SignalFamily`, `DetectionOutcome`, `SignalResult`, `WindowAggregateStats`, and `DetectionResult`.
- `src/kuyebiko/detection/context.py`: Immutable `DetectionContext` container supplied to evaluators.
- `src/kuyebiko/detection/window.py`: `RootSlidingWindow` and `SlidingWindowCorrelator` for multi-root chronological buffering and O(1) aggregation.
- `src/kuyebiko/detection/registry.py`: `SignalRegistry` for evaluator lifecycle, runtime enablement, threshold overrides, and exception isolation.
- `src/kuyebiko/detection/engine.py`: Top-level `DetectionEngine` implementing `EventConsumer` for Phase 3 pipeline integration.
- `src/kuyebiko/detection/signals/base.py`: `BaseSignalEvaluator` abstract class with safe validation, dynamic setters, and result construction.
- `src/kuyebiko/detection/signals/burst_write.py`: `FS_BURST_WRITE` evaluator.
- `src/kuyebiko/detection/signals/rename_ratio.py`: `FS_RENAME_RATIO` evaluator.
- `src/kuyebiko/detection/signals/delete_ratio.py`: `FS_DELETE_RATIO` evaluator.
- `src/kuyebiko/detection/signals/directory_traversal.py`: `FS_DIRECTORY_TRAVERSAL` evaluator.
- `src/kuyebiko/detection/signals/extension_convergence.py`: `FS_EXTENSION_CONVERGENCE` evaluator.
- `docs/detection-architecture.md`: Formal architectural specification and contracts documentation.
- `scripts/measure_phase4_performance.py`: Empirical performance benchmarking suite.
- `tests/unit/test_detection_contracts.py`: Unit tests for models, immutability, timezone validation, and protocols (8 tests).
- `tests/unit/test_sliding_window.py`: Unit tests for sliding window, expiration, bounds, and root isolation (10 tests).
- `tests/unit/test_signal_registry.py`: Unit tests for registration, dynamic thresholds, and failure isolation (7 tests).
- `tests/unit/test_detection_signals.py`: Unit tests for all five foundational behaviour signals (9 tests).
- `tests/integration/test_detection_engine_integration.py`: End-to-end integration tests covering Scenarios A through E and error isolation (9 tests).

### Modified Modules:
- `src/kuyebiko/core/exceptions.py`: Added `DetectionError` and `EvaluatorExecutionError`.
- `src/kuyebiko/detection/__init__.py`: Exported public detection engine, window, registry, and signal interfaces.
- `README.md`: Updated Phase 4 status, architectural documentation links, and benchmark summary.

---

## 3. Five Foundational Behaviour Signals

| Signal ID | Name | Family | Default Threshold | Observed Metric | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`FS_BURST_WRITE`** | Burst Write Frequency | `FILESYSTEM_ACTIVITY` | 15 unique files, rate >= 2.0 ops/sec | Unique modified paths & burst rate | Detects mass file encryption operations modifying numerous documents rapidly. Repeated writes to a single file do not trigger. |
| **`FS_RENAME_RATIO`** | Abnormal Rename Ratio | `RENAME_DELETION` | 60% rename ratio (min 5 renames) | `rename_count / total_events` | Detects mass file renaming, characteristic of ransomware appending custom extensions. Requires confirmed rename pairs. |
| **`FS_DELETE_RATIO`** | Abnormal Delete Ratio | `RENAME_DELETION` | 60% delete ratio (min 5 deletes) | `delete_count / total_events` | Detects bulk file deletion or replace-and-delete encryption schemes. Differentiates file from directory deletions. |
| **`FS_DIRECTORY_TRAVERSAL`** | Directory Traversal Diversity | `DIRECTORY_TRAVERSAL` | >= 5 unique directories touched | Unique relative directory count | Detects rapid recursive directory traversal across divergent branches of the filesystem. |
| **`FS_EXTENSION_CONVERGENCE`** | File Extension Convergence | `FILE_TRANSFORMATION` | >= 3 diverse original extensions converging to 1 target (>= 75% ratio) | Distinct source extensions converted | Detects homogenization of disparate file types (`.docx`, `.pdf`, `.xlsx`, `.jpg`) into a single ransomware extension (e.g., `.locked`). |

---

## 4. Detection Pipeline Data Flow

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
  - EventDeduplicator (TTL window)
  - EventOrderingTracker (monotonic order)
  - EventNormalizer & RenameCorrelator
            |
            v (Normalized FileEvent + EventOrderingMetadata)
[DetectionEngine] (EventConsumer)
            |
            +---> [SlidingWindowCorrelator] (Per-root chronological window, monotonic prune)
            |
            +---> [SignalRegistry] (Isolated evaluator execution)
                     |
                     +---> FS_BURST_WRITE
                     +---> FS_RENAME_RATIO
                     +---> FS_DELETE_RATIO
                     +---> FS_DIRECTORY_TRAVERSAL
                     +---> FS_EXTENSION_CONVERGENCE
            |
            v (DetectionResult: NO_DETECTION | SUSPICIOUS_ACTIVITY | DETECTION | INSUFFICIENT_TELEMETRY | EVALUATION_ERROR)
[Subscribed Detection Listeners]
```

---

## 5. Configuration Options

| Parameter | Subsystem | Default | Description |
| :--- | :--- | :--- | :--- |
| `window_duration_seconds` | `SlidingWindowCorrelator` | `10.0` | Active temporal correlation window duration in seconds. |
| `max_events_per_root` | `SlidingWindowCorrelator` | `5000` | Hard cap on retained events per monitored root. |
| `max_active_roots` | `SlidingWindowCorrelator` | `100` | Maximum concurrently tracked monitored roots before idle eviction. |
| `detection_family_threshold` | `DetectionEngine` | `2` | Minimum independent signal families required for confirmed `DETECTION`. |
| `threshold` | `BurstWriteSignalEvaluator` | `15.0` | Minimum unique modified files required to trigger burst write. |
| `rate_threshold` | `BurstWriteSignalEvaluator` | `2.0` | Minimum writes per second during burst span. |
| `threshold` | `RenameRatioSignalEvaluator` | `0.60` | Minimum proportion of rename operations relative to total events. |
| `threshold` | `DeleteRatioSignalEvaluator` | `0.60` | Minimum proportion of file deletion operations. |
| `threshold` | `DirectoryTraversalSignalEvaluator` | `5.0` | Minimum distinct directories touched in active window. |
| `threshold` | `ExtensionConvergenceSignalEvaluator` | `3.0` | Minimum distinct original extensions converging to common target. |
| `min_convergence_ratio` | `ExtensionConvergenceSignalEvaluator` | `0.75` | Minimum ratio of renamed files matching the top target extension. |

---

## 6. Test Suite & Coverage Verification

### Test Breakdown:
- **Baseline Phase 3:** 256 passed
- **New Phase 4 Unit Tests:**
  - `tests/unit/test_detection_contracts.py`: 8 passed
  - `tests/unit/test_sliding_window.py`: 10 passed
  - `tests/unit/test_signal_registry.py`: 7 passed
  - `tests/unit/test_detection_signals.py`: 9 passed
- **New Phase 4 Integration Tests:**
  - `tests/integration/test_detection_engine_integration.py`: 9 passed
- **Total Test Count:** **299 passed** (0 failed, 0 skipped, 10.21s execution)

### Code Coverage:
```
Name                                                      Stmts   Miss  Cover
-----------------------------------------------------------------------------
src\kuyebiko\detection\__init__.py                           13      0   100%
src\kuyebiko\detection\context.py                            23      1    96%
src\kuyebiko\detection\contracts.py                          22      0   100%
src\kuyebiko\detection\engine.py                            111     11    90%
src\kuyebiko\detection\models.py                             70      1    99%
src\kuyebiko\detection\registry.py                           87      4    95%
src\kuyebiko\detection\signals\__init__.py                    7      0   100%
src\kuyebiko\detection\signals\base.py                       56      5    91%
src\kuyebiko\detection\signals\burst_write.py                38      5    87%
src\kuyebiko\detection\signals\delete_ratio.py               35      4    89%
src\kuyebiko\detection\signals\directory_traversal.py        30      1    97%
src\kuyebiko\detection\signals\extension_convergence.py      52      4    92%
src\kuyebiko\detection\signals\rename_ratio.py               34      4    88%
src\kuyebiko\detection\window.py                            236     20    92%
-----------------------------------------------------------------------------
TOTAL (Entire Project)                                     2913    181    94%
```

---

## 7. Performance Benchmarking Results

Executed locally on **Windows 11 (AMD64)** running **Python 3.14.4 (CPython)** via `scripts/measure_phase4_performance.py`:

| Workload | Event Volume & Roots | Throughput (events/sec) | Avg Latency | P50 Latency | P95 Latency | P99 Latency | Peak Heap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small Load** | 100 events, 1 root | **1,924.7 eps** | 0.518 ms | 0.415 ms | 1.400 ms | 1.682 ms | **0.079 MB** |
| **Medium Load** | 1,000 events, 1 root | **326.7 eps** | 3.058 ms | 2.820 ms | 6.373 ms | 10.135 ms | **0.281 MB** |
| **High Load** | 10,000 events, 1 root | **34.7 eps** | 28.816 ms | 31.941 ms | 48.921 ms | 57.993 ms | **2.118 MB** |
| **Multi-Root Concurrent** | 4,000 events, 4 roots | **275.4 eps** | 3.628 ms | 3.856 ms | 6.343 ms | 8.123 ms | **0.859 MB** |
| **High-Volume Multi-Root** | 10,000 events, 5 roots | **127.4 eps** | 7.848 ms | 7.391 ms | 16.586 ms | 22.439 ms | **2.050 MB** |

### Benchmark Observations:
- In realistic multi-root workloads (5 roots receiving 10,000 events), processing latency averages **7.85 ms** per event with **127.4 events/sec** throughput.
- Peak memory footprint is exceptionally lightweight, allocating at most **2.12 MB** under sustained 10,000 event workloads.
- Evaluators execute synchronously and deterministically with zero garbage collection spikes.

---

## 8. Known Limitations & False-Positive Risks

1. **Benign High-Volume Batch Operations:** Operations such as code compilation (`cargo build`, `npm install`), photo editing exports (`Lightroom`), or git branch switching can produce high burst write and delete rates. Kuyebiko addresses this by requiring multi-family correlation (e.g. extension convergence + traversal + burst), but standalone threshold tuning will be calibrated in Step 4.6.
2. **Low-and-Slow Evasion:** Ransomware that deliberately encrypts one file every 30 seconds will stay beneath a 10-second sliding correlation window. Expanding correlation to multi-tiered sliding windows (e.g. 10s, 60s, 300s) will be addressed in future phases.
3. **No Direct Process Identity:** The native Windows `ReadDirectoryChangesW` API does not provide originating Process IDs. Behaviour is monitored at the filesystem interface. ETW / Sysmon correlation will provide process attribution in Phase 5.
4. **No Content Inspection:** Encrypted files with preserved extensions and no rename operations cannot be validated as encrypted based purely on metadata alone without entropy analysis (planned for Phase 4.8).

---

## 9. Next Steps (Phase 4.6+)

- **Step 4.6:** Multi-window temporal correlation (tiered 10s, 60s, 300s windows for low-and-slow detection).
- **Step 4.7:** Composite Risk Scoring Engine & Heuristic Weighting.
- **Step 4.8:** File entropy estimation and header inspection adapter.
- **Step 4.9:** Relational SQLite persistence of `SecurityIncident` records with cryptographic hash chaining.
