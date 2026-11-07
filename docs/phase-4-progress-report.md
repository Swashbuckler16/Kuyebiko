# Kuyebiko — Phase 4 Core Behaviour Detection Engine: Complete Implementation & Sign-Off Report (Steps 4.1 to 4.10)

**Platform:** Local-First Windows Ransomware Behaviour Monitoring & Investigation  
**Author & Code Owner:** Atharva Ghag ([@Swashbuckler16](https://github.com/Swashbuckler16))  
**License:** GNU General Public License v3.0 (GNU GPL v3.0)  
**Date:** 2026-11-07  
**Scope:** Phase 4 Steps 4.1–4.10 Core Detection Engine + Hardening, Verification & Final Sign-Off  
**Test Suite:** 323 passed in 9.37s (100% pass rate)  
**Code Coverage:** 93% statement coverage across 3,065 statements  

---

## 1. Executive Summary & Hardening Roadmap (Steps 4.6 to 4.10)

Phase 4 establishes the core real-time behavioural ransomware detection engine for Kuyebiko, processing normalized filesystem events into deterministic, multi-factor security detections without inspecting file contents. 

Following the initial MVP and audit fixes, five additional hardening and verification steps (Steps 4.6 to 4.10) were executed and verified:

### Step 4.6 — Rename Correlation Provenance & Detection Accuracy
- **Explicit Provenance Model:** Added `correlation_provenance: str | None = None` to `FileEvent`. `EventNormalizer.normalize_correlated_rename` attaches explicit correlation provenance (`rename_correlator:<old>-><new>`).
- **Unpaired Notification Immunity:** Raw, unpaired, or un-correlated rename notifications lack correlation provenance and can never inflate `FS_RENAME_RATIO`.
- **Directory Rename Isolation:** `RootSlidingWindow` and `RenameRatioSignalEvaluator` strictly exclude directory renames (`is_directory = True`) from rename pair statistics.
- **Aggregate Statistics Cross-Checking:** Evaluators independently verify event-level provenance against `context.stats.rename_pairs_count`. Discrepancies are flagged in metadata (`stats_discrepancy = True`) while relying on verified event truth.
- **Automated Validation:** 7 unit tests in `tests/unit/test_rename_provenance.py`.

### Step 4.7 — Telemetry Health & Root Recovery Hardening
- **No Recovery from Elapsed Time Alone:** An evicted root returning to monitoring does not clear degradation merely because time elapsed while idle. Genuine recovery requires demonstrable **observation continuity** (active stream of $\ge 2$ events covering the window horizon).
- **Watcher & Pipeline Health Precondition:** Eviction degradation cannot recover if the upstream watcher or pipeline is degraded (`is_telemetry_degraded = True`, `uncounted_kernel_loss = True`, or degraded telemetry quality).
- **Zero Active Drops Requirement:** Recovery requires both `active_capacity_dropped_events == 0` and `active_retrograde_dropped_events == 0`.
- **Independent Degradation Tracking:** Every degradation cause is tracked independently in an active reasons registry. Recovering one reason (e.g. driver timeout) preserves others (e.g. capacity drop or eviction loss).
- **Automated Validation:** 4 unit tests in `tests/unit/test_telemetry_recovery_hardening.py`.

### Step 4.8 — Detection Engine Reliability & Edge-Case Validation
- **Boundary Expiration:** Events arriving at exact sub-nanosecond window boundaries ($t \pm 1\text{ns}$) expire deterministically.
- **Benign Workload Distinctions:**
  * Bulk file copying (rapid `CREATED` events) $\rightarrow$ `NO_DETECTION` / `SUSPICIOUS_ACTIVITY`, never `DETECTION`.
  * Software installation (burst writes in single folder) $\rightarrow$ `SUSPICIOUS_ACTIVITY`, never `DETECTION`.
  * Large-scale cleanup (bulk temporary deletions) $\rightarrow$ `SUSPICIOUS_ACTIVITY`, never `DETECTION`.
  * Bulk code refactoring (renames without deletions/bursts) $\rightarrow$ `SUSPICIOUS_ACTIVITY`, never `DETECTION`.
- **Multi-Vector Ransomware Trigger:** Traversal + Burst Writes + Extension Convergence $\rightarrow$ Confirmed `DETECTION` with complete traceability of evidence event UUIDs.
- **Multi-Root Concurrency:** 5 concurrent roots under continuous stress show 0 cross-root data leakage.
- **Automated Validation:** 7 integration tests in `tests/integration/test_detection_reliability_edge_cases.py`.

### Step 4.9 — Algorithmic Performance Optimization
- **O(1) Homogeneous Workload Fast-Paths:** When all events in a window represent uniform file mutations (e.g., 100% write burst or 100% deletion batch), list comprehensions and set allocations are bypassed in O(1) time using precomputed totals and unique path sets.
- **Adaptive Path Sorting:** For window sizes exceeding 200 paths, expensive full string sorting is bypassed in favor of O(n) key retrieval, eliminating CPU bottlenecks during sustained high-event bursts.
- **Precomputed Directory Diversity:** `FS_DIRECTORY_TRAVERSAL` evaluates directory branch diversity directly from precomputed window statistics (`stats.unique_directories`), avoiding full-window event iteration.

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
  - EventNormalizer & RenameCorrelator (explicit provenance tagging)
            |
            v (Normalized FileEvent + EventOrderingMetadata)
[DetectionEngine] (EventConsumer)
            |
            +---> [SlidingWindowCorrelator] (Strict chronological order via bisect)
            |     - Bounded per-root window (5,000 max events)
            |     - O(1) incremental statistics (paths, dirs, exts, verified pairs)
            |     - Recoverable capacity & retrograde drop horizons
            |     - Active observation continuity recovery verification
            |
            +---> [SignalRegistry] (Isolated evaluator execution)
                     |
                     +---> FS_BURST_WRITE (O(1) pre-screened + homogeneous fast-path)
                     +---> FS_RENAME_RATIO (Verified correlation provenance only)
                     +---> FS_DELETE_RATIO (O(1) pre-screened + homogeneous fast-path)
                     +---> FS_DIRECTORY_TRAVERSAL (O(1) pre-screened via window stats)
                     +---> FS_EXTENSION_CONVERGENCE (O(1) pre-screened)
            |
            v
[DetectionResult: NO_DETECTION | SUSPICIOUS_ACTIVITY | DETECTION | INSUFFICIENT_TELEMETRY | EVALUATION_ERROR]
```

---

## 3. Test Suite Verification

### Test Breakdown (323 passed in 9.37s):
- **Phase 1–3 Tests:** 256 passed
- **Phase 4 Detection Contracts:** 8 passed (`tests/unit/test_detection_contracts.py`)
- **Phase 4 Sliding Window:** 14 passed (`tests/unit/test_sliding_window.py`)
- **Phase 4 Rename Correlation Provenance (Step 4.6):** 7 passed (`tests/unit/test_rename_provenance.py`)
- **Phase 4 Telemetry Recovery Hardening (Step 4.7):** 4 passed (`tests/unit/test_telemetry_recovery_hardening.py`)
- **Phase 4 Signal Registry:** 7 passed (`tests/unit/test_signal_registry.py`)
- **Phase 4 Behaviour Signals:** 10 passed (`tests/unit/test_detection_signals.py`)
- **Phase 4 Engine Integration:** 10 passed (`tests/integration/test_detection_engine_integration.py`)
- **Phase 4 Reliability & Edge Cases (Step 4.8):** 7 passed (`tests/integration/test_detection_reliability_edge_cases.py`)

---

## 4. Empirical Performance Benchmarking (Post Step 4.9 Optimization)

Measured on **Windows 11 (AMD64)** running **Python 3.14.4 (CPython)** via `scripts/measure_phase4_performance.py`:

| Workload Scenario | Event Volume & Roots | Baseline Throughput | Optimized Throughput | Baseline Latency | Optimized Latency | Peak Heap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small Load** | 100 events, 1 root | 1,937.6 eps | **2,757.2 eps** | 0.51 ms | **0.36 ms** | **0.077 MB** |
| **Medium Load** | 1,000 events, 1 root | 344.7 eps | **660.2 eps** | 2.90 ms | **1.51 ms** | **0.288 MB** |
| **High Load** | 10,000 events, 1 root | 47.1 eps | **94.9 eps** | 21.22 ms | **10.53 ms** | **2.081 MB** |
| **Concurrent Multi-Root** | 4,000 events, 4 roots | 372.3 eps | **709.8 eps** | 2.68 ms | **1.40 ms** | **0.847 MB** |
| **High-Volume Multi-Root** | 10,000 events, 5 roots | 177.5 eps | **345.0 eps** | 5.63 ms | **2.89 ms** | **1.948 MB** |

### Benchmark Analysis:
- **Throughput Doubled:** Across multi-root workloads, throughput increased from **177.5 eps to 345.0 eps** (+94%) and concurrent multi-root jumped to **709.8 eps** (+90%).
- **Latency Cut in Half:** High-load per-event processing latency was reduced from **21.22 ms down to 10.53 ms** (-50%), with P50 latency at **2.89 ms** under multi-root load.
- **Memory Efficiency:** Peak heap utilization remains under **~2.08 MB** even under sustained 10,000-event stress testing.

---

## 5. Step 4.10: Final Sign-Off & Verification Checklist

| Verification Item | Requirement | Result | Status |
| :--- | :--- | :--- | :--- |
| **Platform Compatibility** | Windows 11 (AMD64), Python >=3.12 | Verified on Windows 11 with Python 3.14.4 | PASSED |
| **Automated Test Suite** | 100% test pass rate across all phases | 323 passed in 9.37s | PASSED |
| **Test Coverage** | >= 90% statement coverage | 93% statement coverage across 3,065 statements | PASSED |
| **Code Hygiene** | Ruff lint & format checks pass cleanly | Zero lint errors, zero format discrepancies | PASSED |
| **Rename Provenance** | Only verified Phase 3 correlated pairs counted | Explicit provenance enforced, directory renames excluded | PASSED |
| **Telemetry Health** | No recovery on elapsed time alone | Active continuity evidence + healthy watcher required | PASSED |
| **Benign Workload Immunity**| Copying/builds/cleanup do not trigger DETECTION | Differentiated via multi-family transformation criteria | PASSED |
| **Deterministic Evidence** | Traceable UUIDs for all detections | All detections provide contributing event IDs | PASSED |
| **Performance Benchmarks** | Repeatable, documented measurements | Verified across 5 load tiers | PASSED |
| **Licensing & Ownership** | GNU GPL v3.0, Atharva Ghag | Verified headers, pyproject.toml, and LICENSE | PASSED |

**Final Phase 4 Verdict: APPROVED & SIGNED OFF.** All requirements for Phase 4 Steps 4.1 through 4.10 are complete and verified. The codebase is fully prepared for Phase 5 (Incident Investigation & UI).
