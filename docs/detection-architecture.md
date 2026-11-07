# Detection Architecture & Contracts — Kuyebiko Phase 4

## 1. Subsystem Purpose & Responsibilities

The Kuyebiko Behaviour Detection Engine evaluates streams of validated, normalized filesystem events (`FileEvent`) to identify behavioural indicators characteristic of ransomware operations without inspecting file contents, executing live malware, or interfering destructively with the operating system.

It bridges the Phase 3 event processing pipeline to higher-level threat analysis and incident management.

```
+-----------------------------------------------------------------------------------+
|                        Phase 3 Event Processing Pipeline                         |
|   WindowsDirectoryWatcher -> Ingestor -> BoundedQueue -> Worker -> FileEvent      |
+-----------------------------------------------------------------------------------+
                                          |
                                          v (Normalized FileEvent + EventOrderingMetadata)
+-----------------------------------------------------------------------------------+
|                       Phase 4 Behaviour Detection Engine                          |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | Sliding-Window Event Correlator (Isolated per Monitored Root)             |   |
|   | - Chronological event buffering (Monotonic timestamp deltas)              |   |
|   | - Incremental aggregate counters (O(1) path/extension/type updates)       |   |
|   | - Bounded root capacity & automatic TTL expiration                         |   |
|   +---------------------------------------------------------------------------+   |
|                                         |                                         |
|                                         v (DetectionContext)                      |
|   +---------------------------------------------------------------------------+   |
|   | Signal Registry & Evaluation Coordinator                                  |   |
|   | - Isolated synchronous evaluation across registered SignalEvaluators      |   |
|   | - Per-evaluator exception isolation & execution failure tracking          |   |
|   | - Multi-factor family correlation without duplicate evidence counting     |   |
|   +---------------------------------------------------------------------------+   |
|                                         |                                         |
|                                         v (SignalResult / DetectionResult)        |
|   +---------------------------------------------------------------------------+   |
|   | Behavioural Signals (Foundational MVP)                                    |   |
|   | 1. FS_BURST_WRITE (High modification frequency / unique paths)            |   |
|   | 2. FS_RENAME_RATIO (Elevated rename activity & correlated pairs)          |   |
|   | 3. FS_DELETE_RATIO (Elevated file removal & directory pruning)            |   |
|   | 4. FS_DIRECTORY_TRAVERSAL (Broad cross-directory spreading)               |   |
|   | 5. FS_EXTENSION_CONVERGENCE (Targeted extension changes / homogenization)  |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                         Phase 4.6+ Incident Generation                            |
|                 (SecurityIncident persistence & timeline linkage)                 |
+-----------------------------------------------------------------------------------+
```

---

## 2. Detection Interfaces & Contracts

### 2.1 `SignalEvaluator` Protocol
Every behaviour detector implements the `SignalEvaluator` protocol:
- **`signal_id: str`**: Unique machine identifier (e.g., `"FS_BURST_WRITE"`).
- **`name: str`**: Human-readable name.
- **`family: SignalFamily`**: Broad behavioural category for multi-factor correlation.
- **`threshold: float`**: Configurable activation threshold.
- **`is_enabled: bool`**: Active status flag.
- **`evaluate(context: DetectionContext) -> SignalResult`**: Pure, side-effect-free evaluation.

### 2.2 `DetectionContext`
Encapsulates all evaluation telemetry for a specific monitored root:
- `root_id`: Monitored root identifier.
- `events`: Ordered list of events falling within the active correlation window.
- `stats`: `WindowAggregateStats` providing precomputed counts, unique paths, directories, extensions, and frequencies.
- `window_start_utc` & `window_end_utc`: Boundary timestamps.
- `evaluated_monotonic_ns`: Monotonic clock value ensuring drift-free calculations.
- `is_telemetry_degraded`: Propagated from collector and pipeline drops (e.g. Windows buffer overflow or queue drops).
- `config`: Operational parameters and threshold overrides.

### 2.3 `SignalResult`
Returned by each evaluator:
- `signal_id`, `signal_name`, `family`.
- `triggered: bool`: True if the observed metric crosses the threshold.
- `severity_score: float` (0.0 to 1.0): Normalized contribution.
- `observed_metric: float` & `threshold: float`: Numeric evidence.
- `explanation: str`: Human-readable justification of the determination.
- `evidence_event_ids: list[str]`: Precise UUIDs of the contributing `FileEvent` records.
- `metadata: dict`: Extra diagnostic breakdown.

---

## 3. Signal Families

To prevent double-counting collinear metrics (e.g., counting high write count, high write rate, and multiple modified files as three independent proof vectors), signals are classified into distinct families:

1. **`FILESYSTEM_ACTIVITY`**: Raw operation frequency, burst writes, bulk modifications.
2. **`RENAME_DELETION`**: Mass renaming, destructive file replacement, directory pruning.
3. **`DIRECTORY_TRAVERSAL`**: Rapid lateral directory depth traversal, branch spreading.
4. **`FILE_TRANSFORMATION`**: Extension changes, extension convergence, entropy shifts.
5. **`RECOVERY_INTERFERENCE`**: Shadow copy tampering, backup deletion attempts (future ETW/process).
6. **`CANARY_INTERACTION`**: Decoy file modification, deletion, or renaming.
7. **`PROCESS_ATTRIBUTION`**: Suspicious executable provenance, untrusted process contexts.

---

## 4. Detection Outcomes

Evaluation cycles yield structured `DetectionOutcome` values:
- **`NO_DETECTION`**: Activity within normal operational thresholds.
- **`SUSPICIOUS_ACTIVITY`**: Isolated signals triggered, requiring continuous observation.
- **`DETECTION`**: Multi-factor behavioural confirmation exceeding composite risk thresholds.
- **`INSUFFICIENT_TELEMETRY`**: Event volume or window history insufficient for confidence.
- **`EVALUATION_ERROR`**: Critical evaluator failure during processing.

---

## 5. Security & Resource Boundaries

1. **No Content Inspection:** The detection engine only processes normalized metadata (`FileEvent`). No file reads, content hashing, or inspection is performed.
2. **Platform Independence:** Core detection algorithms execute purely in Python memory without Windows API bindings (`ctypes` or Win32 calls).
3. **Strict Memory Bounds:** Sliding windows maintain a hard cap on retained events (`max_events_per_root`) and automatically prune aged events using monotonic clocks.
4. **Deterministic & Explainable:** Every trigger provides specific event IDs, measured ratios, and concrete thresholds.

---

## 6. Sliding-Window Mechanics & Complexity Profiles

### 6.1 Insertion Complexity
- **Fast Path (Amortized O(1)):** Under standard chronological event arrival, events and their monotonic timestamps are appended directly to `_events` and a parallel `_timestamps: list[int]` array.
- **Out-of-Order Worst Case (O(n)):** For rare out-of-order events arriving within the active window horizon, the insertion index is located via O(log n) binary search (`bisect_right`) over the pre-maintained `_timestamps` array, followed by an O(n) element shift to insert the event. This avoids intermediate list allocations while maintaining strictly sorted chronological order.
- **Retrograde Event Handling:** Events whose timestamps are older than the active window duration (`clock_ns - monotonic_ns > window_duration_ns`) are dropped. Their occurrence is tracked via a timestamped deque (`_retrograde_drop_timestamps`) and immediately degrades `DetectionContext` telemetry (`is_telemetry_degraded = True`, reason: `retrograde_events_dropped:N`).

### 6.2 Degradation & Telemetry Loss Recovery
All internal degradation sources feature deterministic, time-bounded recovery policies:
1. **Window Capacity Drops:** Tracked via `_capacity_drop_timestamps: deque[int]`. Once expired relative to the sliding window duration horizon (`cutoff_ns = now_monotonic_ns - window_duration_ns`), the drop records are evicted and telemetry degradation automatically clears.
2. **Retrograde Event Drops:** Tracked via `_retrograde_drop_timestamps: deque[int]`. Expired once their drop timestamps fall outside the active window duration horizon.
3. **Root Eviction Telemetry Loss:** When the correlator reaches capacity (`max_active_roots`), the oldest idle root is evicted and its loss timestamp recorded in `_evicted_roots_loss`. When the evicted root returns, it is initially flagged as degraded until a full, continuous observation window (duration >= `window_duration_seconds`) has been re-established without further active drops, at which point the eviction loss record is removed and normal telemetry status is restored.

