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

### 6.2 Degradation & Telemetry Loss Recovery (Hardened)
All internal degradation sources feature deterministic, time-bounded recovery policies:
1. **Window Capacity Drops:** Tracked via `_capacity_drop_timestamps: deque[int]`. Once expired relative to the sliding window duration horizon (`cutoff_ns = now_monotonic_ns - window_duration_ns`), the drop records are evicted and telemetry degradation automatically clears.
2. **Retrograde Event Drops:** Tracked via `_retrograde_drop_timestamps: deque[int]`. Expired once their drop timestamps fall outside the active window duration horizon.
3. **Root Eviction Telemetry Loss:** When the correlator reaches capacity (`max_active_roots`), the oldest idle root is evicted and its loss timestamp recorded in `_evicted_roots_loss`. Recovery requires **active observation continuity evidence** (`len(events) >= 2` spanning the observation window duration, or continuous monitoring since reseen with recent events), a **healthy external watcher** (`is_telemetry_degraded = False`, normal quality, no kernel loss), and **zero active drops** in the window. Elapsed time alone without active events never clears degradation.
4. **Independent Reason Tracking:** Each degradation source (watcher buffer overflow, driver timeout, window capacity drop, retrograde drop, root eviction loss) is tracked and evaluated independently. Recovering one reason never accidentally clears another.

---

## 7. Rename Correlation Provenance & Detection Integrity

1. **Explicit Correlation Provenance:** `FileEvent` models generated from Windows two-part rename notifications carry explicit provenance (`correlation_provenance = "rename_correlator:<old>-><new>"`). Unpaired or incomplete rename notifications cannot inflate `FS_RENAME_RATIO`.
2. **Directory Rename Exclusion:** Directory renames (`is_directory = True`) are excluded from file rename pair counts and ratios to prevent administrative folder operations from skewing ransomware detection metrics.
3. **Incremental Statistics Cross-Checking:** `RootSlidingWindow` incrementally tracks verified `rename_pairs_count`. Evaluators independently verify event-level provenance against `context.stats.rename_pairs_count` and flag any discrepancies (`stats_discrepancy = True`) in detection metadata.

---

## 8. Algorithmic Optimizations & Scaling

1. **Pre-Screening Guards:** All five foundational evaluators execute instantaneous O(1) statistical pre-screening checks using precomputed window aggregates (`stats.rename_pairs_count`, `stats.deleted_count`, `stats.unique_directories`, etc.) before evaluating event lists.
2. **Homogeneous Workload Fast-Paths:** When all events in a window represent uniform file mutations (e.g. 100% write burst or 100% deletion batch), list comprehensions and set allocations are bypassed in O(1) time using precomputed totals and unique path sets.
3. **Adaptive Path Sorting:** For window sizes exceeding 200 paths, expensive full string sorting is bypassed in favor of O(n) key retrieval, eliminating CPU bottlenecks during sustained high-event bursts.
4. **Precomputed Directory Diversity:** `FS_DIRECTORY_TRAVERSAL` evaluates directory branch diversity directly from precomputed window statistics (`stats.unique_directories`), avoiding full-window event iteration.

---

## 9. Phase 5: Advanced Behavioural Detection Modules

Phase 5 extends Kuyebiko beyond its five foundational signals by incorporating MITRE ATT&CK-aligned behaviour modules with explicit telemetry capability contracts.

### 9.1 Telemetry Capability Architecture & Boundaries
A fundamental principle of Kuyebiko's advanced detection is separating **what can be observed** from **what the engine attempts to detect**:
- `TelemetryCapability.FILESYSTEM_METADATA`: Standard Windows change notifications (`ReadDirectoryChangesW`).
- `TelemetryCapability.PROCESS_EXECUTION`: Process creation and command-line execution (e.g., `vssadmin`, `wbadmin`, `wevtutil`).
- `TelemetryCapability.EVENT_LOG`: Windows Event Log channels (e.g., Security Event ID 1102 / System Event ID 104).
- `TelemetryCapability.FILESYSTEM_READ_ACCESS`: File read operations and directory enumeration (requires filter driver or dedicated read tracing).

**Explicit Capability Enforcement:** If an advanced signal requires capabilities not available in the current environment or context, the evaluator automatically returns `triggered = False`, `severity = 0.0`, and records explicit `capability_limitation` metadata. Missing telemetry never fabricates a false detection or false safety claim.

### 9.2 Advanced Evaluator Modules (Steps 5.2 – 5.5)
1. **`FS_RECOVERY_INHIBITION` (MITRE ATT&CK T1490):**
   - Family: `SignalFamily.RECOVERY_INTERFERENCE`.
   - Filesystem observables: Deletion or destructive modification of recovery images, VSS shadow copy storage, backup catalogs (`.vhd`, `.vhdx`, `.bkf`, `.wbcat`, `System Volume Information`, `WindowsImageBackup`).
   - Extended observables: Correlates command-line executions (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set ... recoveryenabled no`).
   - Capability boundary: If process telemetry is absent, records explicit limitation while reliably inspecting recovery filesystem paths.
2. **`FS_DATA_DESTRUCTION` (MITRE ATT&CK T1485):**
   - Family: `SignalFamily.DATA_DESTRUCTION`.
   - Distinct from `FS_DELETE_RATIO`: Requires substantial deletion volume across multiple distinct directory branches (`unique_directories >= 3`).
   - Benign cleanup isolation: Mass deletions strictly confined to temporary or build directories (`temp`, `tmp`, `node_modules`, `target`, `build`, `.cache`) are recognized as benign cleanups and do not trigger destructive alarms.
3. **`FS_FILESYSTEM_DISCOVERY` (MITRE ATT&CK T1083):**
   - Family: `SignalFamily.FILESYSTEM_DISCOVERY`.
   - Strictly declares `FILESYSTEM_READ_ACCESS` capability requirement.
   - Change notifications (`ReadDirectoryChangesW`) cannot observe directory enumeration; when operating without dedicated read-access telemetry, the evaluator documents this capability limitation.
   - When read-access telemetry is provided, detects high-velocity enumeration across directories while recognizing benign indexers (`SearchIndexer.exe`, `explorer.exe`).
4. **`FS_INDICATOR_REMOVAL` (MITRE ATT&CK T1070):**
   - Family: `SignalFamily.INDICATOR_REMOVAL`.
   - Detects direct deletion of primary event logs (`winevt/Logs/Security.evtx`, `System.evtx`), NTFS USN journals (`$LogFile`, `$UsnJrnl`), or local forensic databases (`kuyebiko.db`).
   - Correlates with event log clearing records (Event 1102 / 104) and process commands (`wevtutil cl`).
   - Distinguishes standard archival log rotation (`Archive-*.evtx`) from hostile indicator tampering.


