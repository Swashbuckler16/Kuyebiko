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

## 7. Rename Correlation Provenance & Cryptographic Trust Boundary

1. **Cryptographic Provenance Token:** `FileEvent` models generated from Windows two-part rename notifications carry explicit, authenticated provenance (`correlation_provenance = "<type>:<old>-><new>#<hmac_sha256>"`). Unsigned, tampered, or fabricated provenance strings are rejected by constant-time signature verification (`verify_provenance_signature`).
2. **Untrusted Input Isolation:** Unpaired or explicit caller-supplied rename pairs (`explicit_pair:...`) cannot claim or forge correlator provenance, preventing untrusted callers from inflating `FS_RENAME_RATIO`.
3. **Directory Rename Exclusion:** Directory renames (`is_directory = True`) are excluded from file rename pair counts and ratios to prevent administrative folder operations from skewing ransomware detection metrics.
4. **Incremental Statistics Cross-Checking:** `RootSlidingWindow` incrementally tracks verified `rename_pairs_count`. Evaluators independently verify event-level provenance against `context.stats.rename_pairs_count` and flag any discrepancies (`stats_discrepancy = True`) in detection metadata.

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

**Capability Contracts & Scoping:**
1. **Mandatory vs. Optional Capabilities:** `SignalMetadata` explicitly distinguishes `required_capabilities` (mandatory gates without which evaluation cannot execute) from `optional_capabilities` (corroborating sources like process execution or event logs). Missing optional capabilities never fail the evaluation; instead, the evaluator records unmonitored capability state.
2. **Auxiliary Telemetry Scoping:** Evaluators strictly scope auxiliary telemetry (`ProcessTelemetryEvent`, `EventLogTelemetryEvent`, `DiscoveryTelemetryEvent`) using `scope_auxiliary_telemetry()`, rejecting events matching foreign `root_id`s or outside the sliding correlation window horizon.
3. **Explicit Evidence vs. Limitation:** Telemetry state is explicitly classified into `evidence_observed`, `clean` (monitored with zero adverse activity), and `unavailable` (unmonitored), preventing confidence inflation when optional corroboration is absent.

### 9.2 Advanced Evaluator Modules (Steps 5.2 – 5.5)
1. **`FS_RECOVERY_INHIBITION` (MITRE ATT&CK T1490):**
   - Family: `SignalFamily.RECOVERY_INTERFERENCE`.
   - Strong vs. Weak Indicators: Separates strong recovery indicators (VSS shadow storage, `WindowsImageBackup`, `System Volume Information`, `.bkf`, `.wbcat`, and process commands like `vssadmin delete shadows`) from weak indicators (`$Recycle.Bin`, routine `.vhd` modifications).
   - Weak Indicator Protection: Weak indicators cannot independently trigger `FS_RECOVERY_INHIBITION`, preventing routine recycle bin clearing or virtual disk operations from raising false alarms.
   - Capability boundary: If process telemetry is absent, records explicit limitation while reliably inspecting strong filesystem recovery paths.
2. **`FS_DATA_DESTRUCTION` (MITRE ATT&CK T1485):**
   - Family: `SignalFamily.DATA_DESTRUCTION`.
   - Contextual Discounting: Avoids unconditional vetoes based on directory naming. While single-folder or modest deletions (< 45 files or < 5 subdirs) in `temp`/`cache` are discounted as benign cleanups, massive deletion bursts (>= 45 files across >= 5 subdirectories) are detected even within cache trees.
   - Mixed Workload Protection: Deletions in user document directories are evaluated independently and cannot be masked or suppressed by concurrent cache directory deletions.
3. **`FS_FILESYSTEM_DISCOVERY` (MITRE ATT&CK T1083):**
   - Family: `SignalFamily.FILESYSTEM_DISCOVERY`.
   - Strictly declares `FILESYSTEM_READ_ACCESS` capability requirement.
   - Granular Process Attribution: Evaluates enumeration rates and directory diversity per individual process. A high-volume benign indexing process (`SearchIndexer.exe`, `explorer.exe`) cannot mask concurrent rapid enumeration conducted by an unauthorized process (`cmd.exe`, `powershell.exe`).
4. **`FS_INDICATOR_REMOVAL` (MITRE ATT&CK T1070):**
   - Family: `SignalFamily.INDICATOR_REMOVAL`.
   - Detects direct deletion of primary event logs (`winevt/Logs/Security.evtx`, `System.evtx`), NTFS USN journals (`$LogFile`, `$UsnJrnl`), or local forensic databases (`kuyebiko.db`).
   - Correlates with event log clearing records (Event 1102 / 104) and process commands (`wevtutil cl`).
   - Enforces capability gating and window scoping on event log and process events.

### 9.3 Multi-Horizon Observation Windows (Step 5.6)
To detect stealthy ransomware strains that deliberately throttle activity to evade short sliding windows, Kuyebiko incorporates multi-tiered observation horizons:
- **Short Horizon (10s, 2,000 events):** Captures high-frequency mutations and burst patterns.
- **Medium Horizon (60s, 5,000 events):** Observes distributed modifications and low-and-slow campaigns.
- **Long Horizon (300s, 10,000 events):** Preserves macro-trend behavioral persistence across extended intervals.

**Architectural Guarantees:**
1. **Per-Root Isolation:** Multi-horizon windows (`RootMultiHorizonWindow`) isolate observation state per monitored root.
2. **Unified Degradation Propagation:** Telemetry degradation (capacity drops, retrograde drops, upstream loss) in *any* horizon propagates immediately to the primary detection context, preventing long horizons from concealing observation degradation.
3. **Bounded Memory & O(1) Access:** Sub-windows maintain monotonic timestamps and incremental aggregates without unbounded event retention or scanning.

### 9.4 Low-and-Slow & In-Place Transformation Signals (Step 5.6)
1. **`FS_IN_PLACE_TRANSFORMATION` (MITRE ATT&CK T1486):**
   - Family: `SignalFamily.FILE_TRANSFORMATION`.
   - Detects systematic modification of >= 15 distinct files across >= 3 directory branches without rename operations or extension changes (`rename_ratio <= 15%`).
   - Contextual discounting distinguishes single-file editor saves and localized scratch directory builds from genuine multi-directory overwrites.
   - Observational integrity: strictly evaluates filesystem metadata without claiming content or entropy inspection.
2. **`FS_LOW_AND_SLOW_ACTIVITY` (MITRE ATT&CK T1486):**
   - Family: `SignalFamily.FILE_TRANSFORMATION`.
   - Evaluates persistence across medium/long horizons (>= 15s time span) at throttled event rates (<= 6 ops/sec) spanning multiple directories.
   - Fills the detection gap where high-frequency burst detectors (`FS_BURST_WRITE`) intentionally refrain from alerting.

### 9.5 Benign Workload Discrimination Framework
Validated against a structured 10-scenario workload corpus:
1. Normal document editing (frequent saves to active file) -> Non-triggering.
2. Software installation (binary creation burst in Program Files) -> Non-triggering.
3. Git checkout / branch switching (.git objects) -> Non-triggering.
4. Dev build operations (build/ and target/ scratch artifacts) -> Non-triggering.
5. Database WAL writes (kuyebiko.db-wal periodic writes) -> Non-triggering.
6. Backup / synchronization destination writing -> Non-triggering.
7. Bulk file copying into destination directory -> Non-triggering.
8. Repeated file edits (30 edits to single file) -> Non-triggering.
9. Synthetic low-frequency multi-directory transformation -> Confirmed detection (`FS_LOW_AND_SLOW_ACTIVITY`).
10. Synthetic in-place transformation across 5 directories -> Confirmed detection (`FS_IN_PLACE_TRANSFORMATION`).

### 9.6 Advanced Multi-Signal Correlation & Explainability Engine (Step 5.7 & 5.8)
The behavioural correlation layer (`src/kuyebiko/detection/correlation/`) synthesizes individual signal results into deterministic detection outcomes while eliminating collinear evidence inflation.

1. **`SignalRelationshipModel`:**
   - Categorizes signals into broad behavioral scopes: `TRANSFORMATION`, `DESTRUCTION`, `DEFENSE_EVASION`, `DISCOVERY`, `ACTIVITY_VOLUME`, and `TRAVERSAL`.
   - Identifies overlapping pairs (e.g. `FS_DELETE_RATIO` and `FS_DATA_DESTRUCTION`; `FS_BURST_WRITE` and `FS_IN_PLACE_TRANSFORMATION`).
   - Prevents treating two collinear manifestations of the same underlying event stream as independent corroboration.
2. **`DeduplicatedEvidence`:**
   - Event-level deduplication tracking unique vs shared event UUIDs.
   - Computes a pairwise signal overlap matrix and evidence completeness ratio.
3. **Deterministic Metric Separation:**
   - **Severity Score (0.0–1.0):** Upper-bound damage potential across triggered signals with corroboration boost.
   - **Confidence Score (0.0–1.0):** Certainty metric derived from independent families, discounted by evidence overlap and telemetry degradation.
   - **Telemetry Coverage (0.0–1.0):** Ratio of active required capabilities vs unavailable sources.
   - **Evidence Completeness (0.0–1.0):** Proportion of triggered signals providing contributing event IDs.
4. **`ExplainabilityEngine`:**
   - Generates structured markdown summaries documenting the classification rationale, contributing signals, independent families, overlapping pairs, and known uncertainties.



