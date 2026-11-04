# Kuyebiko — Detection Benchmark and Validation Methodology

## 1. Purpose & Core Evaluation Philosophy

In cybersecurity and endpoint behavioural detection, subjective demonstrations and curated product videos often present a misleading illusion of efficacy. A detector tuned specifically to alert on a single rapid rename script will look flawless in a recorded demo, yet flood users with intolerable false alarms during a standard software build or photo import.

**Kuyebiko establishes a scientific, empirical validation methodology.** Detection capabilities must be objectively measured, quantitatively verified, and evaluated against both positive attack simulations and complex, benign everyday workloads.

### Safety-First Evaluation
- **No Live Ransomware Payloads:** Under no circumstances is live, weaponized, or executable ransomware required or recommended to validate Kuyebiko. Real malware presents unacceptable risks of data loss, collateral infection, and infrastructure compromise.
- **Harmless Synthetic Emulation:** All positive evaluation is conducted via deterministic event trace replays (JSONL fixtures), safe in-memory event generators, or strictly sandboxed behavioural emulators operating within disposable test roots.

---

## 2. Evaluation Categories & Metrics

To thoroughly assess the detector, Kuyebiko evaluates eight core performance dimensions:

| Evaluation Dimension | Primary Metric | Operational Objective |
| :--- | :--- | :--- |
| **Detection Recall** | Sensitivity ($\ge 90\%$ proposed target) | Ensure true ransomware-like behaviours are consistently flagged. |
| **Detection Precision** | Positive Predictive Value ($\ge 90\%$ proposed target) | Ensure High and Critical alerts correspond to genuinely malicious activity. |
| **False-Positive Rate** | False alarms per benign unit time ($\le 1$ per 24 endpoint-hours) | Prevent user alert fatigue during intensive normal computing. |
| **Detection Latency** | Elapsed time to alert ($p95 \le 10$ seconds) | Provide rapid situational awareness before damage spreads. |
| **Telemetry Completeness** | Ingestion capture rate ($\ge 99\%$ in harness) | Minimize dropped notifications across collection buffers and queues. |
| **Event Traceability** | Evidence reference rate ($100\%$ incident linkage) | Guarantee every incident links directly to raw `FileEvent` IDs. |
| **Resource Overhead** | CPU $<2\%$ idle; RAM $<250$ MB total | Maintain lightweight, non-intrusive local execution. |
| **Application Stability** | Zero unhandled crashes during stress | Ensure continuous monitoring during extreme I/O storms and faults. |

---

## 3. Mathematical Definitions & Limitations

### 3.1 Standard Formulations

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$

$$\text{Recall (Sensitivity)} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$

$$\text{False Positive Rate (FPR)} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

Where:
- **True Positive (TP):** An anomalous scenario containing ransomware-like behavioural sequences correctly generates an incident at or above the expected severity band.
- **False Positive (FP):** A known benign workload scenario triggers an alert at or above High or Critical severity.
- **False Negative (FN):** An anomalous scenario containing qualifying ransomware behaviour fails to reach the required severity threshold or is missed entirely.
- **True Negative (TN):** A benign workload completes without triggering High or Critical alerts.

### 3.2 Operational Alert Rate Formulation
In continuous endpoint monitoring, defining a discrete "Negative" transaction is ambiguous because events stream continuously. Therefore, false positives are primarily measured as an operational rate:

$$\text{Alert Rate}_{\text{benign}} = \frac{\sum \text{False High/Critical Incidents}}{\text{Total Benign Endpoint-Hours Observed}}$$

### 3.3 Metric Nuances and Limitations
- **High Recall vs. High Precision Trade-off:** Tuning thresholds to catch slow, low-volume encryption inevitably increases false alarms during benign batch operations.
- **Severity Mismatch Accounting:** If a positive scenario expected to reach `Critical` only reaches `Low`, it is recorded as a sub-threshold degradation and flagged in benchmark reports.

---

## 4. Test Datasets & Corpus Plan

The validation corpus is divided into five distinct scenario families:

```
┌────────────────────────────────────────────────────────┐
│               Kuyebiko Validation Corpus               │
├────────────────────────────┬───────────────────────────┤
│ 1. Synthetic Positive      │ - Rapid burst encryption  │
│    Traces (JSONL)          │ - In-place rewrites       │
│                            │ - Mass file renames       │
├────────────────────────────┼───────────────────────────┤
│ 2. Safe Behavioral         │ - Disposable test root    │
│    Simulation              │ - Path-jailed dummy files │
│                            │ - Reversible operations   │
├────────────────────────────┼───────────────────────────┤
│ 3. Atomic Red Team         │ - Safe T1486 emulations   │
│    (Isolated Subsets)      │ - Safe T1490 emulations   │
├────────────────────────────┼───────────────────────────┤
│ 4. Benign Workload         │ - Software compiles       │
│    Traces                  │ - Photo imports / Sync    │
│                            │ - Archive extractions     │
├────────────────────────────┼───────────────────────────┤
│ 5. Telemetry Fault         │ - Queue saturation        │
│    Injections              │ - Buffer overruns         │
│                            │ - Collector restarts      │
└────────────────────────────┴───────────────────────────┘
```

1. **Harmless Synthetic Filesystem Event Traces:** JSONL recordings representing normalized `FileEvent` sequences. Replayed directly into the ingestion engine to evaluate detection algorithms with zero disk I/O.
2. **Benign Workload Traces:** Real-world recordings of developer workstations, office productivity suites, and media creation tools executing intensive file operations.
3. **Controlled Behaviour Simulator:** A specialized, built-in application module that creates disposable directories beneath an isolated test root, performs bounded file manipulations (creates, renames, dummy content modifications), and cleans up after itself.
4. **Selected Atomic Red Team Tests:** Highly vetted, safe test fixtures derived from MITRE ATT&CK techniques (such as T1486 and T1490) executing only in isolated virtual machines.
5. **Held-Out Validation Datasets:** A reserved set of 20% of synthetic and benign traces that are never used during threshold calibration or feature development, ensuring unbiased evaluation.

---

## 5. Benign Workload Scenarios

To ensure Kuyebiko does not impede legitimate system activity, the benchmark suite evaluates the following standard computing workloads:

| Benign Workload | Characteristics & File Dynamics | Expected Behaviour |
| :--- | :--- | :--- |
| **Software Development Builds** | High-volume read/writes, temporary object creation (`.o`, `.pyc`, target folders) via Cargo, npm, or GCC. | Max severity $\le \text{Low}$. Handled via path filtering and multi-family gating. |
| **Git Operations** | Rapid checking out of thousands of files across deep directory trees during branch switching. | Max severity $\le \text{Informational}$. No extension convergence or abnormal renames. |
| **Archive Extraction** | Extracting deep `.zip` or `.tar.gz` files containing thousands of files. | Burst detected, but lack of rename/deletion or canary triggers prevents High alert. |
| **Bulk File Renaming** | Renaming hundreds of vacation photos using a batch renaming utility. | Rename ratio elevated, but file contents remain intact and extensions remain standard. |
| **Photo / Media Import** | Copying hundreds of RAW image files from an external drive to local folders. | Pure create/write burst; no rename convergence or destructive deletions. |
| **Cloud Storage Sync** | Initial sync or local cache population of OneDrive or Dropbox folders. | Sustained write activity; process attribution (if available) confirms signed sync binary. |
| **Database Transactions** | Intensive SQLite or local database updates with active WAL checkpoints. | High in-place modification on isolated `.db` and `.db-wal` files; does not affect diverse folders. |
| **Document Compilation** | Heavy LaTeX or PDF generation creating and deleting temporary aux files. | Bounded to single directory; does not meet diversity thresholds. |

---

## 6. Adversarial and Edge-Case Scenarios

The benchmark suite explicitly stresses the engine against challenging evasion and failure conditions:

1. **Intermittent Modification Cycles:** Simulating ransomware that encrypts 10 files, sleeps for 30 seconds, and repeats across several hours.
2. **Low-and-Slow Traversal:** Modifying a single document every 15 minutes to stay beneath burst thresholds, testing the `SIG-10` temporal persistence engine.
3. **In-Place Cryptographic Rewriting:** Modifying file contents while leaving paths, filenames, and extensions identical, testing `SIG-09` and opt-in `SIG-05`.
4. **Mass Destructive Wiping:** Simulating wiper malware that executes rapid unlinked file deletions without encryption.
5. **Event Queue Saturation Storm:** Injecting 500,000 raw events within 2 seconds to verify queue backpressure, drop counting, and immediate `DEGRADED` health state activation.
6. **Filesystem Buffer Overrun:** Simulating Windows kernel buffer overflow errors to verify that the agent gracefully transitions to degraded mode and attempts reconciliation.
7. **Service Interruption & Restart:** Killing the collector thread during an active event stream to verify that the unobserved time window is recorded as a permanent monitoring gap.
8. **Missing Process Attribution:** Evaluating detection accuracy when process context is completely `Unavailable` or `Unknown`, verifying that score calculations are not suppressed.

---

## 7. Proposed Acceptance Targets

The following figures represent **proposed engineering baseline targets** for Phase 5 validation. They are target goals for release qualification, **not** achieved empirical results:

| Acceptance Metric | Proposed Release Target | Evaluation Context & Scope |
| :--- | :---: | :--- |
| **Overall Detection Recall** | $\ge 90\%$ | Across all declared high-confidence synthetic positive scenarios. |
| **High/Critical Alert Precision** | $\ge 90\%$ | Across the combined evaluation corpus on reference hardware. |
| **False Alert Frequency** | $\le 1$ per 24 endpoint-hours | Measured across the standardized benign workload mix. |
| **Alert Latency** | $p95 \le 10\text{ seconds}$ | Measured from the close of the qualifying sliding window. |
| **Telemetry Completeness** | $\ge 99\%$ | In non-fault test harness runs on Windows 11 reference hardware. |
| **Evidence Traceability** | $100\%$ | Every generated incident must link directly to valid `FileEvent` IDs. |
| **Idle System Impact** | Average CPU $< 2\%$ | Measured over 10 minutes of idle system observation. |
| **Memory Footprint** | Combined RAM $< 250\text{ MB}$ | Background service plus desktop UI after stabilization. |

---

## 8. Benchmark Reporting Schema

Every benchmark run must generate a standardized, machine-readable validation report (JSON) accompanied by a Markdown summary.

```json
{
  "report_version": "1.0",
  "benchmark_timestamp_utc": "2026-11-04T12:00:00Z",
  "environment": {
    "os": "Microsoft Windows 11 Pro 64-bit (Build 22631)",
    "python_version": "3.14.4",
    "cpu": "AMD Ryzen 7 5800H",
    "ram_total_mb": 16384,
    "disk_type": "NVMe SSD"
  },
  "kuyebiko_build": {
    "version": "0.1.0",
    "git_commit": "abcdef1234567890",
    "detection_model_version": "2.0-baseline"
  },
  "dataset": {
    "corpus_name": "kuyebiko-validation-corpus-v1",
    "fixture_seed": 42,
    "total_scenarios": 120,
    "positive_scenarios": 60,
    "benign_scenarios": 60
  },
  "results": {
    "true_positives": 56,
    "false_positives": 2,
    "false_negatives": 4,
    "true_negatives": 58,
    "calculated_recall": 0.933,
    "calculated_precision": 0.965,
    "false_alerts_per_24h": 0.8,
    "latency_p50_ms": 1250,
    "latency_p95_ms": 4800,
    "telemetry_completeness_pct": 99.8,
    "cpu_idle_avg_pct": 0.8,
    "ram_idle_mb": 142.5
  },
  "unimplemented_or_failed_scenarios": [
    "SCEN-042: Ultra-slow encryption (1 file/hour) remained below threshold",
    "SCEN-089: Deep nested symlink traversal caused transient delay"
  ]
}
```

---

## 9. Reproducibility & Governance

To ensure scientific integrity and prevent biased results:

1. **Version-Locked Fixtures:** All test event traces are checked into version control under `tests/fixtures/` with deterministic timestamps, monotonic counters, and relative paths.
2. **Deterministic Seed Control:** Synthetic event generators use fixed pseudo-random seeds. A test run with seed `42` must yield bit-identical event streams across independent machines.
3. **No Threshold Tuning on Evaluation Data:** Detection thresholds and signal weights may only be tuned against the development set. The held-out evaluation set is run once during release qualification.
4. **Public Limitation Disclosure:** Any scenario where Kuyebiko fails to reach its target severity or produces a false positive must be documented in the public benchmark report as a declared limitation.
