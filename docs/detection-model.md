# Kuyebiko — Behavioural Detection Model

## 1. Detection Philosophy

Traditional antivirus and endpoint detection mechanisms often rely heavily on static file signatures, known hash registries, or static extension blacklists. While necessary as a first line of defence, signature-based approaches exhibit critical weaknesses against modern ransomware:

- **Polymorphism and Obfuscation:** Modern ransomware families employ dynamic packing, crypters, and custom compilers, producing unique binary hashes for every infection instance.
- **Novel and Custom Extensions:** Attackers constantly generate arbitrary extensions (or randomize them per machine), rendering static extension lists obsolete.
- **Living-off-the-Land (LotL):** Ransomware increasingly abuses legitimate scripting interpreters (PowerShell, WMI, Python) or native administrative tools, where binary signatures indicate trusted software.

### The Behavioural Approach
Kuyebiko is architected around **behavioural sequence correlation**. Ransomware fundamentally reveals itself through its operational patterns on the filesystem: modifying numerous files across disparate directories in rapid succession, replacing diverse extensions with uniform extensions, altering file contents to high-entropy ciphertext, or attempting to suppress local recovery mechanisms.

However, filesystem signals are rarely definitive in isolation:
- High-volume writes occur during software compilation and database migrations.
- Mass renames occur during photo library management.
- High entropy is native to compressed archives, encrypted zip files, and media containers.

Therefore, Kuyebiko rejects single-metric alerting. Instead, it aggregates multiple **independent behavioural signal families** across rolling temporal windows, combines their evidence into an explainable normalized score, and explicitly measures confidence based on the health and completeness of available telemetry.

> **Implementation Notice:** The detection signals and scoring algorithms described in this document represent the planned detection architecture. In the current Phase 1 foundation, domain schemas (`FileEvent`, `SecurityIncident`, `TelemetrySnapshot`) are fully implemented and validated to support these models.

---

## 2. Planned Detection Signals

Kuyebiko defines 10 core behavioural signals grouped into independent families.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Kuyebiko Signal Family Matrix                        │
├────────────────────────────────┬───────────────────────────────────────┤
│ Filesystem Activity Dynamics   │ SIG-01: Modification Burst            │
│                                │ SIG-02: Rename/Delete Ratio           │
│                                │ SIG-03: File Diversity                │
│                                │ SIG-04: Extension Anomaly             │
│                                │ SIG-09: In-Place Modification Pattern │
│                                │ SIG-10: Temporal Persistence          │
├────────────────────────────────┼───────────────────────────────────────┤
│ Content & Structural Analysis  │ SIG-05: Entropy Delta (Opt-in)        │
│                                │ SIG-06: Canary Sentinel Interaction   │
├────────────────────────────────┼───────────────────────────────────────┤
│ Contextual OS Telemetry        │ SIG-07: Process Context & Attribution │
│                                │ SIG-08: Recovery Interference (T1490) │
└────────────────────────────────┴───────────────────────────────────────┘
```

### SIG-01: Modification Burst
- **What it observes:** The rate of distinct file write and modification notifications within a rolling time window (e.g., distinct files modified per 5-second interval).
- **Why it matters:** Ransomware typically attempts to maximize file damage before user discovery by writing to files as rapidly as disk I/O allows.
- **Ransomware indicator:** A sudden spike in write volume affecting dozens or hundreds of files within a brief temporal window.
- **Benign explanations:** Software builds (compiling C/Rust/Go projects), unpacking large zip archives, git branch switching, local database bulk updates.
- **Limitations:** Does not detect slow, throttled encryption; cannot differentiate legitimate high-throughput batch scripts without corroborating signals.

### SIG-02: Rename/Delete Ratio
- **What it observes:** The proportion of rename and deletion operations relative to total filesystem modifications within the active window.
- **Why it matters:** Many ransomware variants write encrypted content to temporary files and rename them over original files, or delete original files immediately after encrypting copies.
- **Ransomware indicator:** Abnormally elevated ratios of renames or unlinked deletes coinciding with high write activity.
- **Benign explanations:** Package managers updating dependencies, temporary file cleanup scripts, sync utilities reconciliations.
- **Limitations:** Ineffective against ransomware that encrypts files strictly in-place without altering filenames or deleting originals.

### SIG-03: File Diversity
- **What it observes:** The breadth of file types (extensions) and directory depths affected during the evaluation window.
- **Why it matters:** Legitimate user applications typically modify files within a specific project folder or belonging to a single application type (e.g., photo editor touching `.jpg`). Ransomware traverses all accessible user folders indiscriminately targeting documents, spreadsheets, images, and archives.
- **Ransomware indicator:** Broad traversal across multiple directory hierarchies touching heterogeneous file categories simultaneously.
- **Benign explanations:** Full-system backup software, local cloud synchronization clients (OneDrive/Dropbox syncing newly added folders), anti-malware full scans.
- **Limitations:** Targeted attacks focusing only on specific databases or financial folders will exhibit low diversity.

### SIG-04: Extension Anomaly & Convergence
- **What it observes:** The introduction of rare, unmapped file extensions, or the statistical convergence of diverse source extensions into a single uniform extension (e.g., `.docx`, `.pdf`, `.xlsx` all renamed to `.enc_kuyebiko`).
- **Why it matters:** Extension appending is one of the most recognizable indicators of opportunistic ransomware.
- **Ransomware indicator:** Dozens of previously diverse extensions converging into an identical suffix within a short window.
- **Benign explanations:** Batch file conversion tools (e.g., converting all `.bmp` files to `.png`), archiving utilities.
- **Limitations:** Completely blind to ransomware that preserves original filenames or uses generic extensions.

### SIG-05: Entropy Delta (Opt-In)
- **What it observes:** The statistical Shannon entropy change between pre-modification and post-modification file sample blocks (calculated in-memory and immediately discarded).
- **Why it matters:** Ciphertext generated by strong encryption algorithms (AES, ChaCha20) exhibits near-maximal Shannon entropy ($\approx 7.95 - 8.0$ bits per byte).
- **Ransomware indicator:** A sharp transition from low-to-medium entropy structured files (plain text, documents, source code) to near-uniform maximal entropy.
- **Benign explanations:** Archiving files into `.zip` or `.7z`, downloading pre-compressed files, video rendering, local database encryption.
- **Limitations:** High performance overhead if applied indiscriminately; files that are already compressed (JPEG, MP4, modern DOCX) already exhibit high entropy. Must remain strictly opt-in and bounded.

### SIG-06: Canary Sentinel Interaction (Opt-In v0.1)
- **What it observes:** Any modification, renaming, or deletion of designated sentinel files planted in strategic locations (e.g., alphabetically early or deep directory nodes).
- **Why it matters:** Legitimate users and processes have no reason to modify hidden canary files. Ransomware traversing directories alphabetically will inevitably modify them.
- **Ransomware indicator:** Immediate modification or renaming of a canary sentinel file.
- **Benign explanations:** Antivirus disk scans (read-only, does not trigger), full backup copy operations, accidental user curiosity.
- **Limitations:** Sophisticated ransomware may avoid known canary filenames or target files by extension rather than directory order.

### SIG-07: Process Context & Identity Attribution
- **What it observes:** Process identity (executable path, digital signature status, parent process) associated with the file modifications, provided by optional telemetry sources (Sysmon / ETW).
- **Why it matters:** Differentiates known signed system binaries from untrusted scripts executing out of `AppData` or `Temp`.
- **Ransomware indicator:** Unsigned, unverified binaries running from temporary directories generating heavy filesystem writes.
- **Benign explanations:** Newly compiled user programs, unsigned open-source tools.
- **Limitations:** Native Windows directory notifications (`ReadDirectoryChangesW`) do **not** supply PID context. Process attribution is completely unavailable unless an external adapter is configured.

### SIG-08: Recovery Interference (MITRE ATT&CK T1490)
- **What it observes:** External OS telemetry indicators representing attempts to disable or delete system recovery mechanisms (e.g., execution of `vssadmin.exe delete shadows /all /quiet`, `wbadmin delete catalog`, or tampering with Windows Recovery Environment).
- **Why it matters:** Inactivating shadow copies is a hallmark of human-operated and automated ransomware designed to prevent local restoration.
- **Ransomware indicator:** Security log events reflecting volume shadow copy deletion or recovery service disabling.
- **Benign explanations:** Legitimate administrative maintenance scripts, disk space reclamation routines.
- **Limitations:** Requires administrator-level event log auditing; absence of this telemetry does not imply recovery mechanisms are healthy.

### SIG-09: In-Place Modification Pattern
- **What it observes:** Repeated modifications to file contents (last-write updates, size fluctuations) where original filenames, paths, and extensions remain entirely untouched.
- **Why it matters:** Advanced ransomware evades rename/extension detectors by encrypting data directly inside the existing file structure.
- **Ransomware indicator:** Sustained, high-frequency write operations across existing files without accompanying create/rename operations.
- **Benign explanations:** Database logging, virtual machine disk image writes, continuous application auto-saving.
- **Limitations:** Difficult to distinguish from legitimate database writes without entropy or process attribution.

### SIG-10: Temporal Persistence (Low-and-Slow)
- **What it observes:** Recurring, low-frequency anomalous modifications across extended temporal windows (hours or days) that remain beneath the burst threshold.
- **Why it matters:** Evasive ransomware deliberately inserts pauses (e.g., sleep cycles between encryptions) to defeat burst-rate heuristics.
- **Ransomware indicator:** Cumulative anomalous changes accumulating steadily across long periods originating from the same source or targeting related folders.
- **Benign explanations:** Background file synchronization, scheduled daily backups, indexing services.
- **Limitations:** Higher false-positive risk over extended time horizons; requires persistent state tracking across application restarts.

---

## 3. Detection Scenarios & Signal Mapping

| Detection Scenario | Primary Signals | Corroborating Signals | Expected Severity Band |
| :--- | :--- | :--- | :--- |
| **Rapid Burst Encryption** | `SIG-01` (Burst), `SIG-04` (Extension) | `SIG-02` (Rename), `SIG-03` (Diversity) | High to Critical |
| **Intermittent / Throttled Encryption** | `SIG-03` (Diversity), `SIG-04` (Extension) | `SIG-05` (Entropy), `SIG-10` (Persistence) | Medium to High |
| **Low-and-Slow Attack** | `SIG-10` (Persistence) | `SIG-04` (Extension), `SIG-07` (Process) | Low to Medium |
| **In-Place Encryption (No Rename)** | `SIG-09` (In-Place), `SIG-01` (Burst) | `SIG-03` (Diversity), `SIG-05` (Entropy) | High |
| **Mass File Renaming** | `SIG-02` (Rename Ratio), `SIG-04` (Extension) | `SIG-03` (Diversity) | Medium to High |
| **Mass Destructive Deletion** | `SIG-02` (Delete Ratio), `SIG-01` (Burst) | `SIG-03` (Diversity) | High |
| **Canary File Triggering** | `SIG-06` (Canary Sentinel) | `SIG-01` (Burst), `SIG-07` (Process) | High to Critical |
| **Recovery Inhibition Activity** | `SIG-08` (T1490 Telemetry) | `SIG-01` (Burst), `SIG-04` (Extension) | Critical |

---

## 4. Risk Scoring Methodology

### 4.1 Normalized Scoring Formula
In legacy detection models, unavailable optional telemetry (such as entropy sampling or process monitoring) artificially suppressed overall risk scores, making High or Critical severity mathematically impossible without full instrumentation.

Kuyebiko solves this via a **dynamically normalized scoring formula**:

$$\text{Score} = 100 \times \frac{\sum_{i \in E} p_i}{\sum_{i \in E} w_i}$$

Where:
- $E$ is the set of signal families that are currently **enabled, healthy, and applicable** to the active detection window.
- $w_i$ is the configured maximum weight for signal family $i$.
- $p_i$ is the observed point contribution awarded to signal family $i$, bounded such that $0 \le p_i \le w_i$.

### 4.2 Mathematical Principles
1. **Denominator Normalization:** Signals that are disabled by user configuration, unconfigured (e.g., missing Sysmon adapter), or temporarily `DEGRADED` due to collector failure are **excluded from the denominator**. They do not penalize the score.
2. **Missing Telemetry Is Not Safe Telemetry:** A missing signal does not lower the calculated score, but it **reduces reported telemetry coverage and confidence**.
3. **Score Is Not a Probability:** The risk score (0–100) reflects the empirical weight of observed suspicious behaviour; it is **not** a Bayesian probability of malware infection.
4. **Independence Multiplier:** High-severity classifications cannot be reached by a single signal family alone, regardless of how intense the individual signal is.

### 4.3 Provisional Signal Weights (Reference Baseline)

| Signal Family | Configured Weight ($w_i$) | Default Availability |
| :--- | :---: | :--- |
| `SIG-01` Modification Burst | 20 | Enabled (Base Watcher) |
| `SIG-02` Rename/Delete Ratio | 15 | Enabled (Base Watcher) |
| `SIG-03` File Diversity | 15 | Enabled (Base Watcher) |
| `SIG-04` Extension Anomaly | 10 | Enabled (Base Watcher) |
| `SIG-10` Temporal Persistence | 15 | Enabled (Base Watcher) |
| `SIG-09` In-Place Modification | 10 | Enabled (Base Watcher) |
| `SIG-05` Entropy Delta | 5 | Opt-in (Resource Intensive) |
| `SIG-06` Canary Sentinel | 5 | Opt-in (Requires Setup) |
| `SIG-07` Process Context | 3 | Optional Adapter (Sysmon/ETW) |
| `SIG-08` Recovery Interference | 2 | Optional Adapter (Security Log) |
| **Total Weight Pool** | **100** | *Provisional baseline for calibration* |

---

## 5. Severity Classification & Gating

Kuyebiko enforces strict **severity gates** to prevent false positives from generating high-priority alerts:

| Severity Level | Score Band | Mandatory Severity Gating Rules |
| :--- | :---: | :--- |
| **Informational** | 0 – 19 | Isolated minor activity. Recorded for timeline context; no alert raised. |
| **Low** | 20 – 39 | One or more weak signals. Non-intrusive dashboard notification. |
| **Medium** | 40 – 59 | Requires at least **2 independent signal families** and adequate telemetry health. |
| **High** | 60 – 79 | Requires at least **3 independent signal families**, $\ge 60\%$ telemetry coverage, and no active collector degradation. |
| **Critical** | 80 – 100 | Requires at least **3 independent signal families** with extreme burst/diversity, OR high-confidence canary/recovery corroboration (`SIG-06` or `SIG-08`). |

*Notice:* All numerical score bands and weights are provisional baseline engineering hypotheses. They must be validated and tuned against the labelled benchmark corpus in Phase 5.

---

## 6. Confidence & Telemetry Coverage

Severity measures the *intensity* of the observed anomalous behaviour; **Confidence** measures the *trustworthiness and completeness* of the telemetry used to make that determination.

### 6.1 Confidence Levels
- **High Confidence:** All core filesystem collectors are healthy; queue depth is minimal; process attribution is verified (if enabled); no dropped events in the active window.
- **Moderate Confidence:** Base directory monitoring is healthy; minor event delays observed; process attribution is unavailable (`Unknown` attribution is neutral and does not penalize score).
- **Low Confidence:** High queue saturation ($>80\%$ capacity); transient watcher buffer warnings; missing optional corroborating adapters.
- **Insufficient Evidence:** Active `DEGRADED` collector state; verified dropped event notifications during the window; incomplete timeline reconstruction.

### 6.2 Impact of Process Attribution
Process attribution can exist in four states:
- `Confirmed`: Cryptographically verified process image and signer.
- `Correlated`: Matching PID and start-time correlation from external logs.
- `Unavailable`: No process adapter configured on the system.
- `Unknown`: Adapter active, but responsible process terminated before identity capture.

> **Crucial Rule:** `Unknown` or `Unavailable` process attribution is strictly neutral. It reduces confidence context, but **never** reduces the calculated risk score.

---

## 7. Explainability Framework

Every `SecurityIncident` generated by Kuyebiko is designed to be fully inspectable and transparent. Incidents do not present opaque scores; they expose the exact chain of evidence:

```
┌────────────────────────────────────────────────────────┐
│ Incident INC-20261104-001  [SEVERITY: HIGH] (Score: 75)│
├────────────────────────────────────────────────────────┤
│ Confidence: Moderate (Coverage: 75% | Adapters: Base)  │
│ Root: C:\Users\User\Documents (root-001)               │
│ Timeline: 2026-11-04 14:10:00 UTC to 14:10:08 UTC     │
├────────────────────────────────────────────────────────┤
│ Contributing Signal Breakdown:                         │
│  - SIG-01 (Burst): Rate=45 files/sec [Weight: 20/20]   │
│  - SIG-03 (Diversity): 6 extensions, 4 dirs [15/15]    │
│  - SIG-04 (Extension): .locked appended [10/10]        │
│  - SIG-02 (Rename Ratio): 0.85 [12/15]                 │
│  - Denominator: 75 points available (Healthy signals)  │
├────────────────────────────────────────────────────────┤
│ Evidence Links:                                        │
│  - 342 raw event references (FileEvent IDs)            │
│  - Model Version: 0.1.0-baseline                       │
└────────────────────────────────────────────────────────┘
```

The incident structure is backed by `src/kuyebiko/models/incidents.py`:
- `evidence_event_ids`: Direct foreign keys to raw `FileEvent` UUIDs.
- `signal_families`: List of contributing signal identifiers.
- `risk_score`: Normalized numerical score.
- `severity` & `confidence`: Categorical ratings.

---

## 8. Detection Limitations & Evasion Countermeasures

1. **Compilers and Build Tools:** Developers building large software projects produce intense file modification bursts. Kuyebiko addresses this through granular, auditable path suppression rules and multi-signal gating (build tools rarely converge extensions across diverse non-build directories).
2. **Encrypted Archives and Media Processing:** Extracting large zip archives or rendering video exhibits high entropy and high write volume. Gating requires extension anomaly or canary corroboration before reaching High/Critical severity.
3. **Sub-Threshold Low-and-Slow Evasion:** Ransomware that sleeps for long durations between file operations will avoid burst detection. `SIG-10` monitors extended time horizons, but cannot eliminate this evasion risk entirely without increasing benign false positives.
4. **Kernel-Level & Driver-Based Ransomware:** Malware executing via malicious Windows kernel drivers operates below user-mode Windows filesystem APIs. Kuyebiko cannot observe filesystem activity that is concealed or filtered by kernel rootkits.
