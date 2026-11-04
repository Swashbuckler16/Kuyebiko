# Kuyebiko — Security Threat Model

## 1. Security Objectives

Kuyebiko is a defensive, local-first endpoint behaviour monitoring and investigation tool for Windows. Its security posture is structured around six core objectives:

1. **Detect Suspicious Filesystem Behaviour:** Accurately identify behavioural sequences typical of ransomware and destructive malware (rapid writes, mass renames, anomalous extension changes, directory traversals) within monitored roots.
2. **Preserve Reliable Telemetry:** Maintain accurate, chronological records of observed filesystem metadata, sequence numbers, and timestamps even during heavy I/O workloads.
3. **Maintain Incident Integrity:** Protect the forensic validity of generated incident records, ensuring that timeline modifications or event deletions are detectable.
4. **Protect Locally Stored Investigation Records:** Safeguard the local SQLite database, configuration files, and diagnostic logs against accidental corruption, unprivileged tampering, or unauthorized modification.
5. **Identify Monitoring Failures:** Explicitly signal degraded collection states, buffer overflows, queue drops, and collector restarts to the user rather than giving a false sense of security.
6. **Minimize Collection of Sensitive Information:** Restrict data ingestion strictly to structural path metadata and timestamps. Never inspect, store, or transmit file contents, document text, credentials, or private user data.

---

## 2. Assets to Protect

The following assets define the security boundary of the Kuyebiko application:

| Asset | Description | Sensitivity / Impact |
| :--- | :--- | :--- |
| **Monitoring Configuration** | User-selected root directories, recursion flags, queue capacities, and retention limits. | Tampering can blind the agent to critical directories. |
| **Filesystem Event Metadata** | Normalized event records containing relative paths, event types, UTC timestamps, and sequence numbers. | Corruption or deletion impairs detection and forensic reconstruction. |
| **Incident Records** | Persisted security alerts with calculated risk scores, severity ratings, contributing signals, and evidence IDs. | Modification can erase evidence of active ransomware compromise. |
| **SQLite Database (`kuyebiko.db`)** | Relational database containing events, incidents, and operational health history. | High. Database destruction eliminates historical forensic visibility. |
| **Detection Configuration & Weights** | Signal family weights, sliding window parameters, and severity gate thresholds. | Manipulation can suppress alerts or cause denial-of-service via false positives. |
| **Application Binaries & Libraries** | Python bytecode, virtual environment binaries, and native Windows wrappers. | Modification allows execution of arbitrary code under the agent's identity. |
| **Agent Integrity Records** | Cryptographic hash chains and application startup manifests. | Invalidating or forging records obscures evidence of tampering. |
| **Diagnostic Log Files (`kuyebiko.log`)** | Rotating logs detailing service status, collection errors, and heartbeat intervals. | Log deletion or tampering hides collector failures and system errors. |
| **Monitored Directory Metadata** | Canonical paths and directory identifiers selected by the user. | Leakage exposes the folder structure of the host system. |

---

## 3. Trust Boundaries

Kuyebiko establishes five distinct trust boundaries:

```
┌────────────────────────────────────────────────────────┐
│ [Boundary 5: User Session vs Administrative Context]   │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Windows Operating System / User Context          │  │
│  │ (Untrusted input: filesystem events, paths)      │  │
│  └────────────────────────┬─────────────────────────┘  │
│             [Boundary 1: OS / Windows API]             │
│  ┌────────────────────────▼─────────────────────────┐  │
│  │ Kuyebiko Telemetry Collector (Planned)           │  │
│  └────────────────────────┬─────────────────────────┘  │
│       [Boundary 2: Collector / Ingestion Queue]        │
│  ┌────────────────────────▼─────────────────────────┐  │
│  │ Event Normalizer & Bounded Queue (Planned)       │  │
│  └────────────────────────┬─────────────────────────┘  │
│       [Boundary 3: Processing / Detection Engine]      │
│  ┌────────────────────────▼─────────────────────────┐  │
│  │ Detection Engine & Scoring Logic (Planned)       │  │
│  └────────────────────────┬─────────────────────────┘  │
│       [Boundary 4: Engine / SQLite Persistence]        │
│  ┌────────────────────────▼─────────────────────────┐  │
│  │ SQLite Database & Integrity Store (Implemented)   │  │
│  └────────────────────────▲─────────────────────────┘  │
│                           │                            │
│  ┌────────────────────────┴─────────────────────────┐  │
│  │ Kuyebiko Desktop UI (PySide6) (Planned)          │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

1. **Boundary 1 (Windows OS & Kuyebiko Collector):** Telemetry from the Windows API (`ReadDirectoryChangesW`) is untrusted. File paths, filenames, and change notifications may contain adversarial characters, directory traversal attempts, or extremely high volume.
2. **Boundary 2 (Collector & Event Processor):** The collector receives raw notifications and forwards them across a bounded queue. Unchecked event volume must not crash or exhaust the processor's memory.
3. **Boundary 3 (Event Processor & Detection Engine):** The engine operates only on validated, normalized `FileEvent` objects with verified relative paths, UTC timestamps, and monotonic sequence numbers.
4. **Boundary 4 (Detection Engine & SQLite Persistence):** Detection results cross into persistent storage via parameterized SQLAlchemy queries. The database enforces constraints and integrity checks.
5. **Boundary 5 (Desktop UI & Background Service / Local OS):** The UI reads data locally from SQLite and communicates with the background service. The service executes with independent lifecycle management.

---

## 4. Threat Actors & Adversary Profiles

Kuyebiko considers seven distinct adversary categories:

| Threat Actor | Capabilities & Motivation | Relevance to Kuyebiko |
| :--- | :--- | :--- |
| **Commodity Ransomware** | Automated mass encryption, rapid file renaming, ransom note creation, shadow copy deletion (T1490). | Primary target for behavioural detection. |
| **Malicious Scripts** | PowerShell, batch, or VBScript droppers executing file operations or tampering with settings. | Ingested as rapid or anomalous filesystem activity. |
| **Same-User Malware** | Arbitrary code running with the privileges of the logged-in user. Can attempt to stop user-mode processes or modify local files. | Can attempt to terminate the monitoring agent or corrupt the database. |
| **Standard Local Users** | Legitimate users operating on the host. Can modify their own files or make configuration errors. | Must be protected against path traversal or accidental database deletion. |
| **Local Administrators** | Full control over the Windows operating system. Can stop services, edit registry keys, alter file permissions, and rewrite files. | Outside guaranteed containment; tamper detection possible, prevention impossible. |
| **Kernel-Level Attackers** | Rootkits or kernel drivers capable of intercepting syscalls or subverting ETW/filesystem filters. | Out of scope. Can bypass all user-mode monitoring silently. |
| **Accidental System Actions** | Power cuts, forced restarts, storage full errors, hardware disconnections. | Mitigated via SQLite WAL mode, atomic writes, and startup reconciliation. |

---

## 5. Threat Scenarios

### Scenario 1: Rapid File Modification (Burst Write)
- **Threat Description:** Ransomware modifies hundreds of files within seconds to encrypt user data before detection occurs.
- **Potential Impact:** High. Rapid loss of data confidentiality and availability across monitored directories.
- **Relevant Assets:** Monitored files, Filesystem Event Metadata, Incident Records.
- **Mitigation (Planned):** `SIG-01` (Modification Burst) tracks distinct file modification rates in rolling windows and triggers high-severity alerts.
- **Residual Risk:** Fast ransomware may encrypt initial files before the sliding window evaluates and alerts.

### Scenario 2: File Encryption-Like Behaviour (High Entropy / In-Place)
- **Threat Description:** Adversary rewrites file contents with encrypted ciphertext without altering extensions or filenames.
- **Potential Impact:** High. Unnoticed data encryption.
- **Relevant Assets:** Monitored files, Incident Records.
- **Mitigation (Planned):** `SIG-09` (In-Place Modification) and opt-in `SIG-05` (Bounded Entropy Delta) evaluate content change patterns.
- **Residual Risk:** Bounded entropy sampling cannot inspect all files due to performance and privacy constraints.

### Scenario 3: Mass File Renaming
- **Threat Description:** Ransomware appends custom extensions (e.g., `.locked`, `.kuyebiko_crypto`) across numerous files.
- **Potential Impact:** Medium to High. Disrupts application file associations.
- **Relevant Assets:** Filesystem Event Metadata, Incident Records.
- **Mitigation (Planned):** `SIG-02` (Rename/Delete Ratio) and `SIG-04` (Extension Anomaly) track extension convergence and mass rename operations.
- **Residual Risk:** Benign tools (e.g., photo management utilities) also perform bulk renames; requires multi-signal corroboration.

### Scenario 4: Mass File Deletion
- **Threat Description:** Destructive malware (wiper) deletes files instead of encrypting them.
- **Potential Impact:** Critical. Total data loss.
- **Relevant Assets:** Monitored files, Incident Records.
- **Mitigation (Planned):** `SIG-02` monitors elevated deletion ratios relative to total activity.
- **Residual Risk:** Standard user cleanups or package uninstalls can trigger deletions; gated by corroborating factors.

### Scenario 5: Recovery Interference (MITRE ATT&CK T1490)
- **Threat Description:** Ransomware attempts to delete Volume Shadow Copies (`vssadmin delete shadows`), disable recovery mode, or tamper with backups.
- **Potential Impact:** Critical. Prevents file restoration via Windows native backups.
- **Relevant Assets:** Incident Records, System Recovery Points.
- **Mitigation (Planned):** `SIG-08` correlates external security event telemetry (Sysmon / Security Log) to elevate incident severity.
- **Residual Risk:** Requires optional OS telemetry sources; absence of telemetry is not proof of backup health.

### Scenario 6: Monitoring Process Termination
- **Threat Description:** Malware identifies the Kuyebiko process and executes `taskkill /F` or equivalent to halt monitoring.
- **Potential Impact:** High. Disables monitoring during an active attack.
- **Relevant Assets:** Kuyebiko Application Process, Event Queue.
- **Mitigation (Planned):** Background Windows Service architecture with Service Control Manager (SCM) recovery actions and monotonic heartbeat reporting (`TelemetrySnapshot.last_heartbeat`).
- **Residual Risk:** Malware with administrative privileges can alter SCM configuration or kill the service unconditionally.

### Scenario 7: Configuration Tampering
- **Threat Description:** Adversary modifies `.env` or configuration files to disable monitoring or exclude attack directories.
- **Potential Impact:** High. Monitoring blind spots.
- **Relevant Assets:** Monitoring Configuration (`KuyebikoSettings`).
- **Mitigation (Implemented / Planned):** Strict Pydantic model validation on configuration fields (`ge=100`, `le=1000000` on queue size). Planned ACL restrictions on configuration storage.
- **Residual Risk:** Local administrators can overwrite configuration files directly.

### Scenario 8: Database Corruption
- **Threat Description:** Sudden power loss, disk write failure, or concurrent process conflict corrupts `data/kuyebiko.db`.
- **Potential Impact:** High. Loss of recorded forensic history.
- **Relevant Assets:** SQLite Database.
- **Mitigation (Implemented):** SQLite Write-Ahead Logging (`WAL`), `PRAGMA synchronous = NORMAL`, `busy_timeout = 30000`, and automated `PRAGMA integrity_check` executed via `Database.integrity_check()`.
- **Residual Risk:** Severe physical media failure can still cause unrecoverable database corruption.

### Scenario 9: Database Modification / Deletion by Adversary
- **Threat Description:** Malware locates `data/kuyebiko.db` and deletes or updates records to hide its footprints.
- **Potential Impact:** High. Loss of incident evidence.
- **Relevant Assets:** Incident Records, SQLite Database.
- **Mitigation (Implemented / Planned):** Directory permissions. Planned SHA-256 cryptographic hash chaining across incident records (`IntegrityRecord`) to make row deletions or modifications detectable.
- **Residual Risk:** An attacker with sufficient privileges can delete the entire database file or recompute the hash chain.

### Scenario 10: Event Queue Exhaustion (Denial of Service)
- **Threat Description:** Adversary or benign stress workload generates millions of rapid filesystem events to exhaust application memory.
- **Potential Impact:** Medium. Out-Of-Memory (OOM) crash of the monitoring service.
- **Relevant Assets:** Event Queue, System RAM.
- **Mitigation (Implemented / Planned):** Bounded queue enforced by `KuyebikoSettings.event_queue_size` (default 10,000, validated by Pydantic) and drop accounting in `TelemetrySnapshot.events_dropped`.
- **Residual Risk:** Dropped events create blind spots, though explicitly tracked and reported as `DEGRADED`.

### Scenario 11: Filesystem Notification Overflow
- **Threat Description:** The Windows kernel event buffer for `ReadDirectoryChangesW` overflows during an I/O storm, dropping change notifications.
- **Potential Impact:** Medium. Missing file modification events.
- **Relevant Assets:** Filesystem Event Metadata.
- **Mitigation (Planned):** Catch buffer overflow error codes from Windows API, immediately mark telemetry state as `DEGRADED` in `TelemetrySnapshot`, and schedule a directory reconciliation check.
- **Residual Risk:** Exact chronological order of missed events during the overflow window cannot be recovered.

### Scenario 12: Log Manipulation
- **Threat Description:** Attacker modifies or deletes `logs/kuyebiko.log` to obscure diagnostic errors.
- **Potential Impact:** Low to Medium. Impairs post-incident troubleshooting.
- **Relevant Assets:** Diagnostic Log Files.
- **Mitigation (Implemented):** Centralized rotating file handler (`RotatingFileHandler` with 5 MB capacity and 5 backups) with UTC timestamps and locked file handles.
- **Residual Risk:** Privileged attackers can delete log files from disk.

### Scenario 13: Path Traversal Attacks
- **Threat Description:** Malformed filesystem events inject paths containing directory traversal characters (e.g., `../../Windows/System32`).
- **Potential Impact:** Medium. May cause the detector to evaluate files outside user-selected roots or corrupt internal indexes.
- **Relevant Assets:** Monitored Directory Metadata, Detection Engine.
- **Mitigation (Implemented):** `FileEvent` model validator explicitly checks:
  ```python
  if any(part == ".." for part in normalized.split("/")):
      raise ValueError("Path traversal is not allowed")
  ```
  Absolute Windows paths (e.g., `C:\...`) are also strictly rejected.
- **Residual Risk:** None within the validated Pydantic layer.

### Scenario 14: Symbolic-Link and Reparse-Point Abuse
- **Threat Description:** Adversary creates symlinks or directory junctions inside a monitored root pointing to sensitive external directories.
- **Potential Impact:** Medium. Causes unauthorized monitoring or circular traversal loops.
- **Relevant Assets:** Filesystem Collector, System Storage.
- **Mitigation (Planned):** Canonical path resolution (`Path.resolve()`) and verification that target paths reside strictly beneath authorized root boundaries.
- **Residual Risk:** Fast symlink race conditions (TOCTOU) during rapid filesystem manipulation.

### Scenario 15: Telemetry Suppression / Evasion (Low-and-Slow)
- **Threat Description:** Sophisticated ransomware encrypts files intermittently (e.g., one file every 10 minutes) to avoid burst thresholds.
- **Potential Impact:** High. Silent gradual encryption of user files.
- **Relevant Assets:** Monitored files, Incident Records.
- **Mitigation (Planned):** `SIG-10` (Temporal Persistence) tracks cumulative low-volume anomalies across extended rolling windows (hours/days).
- **Residual Risk:** Low-and-slow attacks closely mimic normal user editing patterns; high precision without false alarms is difficult.

### Scenario 16: Process Attribution Failure / PID Reuse
- **Threat Description:** The responsible process terminates before telemetry captures its identity, or a benign process reuses the terminated process's PID.
- **Potential Impact:** Medium. Misattributing ransomware activity to a legitimate application.
- **Relevant Assets:** Incident Records.
- **Mitigation (Planned):** Process attribution states (`Confirmed`, `Correlated`, `Unavailable`, `Unknown`). Unknown attribution is strictly neutral and never reduces the calculated risk score. Process keys include both PID and process creation timestamp to combat PID reuse.
- **Residual Risk:** Standard directory notifications do not natively provide PID context; attribution depends entirely on optional event sources.

---

## 6. STRIDE Threat Analysis

| Threat Category | Realistic Kuyebiko Threat Scenario | Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary injects fabricated events into the ingestion queue or forges IPC messages to trigger false incidents. | Authenticate IPC endpoints; accept events only from registered internal collector threads. | Planned |
| **Tampering** | Malware modifies configuration parameters (`KuyebikoSettings`), alters database rows in `kuyebiko.db`, or modifies logs. | Strict Pydantic validation; SQLite WAL mode; cryptographic hash chaining over incident records. | Implemented (Models/DB) / Planned (Hash chain) |
| **Repudiation** | Adversary deletes generated incidents from SQLite to hide evidence of ransomware execution. | Append-only incident records; hash-chain verification detects sequence gaps or missing records on startup. | Planned |
| **Information Disclosure** | Diagnostic logs or exported incidents expose sensitive file paths or directory names to unauthorized users. | Enforce local-only data retention; implement path and username redaction in incident export utilities. | Planned |
| **Denial of Service** | Event storms exhaust memory; filesystem buffer overflow blinds detection; database locks prevent writes. | Bounded ingestion queues; explicit `DEGRADED` state signaling; SQLite `busy_timeout = 30000` with WAL concurrency. | Implemented (Config/DB) / Planned (Queue drop logic) |
| **Elevation of Privilege** | Attacker abuses service IPC to execute arbitrary administrative actions or bypass Windows permissions. | Run background service with least privilege; validate all IPC schemas; avoid executing external binaries. | Planned |

---

## 7. Mitigation Strategy

### Implemented Mitigations (Current Baseline)
- **Strict Input Validation:** Pydantic models (`FileEvent`, `SecurityIncident`, `TelemetrySnapshot`, `KuyebikoSettings`) enforce boundary checks, timezone compliance (UTC), and type safety.
- **Secure Path Handling:** `FileEvent` model validators reject absolute paths (`C:\...`), leading slashes, and path traversal sequences (`..`).
- **Database Durability & Integrity:** Asynchronous SQLite engine utilizes WAL mode, connection timeouts (30s), foreign key constraints, and built-in integrity checking (`PRAGMA integrity_check`).
- **Centralized Diagnostic Logging:** Rotating file logs prevent uncontrolled disk consumption while preserving error history.
- **Isolated Testing:** Full unit test suite (44 tests) validating model invariants, negative input rejections, and database health.

### Planned Mitigations (Future Phases)
- **Least Privilege Execution:** Restrict background service permissions to required directory observation handles.
- **Service Recovery & Watchdog:** Windows SCM auto-restart configurations for crash resilience.
- **Cryptographic Hash Chaining:** SHA-256 hash chains over incident rows to identify retrospective tampering.
- **Binary Manifest Verification:** Checksum verification of application binaries at startup to detect unauthorized modification.
- **Bounded Backpressure Queues:** Queue saturation handlers that drop excess events cleanly while incrementing explicit drop counters and toggling `DEGRADED` health states.

---

## 8. Explicit Limitations (Mandatory Boundary)

Kuyebiko is designed with rigorous defensive principles, but operates within fundamental technical limits:

1. **User-Mode Execution Boundary:** A user-mode security application **cannot** guarantee protection or survival against an attacker possessing local administrator or kernel-level (ring 0) privileges. A privileged attacker can terminate services, alter kernel filters, unload drivers, or rewrite files bypassing user-mode notifications entirely.
2. **Local Hash Chain Limitations:** While a local cryptographic hash chain makes unauthorized row deletion or modification detectable, it **cannot** prevent an attacker with write access to the database from rewriting the entire database file and recomputing valid hashes from scratch. Cryptographic non-repudiation requires external hardware anchors (TPM) or remote log shipping, which are outside Kuyebiko's local-first MVP scope.
3. **Event Loss Under Buffer Overrun:** Windows filesystem notifications (`ReadDirectoryChangesW`) rely on fixed-size kernel buffers. During massive I/O bursts, notifications can be dropped by the operating system before Kuyebiko can read them. Kuyebiko reports this state as `DEGRADED`, but cannot recreate events dropped by the OS kernel.
4. **Process Attribution Imprecision:** Directory change notifications do not include process identifiers. Without optional, elevated telemetry providers (such as Sysmon or kernel ETW sessions), process attribution is unavailable.
5. **Probabilistic Nature of Behavioural Detection:** Behavioural detection is inherently heuristic. It can produce false positives on legitimate batch workloads (e.g., code compilation, archive extraction, photo library tagging) and false negatives on evasion-engineered ransomware (e.g., sub-threshold low-and-slow modification).
6. **Not an Antivirus or EDR Platform:** Kuyebiko does not provide file quarantine, process termination, kernel hooking, network filtering, or automatic signature updates. It does not replace Microsoft Defender or commercial endpoint security platforms.
7. **No Prevention or Recovery Guarantees:** Kuyebiko is an observation and investigation tool. It does **not** guarantee that files will be saved from encryption, and it provides no capability to decrypt or restore files once modified.

---

## 9. Security Assumptions

The design of Kuyebiko rests upon the following foundational assumptions:

1. **Operating System Integrity:** The underlying Windows 11 kernel, NTFS filesystem driver, and system APIs behave according to documented specifications and have not been subverted by rootkits.
2. **System Clock Monotonicity:** While wall-clock time (`timestamp_utc`) may be subject to user adjustments or NTP sync jumps, the system monotonic clock (`monotonic_ns`) provides strictly increasing elapsed time intervals.
3. **Local Filesystem Isolation:** The user-designated monitored directories are stored on local NTFS or ReFS filesystems. Network shares (SMB/NFS) may experience delayed or coalesced change notifications beyond Kuyebiko's control.
4. **Defensive Coexistence:** The user maintains active primary endpoint protection (such as Microsoft Defender) and regular, tested offline backups. Kuyebiko operates as a visibility aid, not the primary barrier against malware execution.
