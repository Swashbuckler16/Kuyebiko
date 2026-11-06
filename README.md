# Kuyebiko — Ransomware Behaviour Detection

> **Windows Ransomware Behaviour Monitoring & Incident Investigation Platform**
> *A local-first, privacy-preserving endpoint observation and defensive investigation platform.*

---

## 1. Project Overview

**Kuyebiko** is an open-source, local-first endpoint monitoring and incident investigation application designed for 64-bit Windows systems (primarily Windows 11). It continuously observes filesystem activity across user-selected directories and correlates event patterns to identify behavioural sequences characteristic of ransomware and destructive malware.

Rather than relying on brittle file signatures or easily bypassed extension blacklists, Kuyebiko evaluates multi-signal behavioural dynamics:
- Burst write frequencies.
- Abnormal rename and delete ratios.
- Directory and file-type traversal diversity.
- Uniform extension convergence.
- In-place modification patterns.
- Optional in-memory entropy shifts and canary sentinel interactions.
- Corroborating OS recovery-interference indicators (MITRE ATT&CK T1490).

Kuyebiko operates with complete local data sovereignty: file contents are **never** inspected, collected, or uploaded. It acts as an explainable investigation complement—not an antivirus, EDR replacement, or backup recovery tool.

---

## 2. Core Objectives

- **Local Behavioural Visibility:** Observe directory modifications in real time without external cloud dependencies.
- **Explainable Incident Scoring:** Quantify risk through an additive, normalized scoring model that exposes contributing signals, observed values, thresholds, and weights.
- **Uncertainty & Coverage Quantification:** Explicitly report telemetry quality, degraded monitoring states, buffer overruns, and missing collectors rather than presenting false all-clear assurances.
- **Forensic Evidence Preservation:** Maintain structured, tamper-evident local incident timelines linked directly to raw event identifiers.
- **Safe Response Guidance:** Offer non-destructive situational guidance (such as network isolation and forensic preservation) without executing autonomous destructive file operations.

---

## 3. Current Implementation Status

Kuyebiko is actively under development. Below is the verified status of the codebase at **Phase 3 Complete (Steps 3.1 through 3.14 Verified)**:

### Implemented Functionality (Tested & Active)
- **Event Processing & Ingestion Subsystem (`src/kuyebiko/processing/`):**
  - `EventPipeline` (`processing/pipeline.py`): Central lifecycle coordinator managing deterministic startup, graceful draining, safe shutdown, and leak-free restart across `MonitoredRootRegistry`, `BoundedEventQueue`, `EventIngestor`, and `EventProcessingWorker`. Implements automatic rollback on partial startup failure and strict `PipelineLifecycleState` transitions (`STOPPED`, `STARTING`, `RUNNING`, `STOPPING`, `ERROR`).
  - `EventIngestor` (`processing/ingestion.py`): Fast, thread-safe ingestion interface connecting filesystem watchers and multi-root registries to the processing pipeline. Validates input types, tracks per-root counts, and emits type-safe `IngestionOutcome` status (`ACCEPTED`, `QUEUE_FULL`, `REJECTED`, `SHUTTING_DOWN`).
  - `BoundedEventQueue` (`processing/queue.py`): Thread-safe bounded buffer wrapping standard library `queue.Queue` with configurable capacity (`KUYEBIKO_EVENT_QUEUE_SIZE`), non-blocking submission semantics, high-watermark tracking, and telemetry degradation on saturation with automatic recovery.
  - `EventProcessingWorker` (`processing/worker.py`): Dedicated background worker thread executing strictly sequenced event normalization, rename correlation, error isolation, bounded retries (at-least-once delivery semantics), and downstream event dispatch with graceful shutdown draining.
  - `EventDeduplicator` (`processing/deduplication.py`): Conservative duplicate event filter with bounded fingerprint cache and TTL-based expiration (`ttl_seconds=5.0`). Suppresses only exact duplicate notification deliveries while strictly preserving legitimate sequential writes, multi-chunk modifications, and create-modify sequences.
  - `EventOrderingTracker` (`processing/ordering.py`): Chronology and latency tracking per monitored root. Detects out-of-order event arrivals and monitors processing latency without corrupting observation timestamps or stalling the pipeline.
  - `PipelineTelemetryAggregator` (`processing/telemetry.py`): Structured telemetry aggregator providing separate accounting for Windows kernel buffer overflows (`ERROR_NOTIFY_ENUM_DIR` (1022)) vs. exact application queue backpressure drops (`QUEUE_FULL`), tracking `PipelineHealth` (`HEALTHY`, `DEGRADED`, `ERROR`, `STOPPED`).
  - Downstream Consumer Protocol (`processing/contracts.py`): Extensible `@runtime_checkable` `EventConsumer` protocol with `EventEnvelope` ordering metadata propagation, reference `CallbackEventConsumer`, and thread-safe `InMemoryEventConsumer` implementations.
- **Windows Filesystem Watcher & Collectors Subsystem (`src/kuyebiko/collectors/`):**
  - `WindowsDirectoryWatcher`: Native Windows directory watcher utilizing `ReadDirectoryChangesW` via standard library `ctypes`. Operates in a dedicated background worker thread with non-blocking graceful cancellation via `CancelIoEx`.
  - Transactional Lifecycle Hardening: Guaranteed handle closing on thread start failures; clean timeout shutdowns without dangling handle leaks; strict resource ownership semantics.
  - `FILE_NOTIFY_INFORMATION` Binary Parser (`collectors/windows/parser.py`): Low-level byte parser with strict alignment checks, bounds verification, UTF-16LE decoding, Unicode filename handling, and Windows path normalization.
  - `RenameCorrelator` (`collectors/rename_correlator.py`): Thread-safe rename correlation engine pairing `RENAMED_OLD_NAME` and `RENAMED_NEW_NAME` events based on temporal proximity and directory alignment within a bounded time window (1.0s default). Enforces per-root isolation, bounded pending queues with capacity eviction, rejection of self-renames, and un-correlated rename safety.
  - `EventNormalizer` (`collectors/normalizer.py` & `src/kuyebiko/processing/`): Deterministic event normalizer transforming Win32 raw notifications into domain `FileEvent` objects. Generates collision-resistant UUIDs, atomic monotonic sequence numbers, dual timestamps (UTC + monotonic), path validation, directory flag preservation, and telemetry quality mapping.
  - Telemetry Degradation & Buffer Overflow Management (`collectors/base.py` & `collectors/windows/watcher.py`):
    - `WatcherHealth` state machine: `HEALTHY`, `DEGRADED`, `STOPPED`, and `ERROR`.
    - Detects OS buffer overflow conditions (`ERROR_NOTIFY_ENUM_DIR` (1022)) and zero-byte reads, tracks cumulative `overflow_count` and estimated `gap_count`, records deduplicated degradation reasons, and automatically recovers health state on subsequent successful reads.
    - Generates structured `TelemetrySnapshot` metrics capturing event counts, uncounted event loss flags, queue capacities, and degradation reasons.
  - `MonitoredRootRegistry`: Thread-safe multi-root registry coordinating independent directory watchers. Enforces directory uniqueness, prevents duplicate registrations or path aliasing, tracks aggregate collector health, and supports unified `start_all()` and `stop_all()` lifecycles with transactional rollback.
  - Collector Models (`collectors/models.py`):
    - `MonitoredRoot`: Validated directory configuration model enforcing absolute paths, directory existence, immutability (`frozen=True`), and canonical path resolution.
    - `RawFileNotification`: Raw OS event container enforcing UTC timestamps, monotonic time attribution, relative path normalization, traversal prevention, optional `is_directory` flag, and safe conversion to `FileEvent`.
    - `WindowsFileAction`: IntEnum mapping Win32 action codes (1=ADDED, 2=REMOVED, 3=MODIFIED, 4=RENAMED_OLD_NAME, 5=RENAMED_NEW_NAME) to domain `EventType`.
- **Domain Data Models (`src/kuyebiko/models/`):**
  - `FileEvent`: Normalized filesystem event schema enforcing UTC timezones, monotonic timestamps, relative path normalization, path traversal prevention (`..`), absolute path rejection, directory flag attribution, and rename path pairing.
  - `SecurityIncident`: Incident alert model enforcing 0–100 risk score bounds, unique evidence IDs, unique signal family lists, chronological ordering, and categorical severity/confidence ratings.
  - `TelemetrySnapshot`: Operational health model tracking queue capacity, queue depth, dropped event counters, collector states, and validated degradation reasons.
- **Core Exceptions (`src/kuyebiko/core/exceptions.py`):**
  - Custom domain hierarchy: `KuyebikoError`, `CollectorError`, `WatcherError`, `RegistryError`, `BufferParseError`, `PathValidationError`, `NormalizationError`, `ProcessingError`, `QueueFullError`, `WorkerLifecycleError`, `PipelineLifecycleError`.
- **Application Configuration (`src/kuyebiko/core/config.py`):**
  - `KuyebikoSettings`: Central configuration managed via `pydantic-settings` supporting `.env` files and `KUYEBIKO_` environment variable overrides with validation bounds.
- **Database Infrastructure (`src/kuyebiko/storage/database.py`):**
  - Asynchronous SQLite connection management via SQLAlchemy 2.0 and `aiosqlite`.
  - Automatic PRAGMA configuration: `PRAGMA journal_mode = WAL`, `PRAGMA busy_timeout = 30000`, `PRAGMA foreign_keys = ON`, `PRAGMA synchronous = NORMAL`.
  - Connectivity initialization (`initialize()`), active connection health checks (`health_check()`), and built-in database integrity checks (`integrity_check()`).
- **Centralized Diagnostic Logging (`src/kuyebiko/utils/logging_config.py`):**
  - Rotating file logger (`5 MB` max size, `5` backup archives) and stream console logger with clean formatting and shutdown handlers.
- **Automated Test Suite (`tests/`):**
  - **240 comprehensive unit tests** (`tests/unit/`) validating pipeline lifecycle coordination, bounded queue backpressure, conservative deduplication, ordering tracking, worker thread lifecycles, error isolation, collectors, parsers, normalizers, and domain schemas.
  - **16 integration tests** (`tests/integration/`) verifying live Windows `ReadDirectoryChangesW` filesystem events, end-to-end watcher-to-worker pipeline dispatch, multi-root registry routing, and async database WAL operations.
  - **256 total passing tests** with **94% overall code coverage**.

> [!IMPORTANT]
> **Windows Monitoring Architecture & Limitations:**
> - **Telemetry Only:** Phase 2 and Phase 3 provide an audit-hardened filesystem telemetry ingestion and processing foundation. They do *not* execute ransomware detection, scoring rules, or automated remediation; detection correlation is scheduled for Phase 4.
> - **Notification-Based Semantics:** Windows `ReadDirectoryChangesW` is a notification mechanism, not a guaranteed lossless audit log. Under extreme I/O burst pressure, OS buffers can overflow (`ERROR_NOTIFY_ENUM_DIR` (1022)). Kuyebiko captures this uncertainty through explicit `WatcherHealth.DEGRADED` states, `uncounted_event_loss` flags, and `gap_count` metrics.
> - **No Process Attribution:** Win32 filesystem notifications identify file path mutations but do *not* report the originating process identifier (PID) or executable image path. Process attribution will be introduced in subsequent phases via ETW/Sysmon adapters.

### Partially Implemented Functionality
- **Package Architecture:** Modular package structure established under `src/kuyebiko/` with package initializers (`processing`, `detection`, `integrity`, `application`).

### Planned Functionality (Next Phases)
- **Behavioural Detection Engine (`detection/`):** Sliding time-window correlation, 10 signal evaluators, and normalized scoring formulas (Phase 4).
- **Relational Tables & Migrations (`storage/migrations/`):** Relational schema definitions for events and incidents.
- **Tamper Evidence & Integrity (`integrity/`):** SHA-256 cryptographic hash chaining over incident records.
- **Desktop Interface (`application/`):** PySide6 graphical dashboard, folder manager, and incident timeline inspector.
- **Harmless Behavior Simulator:** Path-jailed sandbox simulator for safe validation testing.

---

## 4. Technology Stack

| Layer | Implemented Technologies | Planned Technologies |
| :--- | :--- | :--- |
| **Language & Runtime** | Python 3.12+ (tested on Python 3.14) | Windows C-types / native win32 bindings |
| **Data Validation** | Pydantic v2.10+, Pydantic Settings v2.7+ | — |
| **Storage & Persistence**| SQLAlchemy 2.0 (asyncio), aiosqlite 0.20+, SQLite 3 WAL | Alembic migrations, SHA-256 hash chaining |
| **Telemetry Ingestion** | Windows `ReadDirectoryChangesW` (Implemented), Pydantic schemas | Sysmon / ETW adapters |
| **User Interface** | Rotating diagnostic file logger, console streams | PySide6 (Qt for Python desktop UI) |
| **Quality & Testing** | pytest 8.0+, pytest-cov 7.1+, Ruff 0.9+ | Labelled synthetic benchmark runner |

---

## 5. Repository Structure

```
Kuyebiko/
├── .github/
│   └── workflows/
│       └── tests.yml             # Continuous integration workflow
├── docs/
│   ├── architecture.md           # System architecture and technical design
│   ├── threat-model.md           # Comprehensive security threat model
│   ├── detection-model.md        # Behavioural detection and scoring model
│   └── benchmark-methodology.md  # Empirical validation and benchmark methodology
├── src/
│   └── kuyebiko/
│       ├── __init__.py           # Package root
│       ├── main.py               # Application entry point
│       ├── core/                 # Core configuration, constants, exceptions
│       │   ├── __init__.py
│       │   ├── config.py         # KuyebikoSettings (pydantic-settings)
│       │   ├── constants.py      # Constants (planned)
│       │   └── exceptions.py     # Domain exceptions (Implemented)
│       ├── models/               # Domain Pydantic schemas (Implemented)
│       │   ├── __init__.py
│       │   ├── events.py         # FileEvent, EventType, EventSource
│       │   ├── incidents.py      # SecurityIncident, IncidentSeverity
│       │   └── telemetry.py      # TelemetrySnapshot, MonitoringStatus
│       ├── collectors/           # Filesystem and OS telemetry collectors (Implemented)
│       │   ├── __init__.py       # Collector package exports
│       │   ├── base.py           # BaseWatcher abstract class & type aliases
│       │   ├── models.py         # MonitoredRoot, RawFileNotification, WindowsFileAction
│       │   ├── registry.py       # MonitoredRootRegistry multi-root coordinator
│       │   └── windows/          # Native Windows watcher implementation
│       │       ├── __init__.py
│       │       ├── api.py        # Win32 ctypes signatures & error constants
│       │       ├── parser.py     # FILE_NOTIFY_INFORMATION buffer parser
│       │       └── watcher.py    # WindowsDirectoryWatcher worker thread
│       ├── processing/           # Normalization, bounded queue, worker (Implemented)
│       │   ├── __init__.py       # Processing exports
│       │   ├── contracts.py      # EventConsumer protocol, outcomes, reference consumers
│       │   ├── deduplication.py  # EventDeduplicator conservative filter
│       │   ├── ingestion.py      # EventIngestor pipeline interface
│       │   ├── ordering.py       # EventOrderingTracker chronology and latency
│       │   ├── queue.py          # BoundedEventQueue and EventQueueMetrics
│       │   ├── telemetry.py      # PipelineTelemetryAggregator and backpressure snapshot
│       │   └── worker.py         # EventProcessingWorker thread with retry isolation
│       ├── detection/            # Signal evaluators and scoring engine (Phase 4)
│       ├── storage/              # Database engine and migrations
│       │   ├── __init__.py
│       │   ├── database.py       # Asynchronous SQLite Database class (Implemented)
│       │   └── migrations/       # Schema migrations (Planned)
│       ├── integrity/            # Cryptographic hash chains (Planned)
│       ├── application/          # Service runner and PySide6 UI (Planned)
│       └── utils/                # Utilities and shared helpers
│           ├── __init__.py
│           └── logging_config.py # Rotating logger configuration (Implemented)
├── tests/
│   ├── __init__.py
│   ├── unit/                     # Unit test suite (115 passing tests)
│   │   ├── test_collector_models.py
│   │   ├── test_config.py
│   │   ├── test_database.py
│   │   ├── test_events.py
│   │   ├── test_incidents.py
│   │   ├── test_logging.py
│   │   ├── test_root_registry.py
│   │   ├── test_telemetry.py
│   │   ├── test_windows_parser.py
│   │   └── test_windows_watcher.py
│   ├── integration/              # Integration tests (9 passing tests)
│   │   ├── test_foundation_integration.py
│   │   └── test_windows_watcher_integration.py
│   └── fixtures/                 # Labelled JSONL test traces (Planned)
├── scripts/                      # Utility and benchmark scripts
├── .env.example                  # Example environment configuration
├── .gitignore                    # Git ignore specifications
├── pyproject.toml                # Project packaging and tool configuration
├── requirements.txt              # Editable development dependencies (-e .[dev])
├── README.md                     # Project overview and documentation
└── LICENSE                       # Project license (MIT)
```

---

## 6. Technical Documentation Index

For in-depth technical specifications, consult the documents in the [`docs/`](docs/) directory:

- [**System Architecture & Technical Design (`docs/architecture.md`)**](docs/architecture.md): Subsystem responsibilities, data flow diagrams, SQLite WAL configuration, and component decoupling.
- [**Security Threat Model (`docs/threat-model.md`)**](docs/threat-model.md): Detailed STRIDE analysis, 16 threat scenarios, trust boundaries, tamper resilience, and explicit defensive limitations.
- [**Behavioural Detection Model (`docs/detection-model.md`)**](docs/detection-model.md): Detailed analysis of the 10 planned signal families, normalized risk scoring formula, severity gates, and explainability mechanisms.
- [**Detection Benchmark & Validation Methodology (`docs/benchmark-methodology.md`)**](docs/benchmark-methodology.md): Empirical test corpus, benign workload matrix, acceptance targets, precision/recall metrics, and reproducibility guidelines.

---

## 7. Development Setup Instructions

### Prerequisites
- **Operating System:** 64-bit Windows 11 (Windows 10 with Python 3.12+ also supported for development).
- **Python:** Version `3.12` or later (tested on Python `3.14`).
- **Git:** Standard git client.

### Step-by-Step Setup

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/Swashbuckler16/Kuyebiko.git
   cd Kuyebiko
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Upgrade packaging tools and install in editable mode:**
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -e ".[dev]"
   ```

4. **Verify package import:**
   ```powershell
   python -c "import kuyebiko; print(kuyebiko.__file__)"
   ```

---

## 8. How to Run the Tests & Continuous Integration

### 8.1 Local Test Execution

Ensure your virtual environment is activated before running tests.

#### Run Unit Tests Only
```powershell
python -m pytest tests/unit -v
```

#### Run Integration Tests Only
```powershell
python -m pytest tests/integration -v
```

#### Run the Full Test Suite
```powershell
python -m pytest -v
```

#### Generate Coverage Reports (Terminal & XML)
```powershell
python -m pytest --cov=kuyebiko --cov-report=term-missing --cov-report=xml
```
*Outputs a terminal summary with line-level gaps and generates a temporary `coverage.xml` file (git-ignored).*

### 8.2 Code Quality & Style Checks (Ruff)
```powershell
# Verify lint rules (E, F, I, B, UP)
python -m ruff check .

# Verify code formatting compliance
python -m ruff format --check .

# Automatically apply safe code formatting
python -m ruff format .
```

### 8.3 Continuous Integration (GitHub Actions)

Kuyebiko enforces automated testing on every push and pull request via [`.github/workflows/tests.yml`](.github/workflows/tests.yml):

- **Triggers:** Automatically runs on all pushes to `main`, pull requests targeting `main`, or manual triggers (`workflow_dispatch`).
- **Runner Environment:** Windows-native (`windows-latest`), matching Kuyebiko's primary deployment target.
- **Python Compatibility Matrix:** Tests independently across all supported Python versions:
  - Python `3.12`
  - Python `3.13`
  - Python `3.14`
- **Execution Pipeline:**
  1. Checks out repository source.
  2. Sets up Python version from the matrix.
  3. Upgrades `pip` and installs package in editable mode (`python -m pip install -e ".[dev]"`).
  4. Runs `ruff check .` to enforce lint standards without suppression.
  5. Runs `ruff format --check .` to verify clean formatting.
  6. Executes the complete test suite with coverage (`pytest --cov=kuyebiko --cov-report=xml`).
  7. Publishes `coverage.xml` as a build artifact for forensic audit.
- **Fail-Safe Integrity:** The workflow does not use `continue-on-error: true`; any lint, format, or test failure blocks the PR.

### 8.4 Phase 3 Empirical Performance Baselines

Performance benchmarking was conducted on a reference 64-bit Windows 11 host (AMD64, CPython 3.14.4) using `scripts/measure_phase3_performance.py`:

| Benchmark Scenario | Metric | Measured Result |
| :--- | :--- | :--- |
| **Scenario 1: Normal Activity** | Single-Worker Throughput | **16,018 – 17,512 events/sec** |
| | Average Pipeline Latency | **33.6 – 41.8 ms** |
| | P50 / P95 / P99 Latency | **32.2 ms / 52.4 ms / 54.8 ms** |
| | CPU Utilization | ~0.10s CPU time per 2,000 events |
| **Scenario 2: High-Volume Burst** | Burst Volume into Cap 1,000 | 5,000 notifications submitted |
| | Backpressure Handling | 100% accounted (accepted + exact drops) |
| | Burst Drain & Recovery Time | **203 – 291 ms** to zero queue depth |
| **Scenario 3: Multi-Root Activity**| 4 Concurrent Watcher Threads | **16,365 – 16,775 events/sec** aggregate |
| | Out-of-Order Observations | **0 retrograde events** detected |
| **Scenario 4: Conservative Dedup** | Duplicate Write Stream (40% dup) | 1,000 duplicate events suppressed |
| | Pipeline Speedup | **~11 – 19% faster** (bypasses normalizer/consumer) |
| **Scenario 5: Fault & Recovery**  | Simulated Consumer Failures | 100% delivered after bounded retry |
| | Pipeline Worker Restart Latency | **0.50 ms** |
| **Memory Footprint** | Heap Allocation (tracemalloc) | **1.16 MB baseline / 3.76 MB peak** |

---

## 9. Security Scope & Explicit Limitations

Kuyebiko is engineered as a defensive, privacy-preserving visibility aid, but operates under strict technical boundaries:

1. **User-Mode Boundary:** A user-mode security application **cannot** guarantee survival against an adversary possessing local administrator or Windows kernel-level (ring 0) privileges.
2. **Local Hash Chain Boundary:** A local cryptographic hash chain detects row modification or deletion within a sequence, but cannot prevent an attacker with full filesystem permissions from deleting the database or rewriting it with recalculated hashes.
3. **Notification Buffer Drops:** Windows filesystem change notifications (`ReadDirectoryChangesW`) rely on fixed-size OS kernel buffers. Massive file bursts may overflow these buffers. Kuyebiko reports this as `is_degraded = True` (`ERROR_NOTIFY_ENUM_DIR` (1022)), but cannot recreate events dropped by the OS.
4. **No Process Attribution from ReadDirectoryChangesW:** The native Windows filesystem notification API (`ReadDirectoryChangesW`) delivers filesystem action records (add, remove, modify, rename) but **does not** provide the originating Process Identifier (PID) or process image name. Process attribution requires correlating filesystem events with dedicated process telemetry (e.g., Event Tracing for Windows (ETW) or Sysmon).
5. **Heuristic Nature:** Behavioural detection is heuristic. It may produce false alarms during intense benign batch operations (compilers, photo converters) and may fail to detect low-frequency, throttled encryption (low-and-slow evasion).
6. **Not Antivirus or EDR:** Kuyebiko does not quarantine files, block processes, inject into foreign executables, or modify Windows ACLs in MVP. It is designed to complement—not replace—Microsoft Defender.
7. **Zero Prevention Guarantee:** Kuyebiko provides monitoring and investigation visibility. It does **not** guarantee that file encryption will be prevented, nor does it recover damaged files.

---

## 10. Project Roadmap Summary

- **Phase 0 — Foundation:** Repository scaffolding, packaging configuration, and threat model establishment. *(Complete)*
- **Phase 1 — Core Models & Infrastructure:** Data schemas, Pydantic validation, async SQLite WAL engine, rotating logger, and technical documentation. *(Complete)*
- **Phase 2 — Windows Filesystem Monitoring MVP:**
  - **Phase 2.1 — Watcher Architecture:** Abstract `BaseWatcher`, `MonitoredRoot`, `RawFileNotification`, and normalized event adapters. *(Complete)*
  - **Phase 2.2 — Native Windows Watcher:** `ReadDirectoryChangesW` watcher, `ctypes` bindings, buffer parser, worker thread, `CancelIoEx` shutdown, and telemetry degradation handling. *(Complete)*
  - **Phase 2.3 — Monitored Roots Registry:** Multi-root registry, duplicate rejection, thread safety, and lifecycle management. *(Complete)*
  - **Phase 2.4 — Hardened Collectors & Parsers:** Buffer boundary validation, overflow metrics, and regression testing. *(Complete)*
- **Phase 3 — Event Processing & Normalization:**
  - Bounded queue backpressure, non-blocking ingestion, single worker thread, conservative deduplication (with TTL), ordering tracking, unified telemetry snapshot, and lifecycle management (`EventPipeline`). *(Complete)*
- **Phase 4 — Behavioural Detection MVP:** Sliding time-window correlation, 10 signal evaluators, normalized scoring formulas, and relational incident persistence. *(Next Step)*
- **Phase 5 — Presentation & Integrity:** PySide6 desktop dashboard, incident timeline inspector, cryptographic hash chaining, and sandboxed test simulator.
- **Phase 6 — Validation & Benchmark:** Labelled synthetic corpus validation, benign workload matrix evaluation, and empirical metric publishing.
- **Phase 7 — Public Release:** Installer packaging, user guide, demonstration assets, and open-source release.

---

## 11. Author, Code Owner & License

- **Code Owner & Primary Contributor:** **Atharva Ghag** ([@Swashbuckler16](https://github.com/Swashbuckler16)) <`atharva.vinod.ghag@gmail.com`>
- **License:** Distributed under the **GNU General Public License v3.0 (GNU GPL v3.0)**. See the [`LICENSE`](LICENSE) and [`AUTHORS.md`](AUTHORS.md) files for complete terms and attribution details.

---

## 12. Disclaimer & Safety Notice

> **Disclaimer:** Kuyebiko is an experimental, defensive behavioural monitoring tool. It is **not** antivirus software, does **not** guarantee prevention of ransomware infections, and **cannot** decrypt or restore files once modified. Always maintain active endpoint protection (e.g., Microsoft Defender) and verified offline backups.
