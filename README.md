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

Kuyebiko is actively under development. Below is the verified status of the codebase at **Phase 1, Step 11**:

### Implemented Functionality (Tested & Active)
- **Domain Data Models (`src/kuyebiko/models/`):**
  - `FileEvent`: Normalized filesystem event schema enforcing UTC timezones, monotonic timestamps, relative path normalization, path traversal prevention (`..`), absolute path rejection, and rename path pairing.
  - `SecurityIncident`: Incident alert model enforcing 0–100 risk score bounds, unique evidence IDs, unique signal family lists, chronological ordering, and categorical severity/confidence ratings.
  - `TelemetrySnapshot`: Operational health model tracking queue capacity, queue depth, dropped event counters, collector states, and validated degradation reasons.
- **Application Configuration (`src/kuyebiko/core/config.py`):**
  - `KuyebikoSettings`: Central configuration managed via `pydantic-settings` supporting `.env` files and `KUYEBIKO_` environment variable overrides with validation bounds.
- **Database Infrastructure (`src/kuyebiko/storage/database.py`):**
  - Asynchronous SQLite connection management via SQLAlchemy 2.0 and `aiosqlite`.
  - Automatic PRAGMA configuration: `PRAGMA journal_mode = WAL`, `PRAGMA busy_timeout = 30000`, `PRAGMA foreign_keys = ON`, `PRAGMA synchronous = NORMAL`.
  - Connectivity initialization (`initialize()`), active connection health checks (`health_check()`), and built-in database integrity checks (`integrity_check()`).
- **Centralized Diagnostic Logging (`src/kuyebiko/utils/logging_config.py`):**
  - Rotating file logger (`5 MB` max size, `5` backup archives) and stream console logger with clean formatting and shutdown handlers.
- **Test Suite (`tests/`):**
  - **53 comprehensive unit tests** (`tests/unit/`) validating data models, edge-case rejection (naive timestamps, traversal, path mismatches), configuration boundaries, database lifecycle, and logging handlers.
  - **5 foundation integration tests** (`tests/integration/`) verifying cross-component integration across configuration, asynchronous SQLite WAL sessions, Pydantic JSON serialization, and centralized logging.
  - **58 total passing tests** with **98% overall code coverage**.

### Partially Implemented Functionality
- **Package Architecture:** Modular package structure established under `src/kuyebiko/` with package initializers (`collectors`, `processing`, `detection`, `integrity`, `application`).

### Planned Functionality (Next Phases)
- **Windows Filesystem Watcher (`collectors/`):** Native Windows `ReadDirectoryChangesW` asynchronous event capture.
- **Event Processing Queue (`processing/`):** Bounded ingestion ring buffers, drop counters, and backpressure management.
- **Behavioural Detection Engine (`detection/`):** Sliding time-window correlation, 10 signal evaluators, and normalized scoring formulas.
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
| **Telemetry Ingestion** | Internal Pydantic schema validation | Windows `ReadDirectoryChangesW`, Sysmon adapter |
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
│       │   └── exceptions.py     # Domain exceptions (planned)
│       ├── models/               # Domain Pydantic schemas (Implemented)
│       │   ├── __init__.py
│       │   ├── events.py         # FileEvent, EventType, EventSource
│       │   ├── incidents.py      # SecurityIncident, IncidentSeverity
│       │   └── telemetry.py      # TelemetrySnapshot, MonitoringStatus
│       ├── collectors/           # Windows watchers and telemetry adapters (Planned)
│       ├── processing/           # Normalization and bounded event queue (Planned)
│       ├── detection/            # Signal evaluators and scoring engine (Planned)
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
│   ├── unit/                     # Unit test suite (53 passing tests)
│   │   ├── test_config.py
│   │   ├── test_database.py
│   │   ├── test_events.py
│   │   ├── test_incidents.py
│   │   ├── test_logging.py
│   │   └── test_telemetry.py
│   ├── integration/              # Integration tests (5 passing tests)
│   │   └── test_foundation_integration.py
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

---

## 9. Security Scope & Explicit Limitations

Kuyebiko is engineered as a defensive, privacy-preserving visibility aid, but operates under strict technical boundaries:

1. **User-Mode Boundary:** A user-mode security application **cannot** guarantee survival against an adversary possessing local administrator or Windows kernel-level (ring 0) privileges.
2. **Local Hash Chain Boundary:** A local cryptographic hash chain detects row modification or deletion within a sequence, but cannot prevent an attacker with full filesystem permissions from deleting the database or rewriting it with recalculated hashes.
3. **Notification Buffer Drops:** Windows filesystem change notifications (`ReadDirectoryChangesW`) rely on fixed-size OS kernel buffers. Massive file bursts may overflow these buffers. Kuyebiko reports this as `DEGRADED`, but cannot recreate events dropped by the OS.
4. **Heuristic Nature:** Behavioural detection is heuristic. It may produce false alarms during intense benign batch operations (compilers, photo converters) and may fail to detect low-frequency, throttled encryption (low-and-slow evasion).
5. **Not Antivirus or EDR:** Kuyebiko does not quarantine files, block processes, inject into foreign executables, or modify Windows ACLs in MVP. It is designed to complement—not replace—Microsoft Defender.
6. **Zero Prevention Guarantee:** Kuyebiko provides monitoring and investigation visibility. It does **not** guarantee that file encryption will be prevented, nor does it recover damaged files.

---

## 10. Project Roadmap Summary

- **Phase 0 — Foundation:** Repository scaffolding, packaging configuration, and threat model establishment. *(Complete)*
- **Phase 1 — Core Models & Infrastructure:** Data schemas, Pydantic validation, async SQLite WAL engine, rotating logger, and technical documentation. *(Complete — Current Step)*
- **Phase 2 — Ingestion & Monitoring MVP:** Windows `ReadDirectoryChangesW` watcher, bounded event queue with backpressure, and source health tracking.
- **Phase 3 — Behavioural Detection MVP:** Rolling window correlator, 10 signal evaluators, normalized scoring engine, and relational incident persistence.
- **Phase 4 — Presentation & Integrity:** PySide6 desktop dashboard, incident timeline inspector, cryptographic hash chaining, and sandboxed test simulator.
- **Phase 5 — Validation & Benchmark:** Labelled synthetic corpus validation, benign workload matrix evaluation, and empirical metric publishing.
- **Phase 6 — Public Release:** Installer packaging, user guide, demonstration assets, and open-source release.

---

## 11. Disclaimer & Safety Notice

> **Disclaimer:** Kuyebiko is an experimental, defensive behavioural monitoring tool. It is **not** antivirus software, does **not** guarantee prevention of ransomware infections, and **cannot** decrypt or restore files once modified. Always maintain active endpoint protection (e.g., Microsoft Defender) and verified offline backups.
