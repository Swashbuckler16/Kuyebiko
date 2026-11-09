# KUYEBIKO — PHASE 5 PROGRESS REPORT
## Advanced Behaviour Detection Modules: Steps 5.1 to 5.5

**Project:** Kuyebiko — Local-First Windows Ransomware Behaviour Monitoring & Investigation  
**Repository:** https://github.com/Swashbuckler16/Kuyebiko  
**Date:** 2026-11-09  
**Branch:** `main`  
**License:** GNU General Public License v3.0 (GNU GPL v3.0)  
**Code Owner & Contributor:** Atharva Ghag (`@Swashbuckler16`, `atharva.vinod.ghag@gmail.com`)  

---

## 1. Executive Summary

This deliverable accomplishes two core milestones:
1. **Resolution of Phase 4 Targeted Audit Findings:** Fully addresses and verifies all four findings identified in the post-Phase 4 audit, specifically constraining rename correlation provenance, establishing explicit duplicate delivery defenses in the sliding window, and reconciling phase naming across project documentation.
2. **Implementation of Phase 5 Steps 5.1 through 5.5:** Implements the Advanced Behaviour Detection Subsystem, introducing formal telemetry capability contracts (`TelemetryCapability`, `SignalMetadata`, `AdvancedSignalEvaluator`), extended telemetry models, and four MITRE ATT&CK-aligned behaviour modules (T1490 Recovery Inhibition, T1485 Data Destruction, T1083 Filesystem Discovery, and T1070 Indicator Removal).

---

## 2. Part 1 — Resolution of Phase 4 Audit Findings

### Issue 1 & 3: Constrained Typed Rename Provenance
- **Problem:** `FileEvent.correlation_provenance` previously accepted arbitrary free-form strings, allowing unverified explicit pairs (`explicit_pair:<old>-><new>`) or forged inputs to bypass the intended correlation check and inflate `FS_RENAME_RATIO`.
- **Implementation:**
  - Defined `CorrelationProvenanceType(StrEnum)` in `src/kuyebiko/models/events.py` with typed origins: `PHASE3_CORRELATOR`, `RENAME_CORRELATOR`, `SIMULATOR`, `EXPLICIT_PAIR`, and `UNTRUSTED`.
  - Added strict Pydantic field validation on `FileEvent.correlation_provenance`: rejects arbitrary or malformed strings that do not conform to approved formats.
  - Implemented `is_approved_rename_provenance()`: only `phase3_correlator`, `rename_correlator`, and `simulator` qualify for detection. Uncorrelated `explicit_pair` events are accepted for raw pipeline flow but strictly excluded from `rename_pairs_count` and `FS_RENAME_RATIO`.
  - Updated `SlidingEventWindow` and `RenameRatioSignalEvaluator` to enforce `is_approved_rename_provenance()`.

### Issue 2: Duplicate Delivery Testing & Sliding Window Defense
- **Problem:** Tests verified counter consistency across distinct pairs, but did not formally demonstrate replay of identical event IDs or delineate Phase 3 deduplication from Phase 4 window responsibilities.
- **Implementation:**
  - Added active event ID tracking (`self._active_event_ids: set[str]`) in `RootSlidingWindow` (`src/kuyebiko/detection/window.py`). Replayed event IDs are rejected in O(1) time without mutating window counters or event sequences.
  - Delineated boundaries:
    - **Phase 3 `EventDeduplicator`:** Filters duplicate `RawFileNotification` deliveries from Windows kernel buffers before queuing/normalization.
    - **Phase 4 `RootSlidingWindow`:** Filters replayed `FileEvent` IDs within the active sliding correlation window.
    - **Legitimate Repeated Operations:** Legitimate renames of the same file (e.g. `doc.txt` -> `doc.tmp` -> `doc.locked`) carry distinct `event_id`s and timestamps, and are tracked accurately.
  - Added comprehensive test cases in `tests/unit/test_rename_provenance.py`.

### Issue 4: Roadmap Documentation Consistency
- Reconciled Phase 5 scope across all documentation to consistently represent **Phase 5: Advanced Detection Modules** (with incident management, risk scoring, and desktop UI retained in their scheduled later phases).

---

## 3. Part 2 — Implementation of Phase 5 Steps 5.1 to 5.5

### Step 5.1 — Advanced Detection Architecture & Contracts
- **Telemetry Capability Separation:** Implemented `TelemetryCapability(StrEnum)` distinguishing:
  - `FILESYSTEM_METADATA`: Standard `ReadDirectoryChangesW` change notifications.
  - `PROCESS_EXECUTION`: Process launch and command-line execution telemetry.
  - `EVENT_LOG`: Windows Event Log security and system channels.
  - `FILESYSTEM_READ_ACCESS`: File read operations and directory enumeration.
- **Contract Boundary:** Created `SignalMetadata` and `AdvancedSignalEvaluator` in `src/kuyebiko/detection/advanced/contracts.py`. If a signal requires capabilities missing from the runtime context, it automatically returns `triggered = False`, `severity = 0.0`, and documents the specific limitation in `metadata["capability_limitation"]`.
- **Extended Telemetry Models:** Defined `ProcessTelemetryEvent`, `EventLogTelemetryEvent`, and `DiscoveryTelemetryEvent`.

### Step 5.2 — Recovery Inhibition Detection (MITRE ATT&CK T1490)
- **Signal Evaluator:** `RecoveryInhibitionSignalEvaluator` (`FS_RECOVERY_INHIBITION`).
- **Filesystem Observable:** Detects deletion or destructive modification of recovery images, shadow copy stores, and backup catalogs (`System Volume Information`, `WindowsImageBackup`, `.vhd`, `.vhdx`, `.bkf`, `.wbcat`).
- **Process Observable:** Correlates recovery command executions (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set ... recoveryenabled no`).
- **Capability Limitation:** When process telemetry is absent, records explicit capability limitation while inspecting filesystem paths.

### Step 5.3 — Mass Data Destruction Detection (MITRE ATT&CK T1485)
- **Signal Evaluator:** `DataDestructionSignalEvaluator` (`FS_DATA_DESTRUCTION`).
- **Behavioral Discrimination:** Requires high deletion volume (`>= 15` deletions) spanning multiple distinct directory branches (`>= 3` directories), avoiding false positives on single-folder cleanups.
- **Benign Cleanup Isolation:** Mass deletions strictly confined to temporary or build directories (`temp`, `tmp`, `node_modules`, `build`, `target`, `.cache`) are recognized as benign developer/OS cleanups and do not trigger.

### Step 5.4 — Filesystem Discovery Detection (MITRE ATT&CK T1083)
- **Signal Evaluator:** `FilesystemDiscoverySignalEvaluator` (`FS_FILESYSTEM_DISCOVERY`).
- **Capability Requirement:** Strictly requires `TelemetryCapability.FILESYSTEM_READ_ACCESS`.
- **Truthful Telemetry Boundary:** Change notifications (`ReadDirectoryChangesW`) do not observe directory reads or enumeration. Operating without read-access telemetry produces an explicit capability limitation, avoiding fabricated detections.
- **Enumeration Analysis:** When read-access telemetry is provided, evaluates directory breadth and velocity while attributing benign system indexers (`SearchIndexer.exe`, `explorer.exe`).

### Step 5.5 — Indicator Removal & Security Log Tampering (MITRE ATT&CK T1070)
- **Signal Evaluator:** `IndicatorRemovalSignalEvaluator` (`FS_INDICATOR_REMOVAL`).
- **Filesystem Observable:** Detects direct deletion of primary event logs (`Security.evtx`, `System.evtx`), NTFS USN journals (`$LogFile`, `$UsnJrnl`), or local audit databases (`kuyebiko.db`).
- **Extended Observable:** Correlates with Windows Event Log clear records (Event 1102 / 104) and process commands (`wevtutil cl`).
- **Benign Rotation:** Distinguishes routine archive rotation (`Archive-*.evtx`) from hostile log tampering.

---

## 4. Verification & Test Metrics

### Test Suite Summary
- **Total Tests:** **359 passed in 9.28s** (100% pass rate).
- **Coverage:** **94% statement coverage** across 3,441 statements.
- **Linter & Formatter:** `ruff check .` (0 errors) and `ruff format --check .` (111 files clean).

### Test Suite Breakdown
| Component | Test File | Test Count | Pass Rate |
| :--- | :--- | :---: | :---: |
| Advanced Contracts (5.1) | `tests/unit/test_advanced_contracts.py` | 6 | 100% |
| Recovery Inhibition (5.2) | `tests/unit/test_recovery_inhibition.py` | 5 | 100% |
| Data Destruction (5.3) | `tests/unit/test_data_destruction.py` | 5 | 100% |
| Filesystem Discovery (5.4) | `tests/unit/test_filesystem_discovery.py` | 5 | 100% |
| Indicator Removal (5.5) | `tests/unit/test_indicator_removal.py` | 6 | 100% |
| Advanced Integration | `tests/integration/test_advanced_detection_integration.py` | 4 | 100% |
| Rename Provenance (Hardened) | `tests/unit/test_rename_provenance.py` | 12 | 100% |
| Sliding Window & Recovery | `tests/unit/test_sliding_window.py` | 14 | 100% |
| Foundational Signals & Engine | `tests/unit/test_detection_signals.py`, `tests/integration/*` | 302 | 100% |
| **Total** | **All 39 test suites** | **359** | **100%** |

---

## 5. Scope Boundary Notice

In strict accordance with the user instructions:
- **Steps 5.1 through 5.5 and Phase 4 audit items are complete, verified, and committed.**
- **Steps 5.6 through 5.8 (Low-and-Slow Detection, Multi-Signal Correlation, and Sign-off Benchmarks) have NOT been started and await explicit authorization.**
