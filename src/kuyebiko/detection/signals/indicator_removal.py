"""FS_INDICATOR_REMOVAL: Indicator Removal & Security Log Tampering (T1070).

Detects attempts to destroy forensic evidence, event logs (.evtx), USN journals,
or security audit trails, with support for correlated Windows Event Log telemetry
(e.g. Event ID 1102 / 104) and process execution commands (wevtutil).
"""

import posixpath
import re
from typing import Any

from kuyebiko.detection.advanced.contracts import (
    AdvancedSignalEvaluator,
    EventLogTelemetryEvent,
    ProcessTelemetryEvent,
    SignalMetadata,
    TelemetryCapability,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.models.events import EventType

# Critical event log and forensic paths targeted by ransomware
_CRITICAL_LOG_PATTERNS = (
    "winevt/logs",
    "security.evtx",
    "system.evtx",
    "application.evtx",
    "$logfile",
    "$usnjrnl",
    "kuyebiko.db",
    "kuyebiko.log",
)

_COMMAND_CLEAR_PATTERNS = [
    re.compile(r"wevtutil(\.exe)?\s+(cl|clear-log)", re.IGNORECASE),
    re.compile(r"clear-eventlog", re.IGNORECASE),
    re.compile(r"fsutil(\.exe)?\s+usn\s+deletejournal", re.IGNORECASE),
]

_CRITICAL_EVENT_CODES = {
    1102,  # The audit log was cleared (Security)
    104,  # The log file was cleared (System)
}


class IndicatorRemovalSignalEvaluator(AdvancedSignalEvaluator):
    """Detects indicator and log removal behaviours under MITRE ATT&CK T1070."""

    def __init__(
        self,
        threshold: float = 1.0,  # Minimum evidence count to trigger
        is_enabled: bool = True,
    ) -> None:
        metadata = SignalMetadata(
            signal_id="FS_INDICATOR_REMOVAL",
            name="Indicator Removal on Host",
            family=SignalFamily.INDICATOR_REMOVAL,
            mitre_technique="T1070",
            description=(
                "Detects deletion of Windows event logs, USN journals, or forensic "
                "traces, and clearing of security event logs."
            ),
            required_capabilities=[TelemetryCapability.FILESYSTEM_METADATA],
            optional_capabilities=[
                TelemetryCapability.EVENT_LOG,
                TelemetryCapability.PROCESS_EXECUTION,
            ],
            evidence_requirements=(
                "Deletion of critical .evtx files, USN journals, event log clear "
                "events (Event ID 1102/104), or execution of wevtutil cl."
            ),
            confidence_limitations=(
                "Filesystem change notifications observe file deletions; "
                "command-line wevtutil clearing and in-memory log clearing require "
                "PROCESS_EXECUTION or EVENT_LOG capabilities."
            ),
            threshold=threshold,
            default_threshold=1.0,
            min_events=1,
        )
        super().__init__(metadata=metadata, is_enabled=is_enabled)

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Evaluate filesystem deletions, event logs, and process execution."""
        evidence_events = []

        # 1. Inspect filesystem deletions of critical logs
        for e in context.events:
            if e.event_type != EventType.DELETED or e.is_directory:
                continue

            path_norm = e.file_path.lower().replace("\\", "/")
            _, ext = posixpath.splitext(path_norm)

            is_target_log = False
            if ext == ".evtx":
                # Check if it's benign archive rotation vs primary log deletion
                filename = posixpath.basename(path_norm)
                if not filename.startswith("archive-"):
                    is_target_log = True
            elif any(pat in path_norm for pat in _CRITICAL_LOG_PATTERNS):
                is_target_log = True

            if is_target_log:
                evidence_events.append(e)

        fs_tampering_count = len(evidence_events)

        # 2. Check Windows Event Log telemetry if capability is available
        event_log_cap_available = self.is_capability_available(
            TelemetryCapability.EVENT_LOG, context
        )
        matched_event_logs: list[EventLogTelemetryEvent] = []
        rejected_event_logs: list[dict[str, Any]] = []

        if event_log_cap_available:
            raw_event_logs: list[EventLogTelemetryEvent] = context.config.get(
                "event_log_events", []
            )
            scoped_el, rejected_event_logs = self.scope_auxiliary_telemetry(
                raw_event_logs, context
            )
            for el in scoped_el:
                if el.event_code in _CRITICAL_EVENT_CODES:
                    matched_event_logs.append(el)

        event_log_count = len(matched_event_logs)

        # 3. Check Process execution telemetry if capability is available
        proc_cap_available = self.is_capability_available(
            TelemetryCapability.PROCESS_EXECUTION, context
        )
        matched_proc_commands: list[ProcessTelemetryEvent] = []
        rejected_procs: list[dict[str, Any]] = []

        if proc_cap_available:
            raw_proc: list[ProcessTelemetryEvent] = context.config.get(
                "process_events", []
            )
            scoped_proc, rejected_procs = self.scope_auxiliary_telemetry(
                raw_proc, context
            )
            for pe in scoped_proc:
                for pattern in _COMMAND_CLEAR_PATTERNS:
                    if pattern.search(pe.command_line):
                        matched_proc_commands.append(pe)
                        break

        proc_cmd_count = len(matched_proc_commands)
        total_evidence_count = fs_tampering_count + event_log_count + proc_cmd_count

        triggered = total_evidence_count >= self.threshold
        severity = 0.0
        if triggered:
            severity = 0.85
            if event_log_count > 0 or fs_tampering_count > 1:
                severity = 0.95

        evidence_ids = (
            [e.event_id for e in evidence_events]
            + [el.event_id for el in matched_event_logs]
            + [pe.event_id for pe in matched_proc_commands]
        )

        has_ext_telemetry = bool(event_log_cap_available or proc_cap_available)

        if triggered:
            parts = []
            if fs_tampering_count > 0:
                parts.append(
                    f"{fs_tampering_count} critical log/journal deletions "
                    f"([e.g. {evidence_events[0].file_path}])"
                )
            if event_log_count > 0:
                parts.append(
                    f"{event_log_count} log cleared events "
                    f"(Event ID {[el.event_code for el in matched_event_logs]})"
                )
            if proc_cmd_count > 0:
                parts.append(
                    f"{proc_cmd_count} log tampering command executions "
                    f"([e.g. {matched_proc_commands[0].process_name}])"
                )
            explanation = (
                f"Indicator removal / security log tampering detected (T1070): "
                f"{'; '.join(parts)}"
            )
        else:
            explanation = (
                "No observable indicator removal or security log tampering detected"
            )

        telemetry_state = {
            "filesystem_metadata": (
                "evidence_observed" if fs_tampering_count > 0 else "clean"
            ),
            "event_log": (
                ("evidence_observed" if event_log_count > 0 else "clean")
                if event_log_cap_available
                else "unavailable"
            ),
            "process_execution": (
                ("evidence_observed" if proc_cmd_count > 0 else "clean")
                if proc_cap_available
                else "unavailable"
            ),
        }

        total_rejected_aux = len(rejected_event_logs) + len(rejected_procs)

        metadata: dict[str, Any] = {
            "filesystem_tampering_count": fs_tampering_count,
            "event_log_clear_count": event_log_count,
            "process_clear_command_count": proc_cmd_count,
            "has_extended_telemetry": has_ext_telemetry,
            "telemetry_state": telemetry_state,
            "rejected_auxiliary_events_count": total_rejected_aux,
            "mitre_technique": "T1070",
        }
        if not has_ext_telemetry:
            metadata["capability_limitation"] = (
                "Command-line wevtutil clearing and in-memory log clearing "
                "require PROCESS_EXECUTION or EVENT_LOG capabilities; "
                "only filesystem deletions observed"
            )

        return self._create_result(
            triggered=triggered,
            observed_metric=float(total_evidence_count),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata=metadata,
        )
