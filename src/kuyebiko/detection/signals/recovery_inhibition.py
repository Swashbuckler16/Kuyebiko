"""FS_RECOVERY_INHIBITION: Recovery Inhibition behavioural signal evaluator (T1490).

Detects attempts to inhibit system recovery via filesystem mutations directed at
recovery catalogs, shadow storage, and backup images, with optional correlation
of process execution telemetry (e.g. vssadmin, wbadmin, bcdedit).
"""

import posixpath
import re
from typing import Any

from kuyebiko.detection.advanced.contracts import (
    AdvancedSignalEvaluator,
    ProcessTelemetryEvent,
    SignalMetadata,
    TelemetryCapability,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.models.events import EventType

# Known filesystem path patterns and extensions associated with Windows recovery
_STRONG_RECOVERY_PATHS = (
    "system volume information",
    "windowsimagebackup",
    "recovery/windowsre",
)

_STRONG_RECOVERY_EXTENSIONS = {
    ".bkf",
    ".wbcat",
    ".vss",
    ".shadow",
    ".tib",  # Acronis backup
    ".vbk",  # Veeam backup
}

# Weak recovery indicators that routinely occur in non-attack scenarios
_WEAK_RECOVERY_PATHS = (
    "$recycle.bin",  # Routine desktop deletion / bin emptying
)

_WEAK_RECOVERY_EXTENSIONS = {
    ".vhd",  # Routine virtual disk modifications
    ".vhdx",
}

# Suspicious recovery command line regexes
_RECOVERY_COMMAND_PATTERNS = [
    re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE),
    re.compile(
        r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)", re.IGNORECASE
    ),
    re.compile(r"bcdedit(\.exe)?\s+/set.*recoveryenabled\s+no", re.IGNORECASE),
    re.compile(
        r"bcdedit(\.exe)?\s+/set.*bootstatuspolicy\s+ignoreallfailures", re.IGNORECASE
    ),
    re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE),
    re.compile(r"powershell.*(win32_shadowcopy|delete-shadowcopy)", re.IGNORECASE),
]


class RecoveryInhibitionSignalEvaluator(AdvancedSignalEvaluator):
    """Evaluates recovery inhibition behaviours under MITRE ATT&CK T1490."""

    def __init__(
        self,
        threshold: float = 1.0,  # Minimum recovery mutation count or command match
        is_enabled: bool = True,
    ) -> None:
        metadata = SignalMetadata(
            signal_id="FS_RECOVERY_INHIBITION",
            name="Inhibit System Recovery",
            family=SignalFamily.RECOVERY_INTERFERENCE,
            mitre_technique="T1490",
            description=(
                "Detects deletion or corruption of system recovery artifacts, "
                "shadow copy backups, or execution of recovery-disabling tools."
            ),
            required_capabilities=[TelemetryCapability.FILESYSTEM_METADATA],
            optional_capabilities=[TelemetryCapability.PROCESS_EXECUTION],
            evidence_requirements=(
                "Deletion/modification of recovery paths (.bkf, .wbcat, "
                "WindowsImageBackup, System Volume Information) or process execution."
            ),
            confidence_limitations=(
                "Filesystem notifications alone cannot verify command-line arguments; "
                "full process attribution requires PROCESS_EXECUTION capability. "
                "Weak indicators (.vhd, $Recycle.Bin) require strong corroboration."
            ),
            threshold=threshold,
            default_threshold=1.0,
            min_events=1,
        )
        super().__init__(metadata=metadata, is_enabled=is_enabled)

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Evaluate filesystem mutations and optional process telemetry."""
        strong_recovery_events = []
        weak_recovery_events = []

        for e in context.events:
            # We look for destructive actions on recovery artifacts
            if e.event_type not in (EventType.DELETED, EventType.MODIFIED):
                continue

            path_norm = e.file_path.lower().replace("\\", "/")
            _, ext = posixpath.splitext(path_norm)

            if ext in _STRONG_RECOVERY_EXTENSIONS or any(
                pat in path_norm for pat in _STRONG_RECOVERY_PATHS
            ):
                strong_recovery_events.append(e)
            elif ext in _WEAK_RECOVERY_EXTENSIONS or any(
                pat in path_norm for pat in _WEAK_RECOVERY_PATHS
            ):
                weak_recovery_events.append(e)

        strong_fs_count = len(strong_recovery_events)
        weak_fs_count = len(weak_recovery_events)

        # Process execution telemetry strictly if capability is available
        proc_telemetry_available = self.is_capability_available(
            TelemetryCapability.PROCESS_EXECUTION, context
        )

        matched_commands: list[dict[str, Any]] = []
        rejected_proc: list[dict[str, Any]] = []

        if proc_telemetry_available:
            raw_proc: list[ProcessTelemetryEvent] = context.config.get(
                "process_events", []
            )
            scoped_proc, rejected_proc = self.scope_auxiliary_telemetry(
                raw_proc, context
            )
            for p in scoped_proc:
                cmd = p.command_line
                for pattern in _RECOVERY_COMMAND_PATTERNS:
                    if pattern.search(cmd):
                        matched_commands.append(
                            {
                                "event_id": p.event_id,
                                "process_name": p.process_name,
                                "command_line": p.command_line,
                            }
                        )
                        break

        proc_count = len(matched_commands)
        strong_evidence_count = strong_fs_count + proc_count

        # Weak indicators must NOT trigger on their own
        if strong_evidence_count >= self.threshold:
            triggered = True
            severity = 0.85 if proc_count > 0 else 0.70
            if strong_fs_count > 3:
                severity = min(1.0, severity + 0.15)
        elif strong_evidence_count == 0 and weak_fs_count >= 5:
            # Elevated weak indicators can trigger with heavy discount
            triggered = True
            severity = 0.40
        else:
            triggered = False
            severity = 0.0

        total_evidence_count = strong_evidence_count + (
            weak_fs_count if triggered else 0
        )

        evidence_ids = (
            [e.event_id for e in strong_recovery_events]
            + [e.event_id for e in weak_recovery_events if triggered]
            + [m["event_id"] for m in matched_commands]
        )

        if triggered:
            details = []
            if strong_fs_count > 0:
                details.append(
                    f"{strong_fs_count} strong recovery filesystem mutations "
                    f"([e.g. {strong_recovery_events[0].file_path}])"
                )
            if weak_fs_count > 0:
                details.append(
                    f"{weak_fs_count} weak recovery indicators "
                    f"([e.g. {weak_recovery_events[0].file_path}])"
                )
            if proc_count > 0:
                details.append(
                    f"{proc_count} recovery inhibition commands "
                    f"([e.g. {matched_commands[0]['process_name']}])"
                )
            explanation = (
                f"Recovery inhibition behaviour detected (T1490): {'; '.join(details)}"
            )
        else:
            explanation = (
                "No observable recovery inhibition activity detected in window"
            )

        telemetry_state = {
            "filesystem_metadata": (
                "evidence_observed"
                if (strong_fs_count + weak_fs_count) > 0
                else "clean"
            ),
            "process_execution": (
                ("evidence_observed" if proc_count > 0 else "clean")
                if proc_telemetry_available
                else "unavailable"
            ),
        }

        metadata: dict[str, Any] = {
            "recovery_filesystem_events": strong_fs_count + weak_fs_count,
            "strong_recovery_events": strong_fs_count,
            "weak_recovery_events": weak_fs_count,
            "recovery_command_events": proc_count,
            "process_telemetry_available": proc_telemetry_available,
            "telemetry_state": telemetry_state,
            "rejected_auxiliary_events_count": len(rejected_proc),
            "mitre_technique": "T1490",
        }
        if not proc_telemetry_available:
            metadata["capability_limitation"] = (
                "Command-line execution (e.g. vssadmin) requires "
                "PROCESS_EXECUTION capability; only filesystem metadata observed"
            )

        return self._create_result(
            triggered=triggered,
            observed_metric=float(total_evidence_count),
            explanation=explanation,
            severity_score=severity,
            evidence_event_ids=evidence_ids if triggered else [],
            metadata=metadata,
        )
