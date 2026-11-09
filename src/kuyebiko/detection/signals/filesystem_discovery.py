"""FS_FILESYSTEM_DISCOVERY: Filesystem Discovery behavioural signal evaluator (T1083).

Enforces strict telemetry capability boundaries: explicitly declares that ordinary
Windows change notifications (ReadDirectoryChangesW) cannot observe directory reads
or enumeration. Requires dedicated read-access / filter-driver telemetry to evaluate.
"""

from typing import Any

from kuyebiko.detection.advanced.contracts import (
    AdvancedSignalEvaluator,
    DiscoveryTelemetryEvent,
    SignalMetadata,
    TelemetryCapability,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult

# Recognized system processes that routinely perform benign filesystem discovery
_BENIGN_DISCOVERY_PROCESSES = {
    "searchindexer.exe",
    "explorer.exe",
    "everything.exe",
    "msbuild.exe",
    "git.exe",
    "rg.exe",
}


class FilesystemDiscoverySignalEvaluator(AdvancedSignalEvaluator):
    """Detects rapid directory discovery and enumeration under MITRE ATT&CK T1083."""

    def __init__(
        self,
        min_directories: int = 15,  # Minimum unique directories enumerated
        threshold: float = 10.0,  # Minimum enumeration rate (dirs/sec)
        is_enabled: bool = True,
    ) -> None:
        metadata = SignalMetadata(
            signal_id="FS_FILESYSTEM_DISCOVERY",
            name="File and Directory Discovery",
            family=SignalFamily.FILESYSTEM_DISCOVERY,
            mitre_technique="T1083",
            description=(
                "Detects rapid, broad directory structure enumeration and "
                "reconnaissance. Requires read-access or filter-driver telemetry."
            ),
            required_capabilities=[TelemetryCapability.FILESYSTEM_READ_ACCESS],
            optional_capabilities=[TelemetryCapability.PROCESS_EXECUTION],
            evidence_requirements=(
                f"Enumeration of >= {min_directories} directories at rate >= "
                f"{threshold:.1f} dirs/sec via dedicated read/enumeration telemetry."
            ),
            confidence_limitations=(
                "ReadDirectoryChangesW cannot observe read or directory enumeration "
                "operations. Detections are only evaluated when FILESYSTEM_READ_ACCESS "
                "telemetry (e.g. minifilter or ETW read tracing) is available. "
                "Process attribution requires PROCESS_EXECUTION capability."
            ),
            threshold=threshold,
            default_threshold=10.0,
            min_events=min_directories,
        )
        super().__init__(metadata=metadata, is_enabled=is_enabled)
        self._min_directories = min_directories

    @property
    def min_directories(self) -> int:
        return self._min_directories

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Evaluate directory discovery with per-process attribution."""
        raw_discovery_events: list[DiscoveryTelemetryEvent] = context.config.get(
            "discovery_events", []
        )

        scoped_discovery_events, rejected_discovery = self.scope_auxiliary_telemetry(
            raw_discovery_events, context
        )

        proc_cap_available = self.is_capability_available(
            TelemetryCapability.PROCESS_EXECUTION, context
        )

        if not scoped_discovery_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    "Read-access telemetry enabled, but no directory enumeration "
                    "events observed in the current correlation window."
                ),
                severity_score=0.0,
                metadata={
                    "discovery_events_count": 0,
                    "rejected_auxiliary_events_count": len(rejected_discovery),
                    "telemetry_state": {
                        "filesystem_read_access": "clean",
                        "process_execution": (
                            "clean" if proc_cap_available else "unavailable"
                        ),
                    },
                    "mitre_technique": "T1083",
                },
            )

        window_duration = max(0.1, context.window_duration_seconds)

        # Group discovery events per process to ensure benign processes
        # (e.g. SearchIndexer) cannot mask concurrent suspicious discovery.
        events_by_proc: dict[str, list[DiscoveryTelemetryEvent]] = {}
        for de in scoped_discovery_events:
            proc_key = de.process_name.lower() if de.process_name else "<unattributed>"
            events_by_proc.setdefault(proc_key, []).append(de)

        offending_procs: list[dict[str, Any]] = []
        benign_suppressed_procs: list[str] = []
        offending_evidence_ids: list[str] = []

        max_offending_rate = 0.0

        for proc_name, procevents in events_by_proc.items():
            proc_dirs = {de.target_directory for de in procevents}
            proc_dir_count = len(proc_dirs)
            proc_rate = proc_dir_count / window_duration
            is_benign = proc_name in _BENIGN_DISCOVERY_PROCESSES

            if proc_dir_count >= self._min_directories and proc_rate >= self.threshold:
                if is_benign:
                    benign_suppressed_procs.append(proc_name)
                else:
                    offending_procs.append(
                        {
                            "process_name": proc_name,
                            "unique_directories": proc_dir_count,
                            "enumeration_rate": round(proc_rate, 2),
                        }
                    )
                    offending_evidence_ids.extend([e.event_id for e in procevents])
                    if proc_rate > max_offending_rate:
                        max_offending_rate = proc_rate

        # Check aggregate non-benign discovery across un-attributed/non-benign processes
        non_benign_events = [
            de
            for de in scoped_discovery_events
            if (de.process_name or "").lower() not in _BENIGN_DISCOVERY_PROCESSES
        ]
        non_benign_dirs = {de.target_directory for de in non_benign_events}
        non_benign_rate = len(non_benign_dirs) / window_duration

        triggered = (len(offending_procs) > 0) or (
            len(non_benign_dirs) >= self._min_directories
            and non_benign_rate >= self.threshold
        )

        observed_metric = max(max_offending_rate, non_benign_rate if triggered else 0.0)

        severity = 0.0
        if triggered:
            rate_factor = min(1.0, observed_metric / (self.threshold * 2))
            severity = min(1.0, 0.60 + 0.30 * rate_factor)

        if triggered:
            offending_names = [p["process_name"] for p in offending_procs] or [
                "<multiple-non-benign>"
            ]
            explanation = (
                f"Rapid filesystem discovery detected (T1083): "
                f"{len(non_benign_dirs)} unique directories enumerated at "
                f"{observed_metric:.1f} dirs/sec "
                f"(threshold: {self.threshold:.1f} dirs/sec; offending processes: "
                f"{offending_names[:3]})"
            )
            evidence_ids = (
                offending_evidence_ids
                if offending_evidence_ids
                else [e.event_id for e in non_benign_events]
            )
        elif benign_suppressed_procs:
            explanation = (
                f"Elevated directory enumeration attributed to "
                f"known benign indexing/system process ({benign_suppressed_procs})"
            )
            evidence_ids = []
        else:
            explanation = (
                f"Filesystem discovery rate ({non_benign_rate:.1f} dirs/sec across "
                f"{len(non_benign_dirs)} dirs) within normal operational limits"
            )
            evidence_ids = []

        telemetry_state = {
            "filesystem_read_access": "evidence_observed",
            "process_execution": (
                "evidence_observed"
                if any(de.process_name for de in scoped_discovery_events)
                else ("clean" if proc_cap_available else "unavailable")
            ),
        }

        metadata: dict[str, Any] = {
            "unique_directories_enumerated": len(
                {de.target_directory for de in scoped_discovery_events}
            ),
            "enumeration_rate": round(
                len({de.target_directory for de in scoped_discovery_events})
                / window_duration,
                2,
            ),
            "offending_processes": offending_procs,
            "benign_processes_suppressed": benign_suppressed_procs,
            "is_benign_indexer": bool(benign_suppressed_procs and not offending_procs),
            "telemetry_state": telemetry_state,
            "rejected_auxiliary_events_count": len(rejected_discovery),
            "mitre_technique": "T1083",
        }

        return self._create_result(
            triggered=triggered,
            observed_metric=round(observed_metric, 2),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids,
            metadata=metadata,
        )
