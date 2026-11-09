"""FS_FILESYSTEM_DISCOVERY: Filesystem Discovery behavioural signal evaluator (T1083).

Enforces strict telemetry capability boundaries: explicitly declares that ordinary
Windows change notifications (ReadDirectoryChangesW) cannot observe directory reads
or enumeration. Requires dedicated read-access / filter-driver telemetry to evaluate.
"""

from collections import Counter
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
            evidence_requirements=(
                f"Enumeration of >= {min_directories} directories at rate >= "
                f"{threshold:.1f} dirs/sec via dedicated read/enumeration telemetry."
            ),
            confidence_limitations=(
                "ReadDirectoryChangesW cannot observe read or directory enumeration "
                "operations. Detections are only evaluated when FILESYSTEM_READ_ACCESS "
                "telemetry (e.g. minifilter or ETW read tracing) is available."
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
        """Evaluate directory discovery from read-access telemetry."""
        discovery_events: list[DiscoveryTelemetryEvent] = context.config.get(
            "discovery_events", []
        )

        if not discovery_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    "Read-access telemetry enabled, but no directory enumeration "
                    "events observed in the current correlation window."
                ),
                severity_score=0.0,
                metadata={"discovery_events_count": 0, "mitre_technique": "T1083"},
            )

        dir_counts: Counter[str] = Counter()
        process_names: Counter[str] = Counter()
        evidence_ids: list[str] = []

        for de in discovery_events:
            dir_counts[de.target_directory] += 1
            if de.process_name:
                process_names[de.process_name.lower()] += 1
            evidence_ids.append(de.event_id)

        unique_dirs = len(dir_counts)
        window_duration = max(0.1, context.window_duration_seconds)
        enumeration_rate = unique_dirs / window_duration

        # Check process attribution for benign indexing or build processes
        is_benign_indexer = False
        if process_names:
            top_proc = process_names.most_common(1)[0][0]
            if top_proc in _BENIGN_DISCOVERY_PROCESSES:
                is_benign_indexer = True

        triggered = (
            unique_dirs >= self._min_directories
            and enumeration_rate >= self.threshold
            and not is_benign_indexer
        )

        severity = 0.0
        if triggered:
            rate_factor = min(1.0, enumeration_rate / (self.threshold * 2))
            severity = min(1.0, 0.60 + 0.30 * rate_factor)

        if triggered:
            explanation = (
                f"Rapid filesystem discovery detected (T1083): {unique_dirs} unique "
                f"directories enumerated at {enumeration_rate:.1f} dirs/sec "
                f"(threshold: {self.threshold:.1f} dirs/sec; processes: "
                f"{list(process_names.keys())[:3]})"
            )
        elif is_benign_indexer and unique_dirs >= self._min_directories:
            explanation = (
                f"Elevated directory enumeration ({unique_dirs} dirs) attributed to "
                f"known benign indexing/system process ({list(process_names.keys())})"
            )
        else:
            explanation = (
                f"Filesystem discovery rate ({enumeration_rate:.1f} dirs/sec across "
                f"{unique_dirs} dirs) within normal operational limits"
            )

        metadata: dict[str, Any] = {
            "unique_directories_enumerated": unique_dirs,
            "enumeration_rate": round(enumeration_rate, 2),
            "is_benign_indexer": is_benign_indexer,
            "observed_processes": list(process_names.keys()),
            "mitre_technique": "T1083",
        }

        return self._create_result(
            triggered=triggered,
            observed_metric=round(enumeration_rate, 2),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata=metadata,
        )
