"""FS_DATA_DESTRUCTION: Advanced Data Destruction signal evaluator (T1485).

Detects wide-scale, multi-directory destructive file deletion activity,
distinguishing mass data destruction from localized cleanup of single folders
or temporary build caches.
"""

import posixpath
from collections import Counter
from typing import Any

from kuyebiko.detection.advanced.contracts import (
    AdvancedSignalEvaluator,
    SignalMetadata,
    TelemetryCapability,
)
from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.models.events import EventType

# Directories typically associated with benign developer or OS temporary cleanup
_BENIGN_CLEANUP_DIRS = {
    "temp",
    "tmp",
    "cache",
    ".cache",
    "node_modules",
    "__pycache__",
    "target",
    "build",
    "dist",
    "obj",
    "bin",
}


class DataDestructionSignalEvaluator(AdvancedSignalEvaluator):
    """Detects multi-directory mass data destruction under MITRE ATT&CK T1485."""

    def __init__(
        self,
        min_deletions: int = 15,  # Minimum absolute deletions required
        min_directories: int = 3,  # Minimum distinct directories affected
        threshold: float = 0.50,  # Minimum deletion ratio relative to total events
        is_enabled: bool = True,
    ) -> None:
        metadata = SignalMetadata(
            signal_id="FS_DATA_DESTRUCTION",
            name="Mass Data Destruction",
            family=SignalFamily.DATA_DESTRUCTION,
            mitre_technique="T1485",
            description=(
                "Detects rapid, multi-directory destructive file deletion spanning "
                "user directories, distinct from benign single-folder cleanup."
            ),
            required_capabilities=[TelemetryCapability.FILESYSTEM_METADATA],
            evidence_requirements=(
                f"At least {min_deletions} file deletions across >= {min_directories} "
                f"distinct directories with deletion ratio >= {threshold:.0%}."
            ),
            confidence_limitations=(
                "Requires directory diversity to avoid false positives on localized "
                "cleanups; does not inspect file contents or wipe patterns."
            ),
            threshold=threshold,
            default_threshold=0.50,
            min_events=min_deletions,
        )
        super().__init__(metadata=metadata, is_enabled=is_enabled)
        self._min_deletions = min_deletions
        self._min_directories = min_directories

    @property
    def min_deletions(self) -> int:
        return self._min_deletions

    @property
    def min_directories(self) -> int:
        return self._min_directories

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Evaluate mass deletion with directory diversity checks."""
        total_events = len(context.events)
        if total_events < self._min_deletions:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({total_events}) for mass data destruction "
                    f"evaluation (min: {self._min_deletions})"
                ),
                severity_score=0.0,
                metadata={"total_events": total_events},
            )

        # Collect all file deletion events
        deleted_events = []
        deleted_dirs: Counter[str] = Counter()

        for e in context.events:
            if e.event_type == EventType.DELETED and not e.is_directory:
                deleted_events.append(e)
                dirname = posixpath.dirname(e.file_path)
                deleted_dirs[dirname] += 1

        del_count = len(deleted_events)
        unique_dirs_count = len(deleted_dirs)
        del_ratio = del_count / total_events if total_events > 0 else 0.0

        # Check if deletions are confined exclusively to known benign temporary dirs
        is_confined_to_temp = False
        if unique_dirs_count > 0:
            all_dirs_benign = True
            for d in deleted_dirs.keys():
                parts = [p.lower() for p in d.split("/")]
                if not any(part in _BENIGN_CLEANUP_DIRS for part in parts):
                    all_dirs_benign = False
                    break
            is_confined_to_temp = all_dirs_benign

        # Triggering criteria:
        # 1. Total deletions >= min_deletions
        # 2. Deletion ratio >= threshold OR substantial volume (>= min_del * 1.3)
        # 3. Directory diversity >= min_directories
        # 4. Not confined strictly to temporary cache directories
        triggered = (
            del_count >= self._min_deletions
            and (
                del_ratio >= self.threshold
                or del_count >= int(self._min_deletions * 1.3)
            )
            and unique_dirs_count >= self._min_directories
            and not is_confined_to_temp
        )

        severity = 0.0
        if triggered:
            # Scaled by volume and directory breadth
            volume_factor = min(1.0, del_count / (self._min_deletions * 3))
            breadth_factor = min(1.0, unique_dirs_count / (self._min_directories * 2))
            severity = min(1.0, 0.65 + 0.20 * volume_factor + 0.15 * breadth_factor)

        evidence_ids = [e.event_id for e in deleted_events]

        if triggered:
            top_dirs = sorted(deleted_dirs.keys())[:5]
            explanation = (
                f"Mass data destruction detected (T1485): {del_count} files deleted "
                f"across {unique_dirs_count} distinct directories "
                f"({del_ratio:.1%} of operations; top dirs: {top_dirs})"
            )
        elif is_confined_to_temp and del_count >= self._min_deletions:
            explanation = (
                f"Elevated deletions ({del_count}) observed but confined to "
                "benign temporary/cache directories (benign cleanup)"
            )
        elif (
            unique_dirs_count < self._min_directories
            and del_count >= self._min_deletions
        ):
            explanation = (
                f"Elevated deletions ({del_count}) observed within only "
                f"{unique_dirs_count} directory branch(es); localized cleanup"
            )
        else:
            explanation = (
                f"Destructive deletion activity within acceptable limits: "
                f"{del_count} deletions across {unique_dirs_count} directories"
            )

        metadata: dict[str, Any] = {
            "deleted_count": del_count,
            "unique_directories_count": unique_dirs_count,
            "deletion_ratio": round(del_ratio, 4),
            "is_confined_to_temp": is_confined_to_temp,
            "affected_directories": sorted(deleted_dirs.keys())[:10],
            "mitre_technique": "T1485",
        }

        return self._create_result(
            triggered=triggered,
            observed_metric=round(del_ratio, 4),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata=metadata,
        )
