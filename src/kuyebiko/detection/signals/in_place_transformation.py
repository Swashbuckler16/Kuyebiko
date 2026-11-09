"""FS_IN_PLACE_TRANSFORMATION: In-Place Transformation signal evaluator (T1486).

Detects suspicious filesystem transformation activity where multiple distinct user
files across diverse directory branches are modified in-place without corresponding
rename operations or extension changes, characteristic of evasion-focused ransomware
strains that overwrite file contents directly.
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

# Known temporary/developer scratch directories discounted unless at extreme scale
_BENIGN_DEV_DIRS = {
    "temp",
    "tmp",
    "cache",
    ".cache",
    "node_modules",
    "__pycache__",
    "target",
    "build",
    "dist",
    ".git",
    "obj",
    "bin",
}


class InPlaceTransformationSignalEvaluator(AdvancedSignalEvaluator):
    """Detects broad multi-directory in-place file modifications under MITRE T1486."""

    def __init__(
        self,
        min_unique_files: int = 15,
        min_directories: int = 3,
        threshold: float = 0.60,  # Minimum modification ratio
        max_rename_ratio: float = 0.15,  # Must be primarily in-place, not rename-based
        is_enabled: bool = True,
    ) -> None:
        metadata = SignalMetadata(
            signal_id="FS_IN_PLACE_TRANSFORMATION",
            name="In-Place File Transformation",
            family=SignalFamily.FILE_TRANSFORMATION,
            mitre_technique="T1486",
            description=(
                "Detects systematic modification of distinct files across multiple "
                "directories without corresponding file rename operations."
            ),
            required_capabilities=[TelemetryCapability.FILESYSTEM_METADATA],
            evidence_requirements=(
                f"Modification of >= {min_unique_files} distinct files across "
                f">= {min_directories} directories with ratio >= {threshold:.0%} "
                f"and rename ratio <= {max_rename_ratio:.0%}."
            ),
            confidence_limitations=(
                "Detection is based solely on filesystem mutation metadata without "
                "inspecting file content, encryption headers, or entropy."
            ),
            threshold=threshold,
            default_threshold=0.60,
            min_events=min_unique_files,
        )
        super().__init__(metadata=metadata, is_enabled=is_enabled)
        self._min_unique_files = min_unique_files
        self._min_directories = min_directories
        self._max_rename_ratio = max_rename_ratio

    @property
    def min_unique_files(self) -> int:
        return self._min_unique_files

    @property
    def min_directories(self) -> int:
        return self._min_directories

    @property
    def max_rename_ratio(self) -> float:
        return self._max_rename_ratio

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Evaluate in-place modification metrics across distinct files and dirs."""
        total_events = len(context.events)
        if total_events < self._min_unique_files:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({total_events}) for in-place transformation "
                    f"evaluation (min: {self._min_unique_files})"
                ),
                severity_score=0.0,
                metadata={"total_events": total_events},
            )

        # Pre-screen guard using precomputed aggregates
        mod_count = context.stats.modified_count
        if mod_count < self._min_unique_files:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Modification count ({mod_count}) below minimum required "
                    f"({self._min_unique_files})"
                ),
                severity_score=0.0,
                metadata={"modified_count": mod_count},
            )

        # Filter modification events on files (exclude directory modifications)
        modified_events = []
        modified_paths: Counter[str] = Counter()
        modified_dirs: Counter[str] = Counter()

        for e in context.events:
            if e.event_type == EventType.MODIFIED and not e.is_directory:
                modified_events.append(e)
                modified_paths[e.file_path] += 1
                dirname = posixpath.dirname(e.file_path)
                modified_dirs[dirname] += 1

        unique_files_count = len(modified_paths)
        unique_dirs_count = len(modified_dirs)
        mod_ratio = len(modified_events) / total_events if total_events > 0 else 0.0

        # Rename ratio check: in-place encryption avoids renames
        rename_count = context.stats.renamed_count
        rename_ratio = rename_count / total_events if total_events > 0 else 0.0

        # Check if modifications are strictly confined to developer scratch / cache dirs
        is_confined_to_dev = False
        non_dev_files = 0
        for path in modified_paths.keys():
            parts = [p.lower() for p in path.replace("\\", "/").split("/")]
            if not any(part in _BENIGN_DEV_DIRS for part in parts):
                non_dev_files += 1

        if unique_dirs_count > 0 and non_dev_files == 0:
            is_confined_to_dev = True

        # Contextual discounting:
        # Dev/cache modifications require massive scale (>= 45 files, >= 5 dirs)
        is_massive_dev_burst = (
            unique_files_count >= max(45, self._min_unique_files * 3)
            and unique_dirs_count >= 5
        )

        meets_criteria = (
            unique_files_count >= self._min_unique_files
            and unique_dirs_count >= self._min_directories
            and mod_ratio >= self.threshold
            and rename_ratio <= self._max_rename_ratio
        )

        if meets_criteria:
            if is_confined_to_dev:
                triggered = is_massive_dev_burst
            else:
                triggered = True
        else:
            triggered = False

        severity = 0.0
        if triggered:
            # Scaled by unique file breadth and multi-directory distribution
            file_factor = min(1.0, unique_files_count / (self._min_unique_files * 2))
            dir_factor = min(1.0, unique_dirs_count / (self._min_directories * 2))
            severity = min(1.0, 0.65 + 0.20 * file_factor + 0.15 * dir_factor)
            if is_confined_to_dev:
                severity = max(0.50, severity - 0.15)

        evidence_ids = [e.event_id for e in modified_events]

        if triggered:
            top_dirs = sorted(modified_dirs.keys())[:5]
            explanation = (
                f"Suspicious in-place file transformation detected (T1486): "
                f"{unique_files_count} unique files modified across "
                f"{unique_dirs_count} directories without renames "
                f"({mod_ratio:.1%} modification ratio; top dirs: {top_dirs})"
            )
        elif is_confined_to_dev and unique_files_count >= self._min_unique_files:
            explanation = (
                f"Modifications ({unique_files_count} files) confined to developer "
                "or build scratch directories; recognized as benign workload"
            )
        elif (
            unique_dirs_count < self._min_directories
            and unique_files_count >= self._min_unique_files
        ):
            explanation = (
                f"Modifications concentrated in only {unique_dirs_count} branch(es); "
                "localized activity within acceptable operational limits"
            )
        elif rename_ratio > self._max_rename_ratio:
            explanation = (
                f"Elevated rename activity present ({rename_ratio:.1%}); "
                "evaluated by rename-specific detection signals"
            )
        else:
            explanation = (
                "In-place modification activity within normal limits: "
                f"{unique_files_count} files across {unique_dirs_count} directories"
            )

        metadata: dict[str, Any] = {
            "unique_files_modified": unique_files_count,
            "unique_directories_count": unique_dirs_count,
            "modification_ratio": round(mod_ratio, 4),
            "rename_ratio": round(rename_ratio, 4),
            "non_dev_files_count": non_dev_files,
            "is_confined_to_dev": is_confined_to_dev,
            "is_massive_dev_burst": is_massive_dev_burst,
            "mitre_technique": "T1486",
        }

        return self._create_result(
            triggered=triggered,
            observed_metric=round(mod_ratio, 4),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata=metadata,
        )
