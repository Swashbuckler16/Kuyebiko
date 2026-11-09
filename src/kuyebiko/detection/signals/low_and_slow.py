"""FS_LOW_AND_SLOW_ACTIVITY: Distributed Low-and-Slow Activity evaluator (T1486).

Identifies stealthy filesystem transformation activity distributed over medium-to-long
time horizons (e.g. 60s – 300s) at low operation frequencies (e.g. <= 5 events/sec)
designed to evade high-frequency burst detectors while systematically transforming
files across multiple user directories.
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

_BENIGN_SCRATCH_DIRS = {
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
}


class LowAndSlowSignalEvaluator(AdvancedSignalEvaluator):
    """Detects distributed low-frequency multi-directory file transformations."""

    def __init__(
        self,
        min_events: int = 20,
        min_directories: int = 3,
        min_time_span_seconds: float = 15.0,
        max_event_rate: float = 6.0,  # Max events/sec to classify as low-and-slow
        threshold: float = 0.50,  # Minimum transformation ratio (modified + deleted)
        is_enabled: bool = True,
    ) -> None:
        metadata = SignalMetadata(
            signal_id="FS_LOW_AND_SLOW_ACTIVITY",
            name="Distributed Low-and-Slow Transformation",
            family=SignalFamily.FILE_TRANSFORMATION,
            mitre_technique="T1486",
            description=(
                "Detects low-frequency, persistent file transformation activity "
                "distributed over extended time horizons across multiple directories."
            ),
            required_capabilities=[TelemetryCapability.FILESYSTEM_METADATA],
            evidence_requirements=(
                f"At least {min_events} transformation events across >= "
                f"{min_directories} dirs spanning >= {min_time_span_seconds:.0f}s "
                f"at rate <= {max_event_rate:.1f} ops/sec."
            ),
            confidence_limitations=(
                "Relies on multi-horizon temporal persistence; does not inspect file "
                "contents or encryption entropy."
            ),
            threshold=threshold,
            default_threshold=0.50,
            min_events=min_events,
        )
        super().__init__(metadata=metadata, is_enabled=is_enabled)
        self._min_events = min_events
        self._min_directories = min_directories
        self._min_time_span_seconds = min_time_span_seconds
        self._max_event_rate = max_event_rate

    @property
    def min_events(self) -> int:
        return self._min_events

    @property
    def min_directories(self) -> int:
        return self._min_directories

    @property
    def min_time_span_seconds(self) -> float:
        return self._min_time_span_seconds

    @property
    def max_event_rate(self) -> float:
        return self._max_event_rate

    def evaluate_advanced(self, context: DetectionContext) -> SignalResult:
        """Evaluate distributed low-and-slow persistence across horizons."""
        # Check if extended horizon is provided in multi-horizon context
        horizons_map = context.config.get("horizons", {})
        eval_ctx: DetectionContext = (
            horizons_map.get("medium") or horizons_map.get("long") or context
        )

        events = eval_ctx.events
        total_events = len(events)

        if total_events < self._min_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient extended-horizon events ({total_events}) for "
                    f"low-and-slow evaluation (min: {self._min_events})"
                ),
                severity_score=0.0,
                metadata={"total_events": total_events},
            )

        # Collect transformation events (modified, deleted, renamed)
        transform_events = []
        affected_dirs: Counter[str] = Counter()
        affected_files: Counter[str] = Counter()

        for e in events:
            if e.event_type in (
                EventType.MODIFIED,
                EventType.DELETED,
                EventType.RENAMED,
            ):
                transform_events.append(e)
                affected_files[e.file_path] += 1
                dirname = posixpath.dirname(e.file_path)
                affected_dirs[dirname] += 1

        transform_count = len(transform_events)
        transform_ratio = transform_count / total_events if total_events > 0 else 0.0

        if transform_count < self._min_events:
            return self._create_result(
                triggered=False,
                observed_metric=round(transform_ratio, 4),
                explanation=(
                    f"Transformation event count ({transform_count}) below threshold "
                    f"({self._min_events})"
                ),
                severity_score=0.0,
                metadata={"transformation_count": transform_count},
            )

        # Measure temporal distribution span across the window
        earliest_ns = min(e.monotonic_ns for e in transform_events)
        latest_ns = max(e.monotonic_ns for e in transform_events)
        time_span_seconds = max(0.001, (latest_ns - earliest_ns) / 1_000_000_000)

        effective_duration = max(time_span_seconds, eval_ctx.window_duration_seconds)
        event_rate = total_events / effective_duration

        unique_dirs_count = len(affected_dirs)
        unique_files_count = len(affected_files)

        # Exclude workloads strictly confined to temporary scratch folders
        is_confined_to_scratch = False
        non_scratch_files = 0
        for path in affected_files.keys():
            parts = [p.lower() for p in path.replace("\\", "/").split("/")]
            if not any(part in _BENIGN_SCRATCH_DIRS for part in parts):
                non_scratch_files += 1

        if unique_dirs_count > 0 and non_scratch_files == 0:
            is_confined_to_scratch = True

        # Trigger conditions for Low-and-Slow transformation:
        # 1. Total transformation events >= min_events
        # 2. Transformation ratio >= threshold
        # 3. Time span >= min_time_span_seconds (distributed across time)
        # 4. Overall event rate <= max_event_rate (differentiates from burst)
        # 5. Directory diversity >= min_directories
        # 6. Not strictly confined to scratch/cache folders
        triggered = (
            transform_count >= self._min_events
            and transform_ratio >= self.threshold
            and time_span_seconds >= self._min_time_span_seconds
            and event_rate <= self._max_event_rate
            and unique_dirs_count >= self._min_directories
            and not is_confined_to_scratch
        )

        severity = 0.0
        if triggered:
            span_factor = min(
                1.0, time_span_seconds / (self._min_time_span_seconds * 3)
            )
            dir_factor = min(1.0, unique_dirs_count / (self._min_directories * 2))
            severity = min(1.0, 0.65 + 0.20 * span_factor + 0.15 * dir_factor)

        evidence_ids = [e.event_id for e in transform_events]

        if triggered:
            top_dirs = sorted(affected_dirs.keys())[:5]
            explanation = (
                f"Distributed low-and-slow transformation detected (T1486): "
                f"{transform_count} operations across {unique_dirs_count} directories "
                f"spanning {time_span_seconds:.1f}s at {event_rate:.2f} ops/sec "
                f"({transform_ratio:.1%} ratio; top dirs: {top_dirs})"
            )
        elif event_rate > self._max_event_rate:
            explanation = (
                f"Event rate ({event_rate:.1f} ops/sec) exceeds low-and-slow envelope; "
                "handled by high-frequency burst detectors"
            )
        elif time_span_seconds < self._min_time_span_seconds:
            explanation = (
                f"Activity compressed within {time_span_seconds:.1f}s "
                f"(min time span: {self._min_time_span_seconds:.0f}s); "
                "insufficient temporal persistence"
            )
        elif is_confined_to_scratch:
            explanation = (
                f"Distributed activity ({unique_files_count} files) confined to "
                "temporary/build scratch directories; recognized as benign workload"
            )
        elif unique_dirs_count < self._min_directories:
            explanation = (
                f"Activity concentrated in only {unique_dirs_count} branch(es); "
                "lacks cross-directory distribution"
            )
        else:
            explanation = (
                f"Activity within acceptable operational limits: "
                f"{transform_count} transformations across {unique_dirs_count} dirs"
            )

        metadata: dict[str, Any] = {
            "transformation_count": transform_count,
            "unique_directories_count": unique_dirs_count,
            "unique_files_count": unique_files_count,
            "time_span_seconds": round(time_span_seconds, 2),
            "event_rate": round(event_rate, 2),
            "transformation_ratio": round(transform_ratio, 4),
            "is_confined_to_scratch": is_confined_to_scratch,
            "mitre_technique": "T1486",
        }

        return self._create_result(
            triggered=triggered,
            observed_metric=round(event_rate, 2),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata=metadata,
        )
