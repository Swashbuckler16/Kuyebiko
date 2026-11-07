"""FS_DIRECTORY_TRAVERSAL: Directory Traversal Diversity evaluator."""

import posixpath
from collections import Counter

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.detection.signals.base import BaseSignalEvaluator


class DirectoryTraversalSignalEvaluator(BaseSignalEvaluator):
    """Detects rapid modifications distributed across diverse directory branches."""

    def __init__(
        self,
        threshold: float = 5.0,  # Minimum unique directories touched
        min_events: int = 10,  # Minimum total operations
        is_enabled: bool = True,
    ) -> None:
        super().__init__(
            signal_id="FS_DIRECTORY_TRAVERSAL",
            name="Directory Traversal Diversity",
            family=SignalFamily.DIRECTORY_TRAVERSAL,
            threshold=threshold,
            is_enabled=is_enabled,
            min_events=min_events,
        )

    def evaluate(self, context: DetectionContext) -> SignalResult:
        total_events = len(context.events)
        if total_events < self.min_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({total_events}) for directory traversal "
                    f"evaluation (min required: {self.min_events})"
                ),
                severity_score=0.0,
            )

        # O(1) Pre-screening: check unique directories in window stats
        if len(context.stats.unique_directories) < self.threshold:
            return self._create_result(
                triggered=False,
                observed_metric=float(len(context.stats.unique_directories)),
                explanation=(
                    f"Unique directories ({len(context.stats.unique_directories)}) "
                    f"below threshold ({self.threshold:.0f})"
                ),
                severity_score=0.0,
            )

        dir_counts: Counter[str] = Counter()
        for event in context.events:
            dirname = posixpath.dirname(event.file_path)
            clean_dir = dirname if dirname else "<root>"
            dir_counts[clean_dir] += 1

        unique_dir_count = len(dir_counts)
        triggered = unique_dir_count >= self.threshold

        severity = 0.0
        if triggered:
            excess = unique_dir_count - self.threshold
            severity = min(1.0, 0.5 + 0.5 * (excess / max(5.0, self.threshold)))

        window_duration = (
            context.window_duration_seconds
            if context.window_duration_seconds > 0.0
            else 1.0
        )
        dirs_per_second = unique_dir_count / window_duration

        if triggered:
            explanation = (
                f"High directory traversal diversity detected: {unique_dir_count} "
                f"unique directories touched across {total_events} operations at "
                f"{dirs_per_second:.1f} dirs/sec "
                f"(threshold: {self.threshold:.0f} directories)"
            )
        else:
            explanation = (
                f"Directory activity localized: {unique_dir_count} unique directories "
                f"touched (threshold: {self.threshold:.0f} directories)"
            )

        evidence_ids = [e.event_id for e in context.events]

        return self._create_result(
            triggered=triggered,
            observed_metric=float(unique_dir_count),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata={
                "unique_directories_count": unique_dir_count,
                "directories_sample": sorted(dir_counts.keys())[:10],
                "traversal_rate_dirs_sec": round(dirs_per_second, 2),
                "total_events": total_events,
            },
        )
