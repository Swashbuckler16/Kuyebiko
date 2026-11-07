"""FS_DELETE_RATIO: Abnormal Delete Ratio behavioural signal evaluator."""

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventType


class DeleteRatioSignalEvaluator(BaseSignalEvaluator):
    """Detects elevated file deletion activity within the correlation window."""

    def __init__(
        self,
        threshold: float = 0.60,  # Minimum delete ratio (e.g. 60%)
        min_deletions: int = 5,  # Minimum absolute deletions
        min_events: int = 10,  # Minimum total operations
        is_enabled: bool = True,
    ) -> None:
        super().__init__(
            signal_id="FS_DELETE_RATIO",
            name="Abnormal Delete Ratio",
            family=SignalFamily.RENAME_DELETION,
            threshold=threshold,
            is_enabled=is_enabled,
            min_events=min_events,
        )
        self._min_deletions = min_deletions

    @property
    def min_deletions(self) -> int:
        return self._min_deletions

    @min_deletions.setter
    def min_deletions(self, value: int) -> None:
        if value < 1:
            raise ValueError(f"min_deletions must be at least 1, got {value}")
        self._min_deletions = value

    def evaluate(self, context: DetectionContext) -> SignalResult:
        total_events = len(context.events)
        if total_events < self.min_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({total_events}) for delete ratio "
                    f"evaluation (min required: {self.min_events})"
                ),
                severity_score=0.0,
            )

        # O(1) Pre-screening: check total deleted count in stats
        if context.stats.deleted_count < self._min_deletions:
            return self._create_result(
                triggered=False,
                observed_metric=round(context.stats.deleted_count / total_events, 4),
                explanation=(
                    f"Total deletions ({context.stats.deleted_count}) below "
                    f"minimum threshold ({self._min_deletions})"
                ),
                severity_score=0.0,
            )

        if (context.stats.deleted_count / total_events) < self.threshold:
            return self._create_result(
                triggered=False,
                observed_metric=round(context.stats.deleted_count / total_events, 4),
                explanation=(
                    f"Delete ratio ({context.stats.deleted_count / total_events:.1%}) "
                    f"below threshold ({self.threshold:.1%})"
                ),
                severity_score=0.0,
            )

        file_delete_events = [
            e
            for e in context.events
            if e.event_type == EventType.DELETED and not e.is_directory
        ]
        delete_count = len(file_delete_events)
        unique_paths = {e.file_path for e in file_delete_events}
        delete_ratio = delete_count / total_events

        triggered = (
            delete_ratio >= self.threshold and delete_count >= self._min_deletions
        )

        severity = 0.0
        if triggered:
            ratio_factor = (delete_ratio - self.threshold) / max(
                0.01, (1.0 - self.threshold)
            )
            count_factor = min(1.0, delete_count / max(10, self._min_deletions * 2))
            severity = min(1.0, 0.5 + 0.3 * ratio_factor + 0.2 * count_factor)

        evidence_ids = [e.event_id for e in file_delete_events]

        if triggered:
            explanation = (
                f"Abnormal file deletion ratio detected: {delete_count}/{total_events} "
                f"operations ({delete_ratio:.1%}) are deletions across "
                f"{len(unique_paths)} unique files (threshold: {self.threshold:.1%}, "
                f"min deletes: {self._min_deletions})"
            )
        else:
            explanation = (
                f"File deletion ratio within normal limits: "
                f"{delete_count}/{total_events} ({delete_ratio:.1%}) deletions "
                f"(threshold: {self.threshold:.1%})"
            )

        return self._create_result(
            triggered=triggered,
            observed_metric=round(delete_ratio, 4),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata={
                "delete_count": delete_count,
                "unique_deleted_paths": len(unique_paths),
                "total_events": total_events,
                "delete_ratio": round(delete_ratio, 4),
                "threshold_ratio": self.threshold,
            },
        )
