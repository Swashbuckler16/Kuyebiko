"""FS_RENAME_RATIO: Abnormal Rename Ratio behavioural signal evaluator."""

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventType


class RenameRatioSignalEvaluator(BaseSignalEvaluator):
    """Detects elevated proportion of rename operations relative to total events."""

    def __init__(
        self,
        threshold: float = 0.60,  # Minimum rename ratio (e.g. 60%)
        min_renames: int = 5,  # Minimum absolute renames
        min_events: int = 10,  # Minimum total operations
        is_enabled: bool = True,
    ) -> None:
        super().__init__(
            signal_id="FS_RENAME_RATIO",
            name="Abnormal Rename Ratio",
            family=SignalFamily.RENAME_DELETION,
            threshold=threshold,
            is_enabled=is_enabled,
            min_events=min_events,
        )
        self._min_renames = min_renames

    @property
    def min_renames(self) -> int:
        return self._min_renames

    @min_renames.setter
    def min_renames(self, value: int) -> None:
        if value < 1:
            raise ValueError(f"min_renames must be at least 1, got {value}")
        self._min_renames = value

    def evaluate(self, context: DetectionContext) -> SignalResult:
        total_events = len(context.events)
        if total_events < self.min_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({total_events}) for rename ratio "
                    f"evaluation (min required: {self.min_events})"
                ),
                severity_score=0.0,
            )

        # O(1) Pre-screening using precomputed window statistics
        if context.stats.rename_pairs_count < self._min_renames:
            return self._create_result(
                triggered=False,
                observed_metric=round(
                    context.stats.rename_pairs_count / total_events, 4
                ),
                explanation=(
                    f"Correlated rename pairs count "
                    f"({context.stats.rename_pairs_count}) below minimum "
                    f"threshold ({self._min_renames})"
                ),
                severity_score=0.0,
                metadata={
                    "total_events": total_events,
                    "stats_rename_pairs_count": context.stats.rename_pairs_count,
                    "min_renames": self._min_renames,
                },
            )

        if (context.stats.rename_pairs_count / total_events) < self.threshold:
            return self._create_result(
                triggered=False,
                observed_metric=round(
                    context.stats.rename_pairs_count / total_events, 4
                ),
                explanation=(
                    f"Correlated rename ratio "
                    f"({context.stats.rename_pairs_count / total_events:.1%}) "
                    f"below threshold ({self.threshold:.1%})"
                ),
                severity_score=0.0,
                metadata={
                    "total_events": total_events,
                    "stats_rename_pairs_count": context.stats.rename_pairs_count,
                    "threshold": self.threshold,
                },
            )

        # Independently verify that each rename has explicit correlation provenance,
        # represents a confirmed distinct file pair, and is not a directory mutation.
        verified_rename_events = []
        for e in context.events:
            if e.event_type != EventType.RENAMED or e.is_directory:
                continue
            # Enforce explicit rename correlation provenance
            if not e.correlation_provenance:
                continue
            if not e.old_path or not e.new_path:
                continue
            # Independently verify old_path and new_path represent distinct locations
            norm_old = e.old_path.strip().replace("\\", "/")
            norm_new = e.new_path.strip().replace("\\", "/")
            if norm_old == norm_new:
                continue
            verified_rename_events.append(e)

        rename_count = len(verified_rename_events)
        stats_pairs = context.stats.rename_pairs_count
        stats_discrepancy = rename_count != stats_pairs

        rename_ratio = rename_count / total_events
        triggered = rename_ratio >= self.threshold and rename_count >= self._min_renames
        severity = 0.0
        if triggered:
            ratio_factor = (rename_ratio - self.threshold) / max(
                0.01, (1.0 - self.threshold)
            )
            count_factor = min(1.0, rename_count / max(10, self._min_renames * 2))
            severity = min(1.0, 0.5 + 0.3 * ratio_factor + 0.2 * count_factor)

        evidence_ids = [e.event_id for e in verified_rename_events]

        if triggered:
            explanation = (
                f"Abnormal rename ratio detected: {rename_count}/{total_events} "
                f"operations ({rename_ratio:.1%}) are verified correlated rename pairs "
                f"(threshold: {self.threshold:.1%}, min renames: {self._min_renames})"
            )
        else:
            explanation = (
                f"Rename ratio within acceptable limits: {rename_count}/{total_events} "
                f"({rename_ratio:.1%}) verified (threshold: {self.threshold:.1%})"
            )

        return self._create_result(
            triggered=triggered,
            observed_metric=round(rename_ratio, 4),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata={
                "rename_count": rename_count,
                "verified_rename_pairs_count": rename_count,
                "stats_rename_pairs_count": stats_pairs,
                "stats_discrepancy": stats_discrepancy,
                "total_events": total_events,
            },
        )
