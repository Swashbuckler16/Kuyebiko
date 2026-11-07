"""FS_EXTENSION_CONVERGENCE: File Extension Convergence evaluator."""

import posixpath
from collections import Counter

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventType


class ExtensionConvergenceSignalEvaluator(BaseSignalEvaluator):
    """Detects convergence of diverse original extensions into a common extension."""

    def __init__(
        self,
        threshold: float = 3.0,  # Minimum distinct original extensions converging
        min_renames: int = 4,  # Minimum extension-changing renames
        min_convergence_ratio: float = 0.75,  # Proportion of new exts matching top
        min_events: int = 5,
        is_enabled: bool = True,
    ) -> None:
        super().__init__(
            signal_id="FS_EXTENSION_CONVERGENCE",
            name="File Extension Convergence",
            family=SignalFamily.FILE_TRANSFORMATION,
            threshold=threshold,
            is_enabled=is_enabled,
            min_events=min_events,
        )
        self._min_renames = min_renames
        self._min_convergence_ratio = min_convergence_ratio

    @property
    def min_renames(self) -> int:
        return self._min_renames

    @min_renames.setter
    def min_renames(self, value: int) -> None:
        if value < 1:
            raise ValueError(f"min_renames must be at least 1, got {value}")
        self._min_renames = value

    def evaluate(self, context: DetectionContext) -> SignalResult:
        if len(context.events) < self.min_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({len(context.events)}) for extension "
                    f"convergence evaluation (min required: {self.min_events})"
                ),
                severity_score=0.0,
            )

        rename_events = [
            e
            for e in context.events
            if e.event_type == EventType.RENAMED and e.old_path and e.new_path
        ]

        old_extensions: Counter[str] = Counter()
        new_extensions: Counter[str] = Counter()
        extension_changes: list[tuple[str, str, str]] = []

        for e in rename_events:
            _, old_ext = posixpath.splitext(e.old_path or "")
            _, new_ext = posixpath.splitext(e.new_path or "")
            old_ext_clean = old_ext.lower().strip()
            new_ext_clean = new_ext.lower().strip()

            if old_ext_clean and new_ext_clean and old_ext_clean != new_ext_clean:
                old_extensions[old_ext_clean] += 1
                new_extensions[new_ext_clean] += 1
                extension_changes.append((e.event_id, old_ext_clean, new_ext_clean))

        total_changes = len(extension_changes)
        if total_changes < self._min_renames:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient extension mutations ({total_changes}) observed "
                    f"(min required: {self._min_renames})"
                ),
                severity_score=0.0,
            )

        distinct_original_exts = len(old_extensions)
        top_target_ext, top_target_count = new_extensions.most_common(1)[0]
        convergence_ratio = top_target_count / total_changes

        triggered = (
            distinct_original_exts >= self.threshold
            and convergence_ratio >= self._min_convergence_ratio
        )

        severity = 0.0
        if triggered:
            diversity_factor = min(
                1.0, distinct_original_exts / max(5.0, self.threshold * 1.5)
            )
            severity = min(1.0, 0.6 + 0.4 * diversity_factor * convergence_ratio)

        evidence_ids = [
            eid for eid, _, next_ext in extension_changes if next_ext == top_target_ext
        ]

        orig_summary = ", ".join(sorted(old_extensions.keys()))
        if triggered:
            explanation = (
                f"File extension convergence detected: {distinct_original_exts} "
                f"diverse original extensions ({orig_summary}) converged into "
                f"'{top_target_ext}' across {total_changes} renames "
                f"({convergence_ratio:.1%} ratio, threshold: {self.threshold:.0f} exts)"
            )
        else:
            explanation = (
                f"Extension changes do not exhibit convergence: "
                f"{distinct_original_exts} original extensions, "
                f"top target '{top_target_ext}' ({convergence_ratio:.1%} ratio)"
            )

        return self._create_result(
            triggered=triggered,
            observed_metric=float(distinct_original_exts),
            explanation=explanation,
            severity_score=round(severity, 3),
            evidence_event_ids=evidence_ids if triggered else [],
            metadata={
                "distinct_original_extensions": distinct_original_exts,
                "top_target_extension": top_target_ext,
                "convergence_ratio": round(convergence_ratio, 3),
                "total_extension_mutations": total_changes,
                "original_extensions_distribution": dict(old_extensions),
            },
        )
