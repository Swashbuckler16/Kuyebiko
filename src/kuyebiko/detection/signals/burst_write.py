"""FS_BURST_WRITE: Burst Write Frequency behavioural signal evaluator."""

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.models import SignalFamily, SignalResult
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.models.events import EventType


class BurstWriteSignalEvaluator(BaseSignalEvaluator):
    """Detects rapid, high-volume write operations across multiple files."""

    def __init__(
        self,
        threshold: float = 15.0,  # Minimum unique modified files to trigger
        rate_threshold: float = 2.0,  # Minimum writes per second
        min_events: int = 10,  # Minimum total operations
        is_enabled: bool = True,
    ) -> None:
        super().__init__(
            signal_id="FS_BURST_WRITE",
            name="Burst Write Frequency",
            family=SignalFamily.FILESYSTEM_ACTIVITY,
            threshold=threshold,
            is_enabled=is_enabled,
            min_events=min_events,
        )
        self._rate_threshold = rate_threshold

    @property
    def rate_threshold(self) -> float:
        return self._rate_threshold

    @rate_threshold.setter
    def rate_threshold(self, value: float) -> None:
        if value < 0.0:
            raise ValueError(f"rate_threshold must be non-negative, got {value}")
        self._rate_threshold = value

    def evaluate(self, context: DetectionContext) -> SignalResult:
        total_events = len(context.events)
        if total_events < self.min_events:
            return self._create_result(
                triggered=False,
                observed_metric=0.0,
                explanation=(
                    f"Insufficient events ({total_events}) for burst "
                    f"evaluation (min required: {self.min_events})"
                ),
                severity_score=0.0,
            )

        # O(1) Pre-screening: check total write operations and unique paths in window
        total_potential_writes = (
            context.stats.modified_count + context.stats.created_count
        )
        if total_potential_writes < self.threshold:
            return self._create_result(
                triggered=False,
                observed_metric=float(total_potential_writes),
                explanation=(
                    f"Total write operations ({total_potential_writes}) below "
                    f"threshold ({self.threshold:.0f})"
                ),
                severity_score=0.0,
            )

        if len(context.stats.unique_relative_paths) < self.threshold:
            u_paths = len(context.stats.unique_relative_paths)
            return self._create_result(
                triggered=False,
                observed_metric=float(u_paths),
                explanation=(
                    f"Unique paths in window ({u_paths}) "
                    f"below threshold ({self.threshold:.0f})"
                ),
                severity_score=0.0,
            )

        write_events = [
            e
            for e in context.events
            if e.event_type in (EventType.MODIFIED, EventType.CREATED)
            and not e.is_directory
        ]

        unique_paths = {e.file_path for e in write_events}
        unique_count = len(unique_paths)
        total_writes = len(write_events)

        # Measure rate using active burst span or fallback to window duration
        if len(write_events) >= 2:
            elapsed_ns = write_events[-1].monotonic_ns - write_events[0].monotonic_ns
            elapsed_sec = max(1.0, elapsed_ns / 1_000_000_000)
        else:
            elapsed_sec = (
                context.window_duration_seconds
                if context.window_duration_seconds > 0.0
                else 1.0
            )

        observed_rate = total_writes / elapsed_sec

        triggered = (
            unique_count >= self.threshold and observed_rate >= self._rate_threshold
        )

        severity = 0.0
        if triggered:
            excess = max(0.0, unique_count - self.threshold)
            severity = min(1.0, 0.6 + 0.4 * (excess / max(1.0, 2 * self.threshold)))

        evidence_ids = [e.event_id for e in write_events]

        if triggered:
            explanation = (
                f"High-frequency write burst detected: {unique_count} unique files "
                f"modified across {total_writes} events at {observed_rate:.1f} ops/sec "
                f"(threshold: {self.threshold:.0f} files, "
                f"rate: {self._rate_threshold:.1f} ops/sec)"
            )
        else:
            explanation = (
                f"Write activity within normal limits: {unique_count} unique files "
                f"modified at {observed_rate:.1f} ops/sec "
                f"(threshold: {self.threshold:.0f} files)"
            )

        return self._create_result(
            triggered=triggered,
            observed_metric=float(unique_count),
            explanation=explanation,
            severity_score=severity,
            evidence_event_ids=evidence_ids if triggered else [],
            metadata={
                "unique_modified_files": unique_count,
                "total_write_events": total_writes,
                "write_rate_ops_sec": round(observed_rate, 2),
                "burst_duration_seconds": round(elapsed_sec, 2),
            },
        )
