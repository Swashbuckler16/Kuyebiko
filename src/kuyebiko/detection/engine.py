"""Central ransomware behaviour detection engine for Kuyebiko.

Integrates SlidingWindowCorrelator, SignalRegistry, and foundational behaviour
evaluators to evaluate normalized FileEvent streams, isolate monitored roots,
account for telemetry degradation, and produce explainable DetectionResults.
"""

import logging
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from kuyebiko.detection.models import (
    DetectionOutcome,
    DetectionResult,
    SignalFamily,
)
from kuyebiko.detection.registry import SignalRegistry
from kuyebiko.detection.signals.burst_write import BurstWriteSignalEvaluator
from kuyebiko.detection.signals.delete_ratio import DeleteRatioSignalEvaluator
from kuyebiko.detection.signals.directory_traversal import (
    DirectoryTraversalSignalEvaluator,
)
from kuyebiko.detection.signals.extension_convergence import (
    ExtensionConvergenceSignalEvaluator,
)
from kuyebiko.detection.signals.rename_ratio import RenameRatioSignalEvaluator
from kuyebiko.detection.window import SlidingWindowCorrelator
from kuyebiko.models.events import EventType, FileEvent, TelemetryQuality
from kuyebiko.processing.contracts import EventConsumer
from kuyebiko.processing.ordering import EventOrderingMetadata

logger = logging.getLogger("kuyebiko.detection.engine")


class DetectionEngine(EventConsumer):
    """Orchestrates correlation windows, signal dispatch, and detection outcomes."""

    def __init__(
        self,
        correlator: SlidingWindowCorrelator | None = None,
        registry: SignalRegistry | None = None,
        auto_register_default_signals: bool = True,
        detection_family_threshold: int = 2,
        eval_interval_events: int = 1,
    ) -> None:
        """Initialize detection engine with correlator, registry, and policies.

        Args:
            correlator: SlidingWindowCorrelator instance (or default if None).
            registry: SignalRegistry instance (or default if None).
            auto_register_default_signals: Whether to register foundational signals.
            detection_family_threshold: Minimum triggered signal families required
                for confirmed DETECTION (default 2). 1 family yields SUSPICIOUS.
            eval_interval_events: Evaluation throttling interval (default 1).
        """
        if detection_family_threshold < 1:
            raise ValueError(
                "detection_family_threshold must be at least 1, "
                f"got {detection_family_threshold}"
            )
        if eval_interval_events < 1:
            raise ValueError(
                f"eval_interval_events must be at least 1, got {eval_interval_events}"
            )

        self._correlator = (
            correlator if correlator is not None else SlidingWindowCorrelator()
        )
        self._registry = registry if registry is not None else SignalRegistry()
        self._detection_family_threshold = detection_family_threshold
        self._eval_interval_events = eval_interval_events

        self._listeners: list[Callable[[DetectionResult], None]] = []
        self._lock = threading.RLock()
        self._latest_results: dict[str, DetectionResult] = {}
        self._telemetry_degraded_by_root: dict[str, tuple[bool, str | None, bool]] = {}
        self._events_since_eval: dict[str, int] = {}

        if auto_register_default_signals:
            self._register_foundational_signals()

    @property
    def correlator(self) -> SlidingWindowCorrelator:
        return self._correlator

    @property
    def registry(self) -> SignalRegistry:
        return self._registry

    @property
    def eval_interval_events(self) -> int:
        return self._eval_interval_events

    @eval_interval_events.setter
    def eval_interval_events(self, value: int) -> None:
        if value < 1:
            raise ValueError(f"eval_interval_events must be at least 1, got {value}")
        self._eval_interval_events = value

    def _register_foundational_signals(self) -> None:
        """Register the five foundational ransomware behavioural signals."""
        signals = [
            BurstWriteSignalEvaluator(),
            RenameRatioSignalEvaluator(),
            DeleteRatioSignalEvaluator(),
            DirectoryTraversalSignalEvaluator(),
            ExtensionConvergenceSignalEvaluator(),
        ]
        for sig in signals:
            try:
                self._registry.register(sig)
            except ValueError:
                pass  # already registered

    def add_listener(self, listener: Callable[[DetectionResult], None]) -> None:
        """Subscribe a callable listener for completed DetectionResult notifications."""
        if not callable(listener):
            raise TypeError("listener must be callable")
        with self._lock:
            self._listeners.append(listener)

    def set_root_telemetry_status(
        self,
        root_id: str,
        is_degraded: bool,
        reason: str | None = None,
        uncounted_kernel_loss: bool = False,
    ) -> None:
        """Record upstream telemetry degradation state for a monitored root."""
        with self._lock:
            self._telemetry_degraded_by_root[root_id] = (
                is_degraded,
                reason,
                uncounted_kernel_loss,
            )

    def handle_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
    ) -> None:
        """EventConsumer interface implementation for pipeline integration."""
        self.process_event(event, ordering)

    def process_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
        now_monotonic_ns: int | None = None,
    ) -> DetectionResult | None:
        """Ingest event, update correlation window, and execute an evaluation cycle."""
        root_id = event.root_id
        clock_ns = (
            now_monotonic_ns if now_monotonic_ns is not None else event.monotonic_ns
        )

        self._correlator.add_event(
            event=event,
            ordering=ordering,
            now_monotonic_ns=clock_ns,
        )

        if event.quality == TelemetryQuality.DEGRADED:
            self.set_root_telemetry_status(
                root_id=root_id,
                is_degraded=True,
                reason="event_telemetry_quality_degraded",
            )

        with self._lock:
            count = self._events_since_eval.get(root_id, 0) + 1
            self._events_since_eval[root_id] = count

            # Evaluate if interval reached or event is a high-priority mutation
            should_eval = count >= self._eval_interval_events or event.event_type in (
                EventType.RENAMED,
                EventType.DELETED,
            )
            if should_eval:
                self._events_since_eval[root_id] = 0

        if should_eval:
            return self.evaluate_root(root_id, now_monotonic_ns=clock_ns)

        return self.get_latest_result(root_id)

    def evaluate_root(
        self,
        root_id: str,
        now_monotonic_ns: int | None = None,
        target_signals: Sequence[str] | None = None,
        extra_config: dict[str, Any] | None = None,
    ) -> DetectionResult:
        """Execute behaviour evaluation cycle for a specific root."""
        with self._lock:
            degraded_info = self._telemetry_degraded_by_root.get(
                root_id, (False, None, False)
            )

        is_degraded, deg_reason, uncounted_loss = degraded_info

        context = self._correlator.get_context(
            root_id=root_id,
            now_monotonic_ns=now_monotonic_ns,
            is_telemetry_degraded=is_degraded,
            degradation_reason=deg_reason,
            uncounted_kernel_loss=uncounted_loss,
            config=extra_config or {},
        )

        now_utc = datetime.now(UTC)

        if context is None:
            res = DetectionResult(
                evaluation_id=str(uuid4()),
                root_id=root_id,
                outcome=DetectionOutcome.NO_DETECTION,
                evaluated_at_utc=now_utc,
                window_start_utc=now_utc,
                window_end_utc=now_utc,
                window_duration_seconds=self._correlator.window_duration_seconds,
                total_events_evaluated=0,
                signal_results=[],
                triggered_signal_ids=[],
                triggered_signal_families=[],
                evaluation_errors=[],
                is_telemetry_degraded=is_degraded,
                degradation_reasons=[deg_reason] if deg_reason else [],
            )
            self._notify_result(res)
            return res

        # Execute registered evaluators in isolation
        signal_results, errors = self._registry.evaluate_all(
            context=context,
            target_signals=target_signals,
        )

        triggered_signals: list[str] = []
        triggered_families_set: set[SignalFamily] = set()

        for sr in signal_results:
            if sr.triggered:
                triggered_signals.append(sr.signal_id)
                triggered_families_set.add(sr.family)

        triggered_families = sorted(list(triggered_families_set), key=lambda f: f.value)

        # Robust outcome determination: differentiate benign batch ops from ransomware
        if errors:
            outcome = DetectionOutcome.EVALUATION_ERROR
        elif len(triggered_families) >= 3:
            outcome = DetectionOutcome.DETECTION
        elif len(triggered_families) >= self._detection_family_threshold:
            # Multi-family correlation requires mutation/transformation confirmation
            has_transformation = (
                SignalFamily.FILE_TRANSFORMATION in triggered_families_set
            )
            has_rename_burst = (
                "FS_BURST_WRITE" in triggered_signals
                and "FS_RENAME_RATIO" in triggered_signals
            )
            if has_transformation or has_rename_burst:
                outcome = DetectionOutcome.DETECTION
            else:
                # E.g. Burst Write + Traversal during build, or Delete + Traversal
                outcome = DetectionOutcome.SUSPICIOUS_ACTIVITY
        elif len(triggered_signals) > 0:
            outcome = DetectionOutcome.SUSPICIOUS_ACTIVITY
        elif context.is_telemetry_degraded:
            outcome = DetectionOutcome.INSUFFICIENT_TELEMETRY
        else:
            outcome = DetectionOutcome.NO_DETECTION

        deg_reasons: list[str] = []
        if context.degradation_reason:
            deg_reasons.append(context.degradation_reason)

        det_result = DetectionResult(
            evaluation_id=str(uuid4()),
            root_id=root_id,
            outcome=outcome,
            evaluated_at_utc=now_utc,
            window_start_utc=context.window_start_utc,
            window_end_utc=context.window_end_utc,
            window_duration_seconds=context.window_duration_seconds,
            total_events_evaluated=len(context.events),
            signal_results=signal_results,
            triggered_signal_ids=triggered_signals,
            triggered_signal_families=triggered_families,
            evaluation_errors=errors,
            is_telemetry_degraded=context.is_telemetry_degraded,
            degradation_reasons=deg_reasons,
            metadata={
                "events_per_second": context.stats.events_per_second,
                "unique_directories": len(context.stats.unique_directories),
                "unique_extensions": len(context.stats.unique_extensions),
                "unique_relative_paths": len(context.stats.unique_relative_paths),
            },
        )

        self._notify_result(det_result)
        return det_result

    def _notify_result(self, result: DetectionResult) -> None:
        """Store latest result and notify subscribed listeners."""
        with self._lock:
            self._latest_results[result.root_id] = result
            listeners = list(self._listeners)

        for listener in listeners:
            try:
                listener(result)
            except Exception as exc:
                logger.exception("Detection listener raised exception: %s", exc)

    def get_latest_result(self, root_id: str) -> DetectionResult | None:
        """Retrieve most recent detection result for a root."""
        with self._lock:
            return self._latest_results.get(root_id)

    def clear(self) -> None:
        """Clear all correlation windows, cached results, and telemetry state."""
        with self._lock:
            self._correlator.clear()
            self._latest_results.clear()
            self._telemetry_degraded_by_root.clear()
            self._events_since_eval.clear()
