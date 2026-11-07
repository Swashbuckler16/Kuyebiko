"""Signal evaluation registry and isolated execution framework.

Coordinates behaviour signal evaluators, validates unique identifiers,
manages runtime enablement and thresholds, and guarantees per-evaluator
exception isolation so evaluator faults never crash detection.
"""

import logging
import threading
from collections.abc import Sequence
from datetime import UTC, datetime

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.contracts import SignalEvaluator
from kuyebiko.detection.models import SignalResult

logger = logging.getLogger("kuyebiko.detection.registry")


class SignalRegistry:
    """Thread-safe registry and execution dispatcher for behaviour signal evaluators."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._evaluators: dict[str, SignalEvaluator] = {}
        self._execution_failures: dict[str, int] = {}

    def register(self, evaluator: SignalEvaluator) -> None:
        """Register a unique signal evaluator.

        Raises:
            ValueError: If a signal with the same signal_id is already registered.
            TypeError: If evaluator does not conform to SignalEvaluator protocol.
        """
        if not isinstance(evaluator, SignalEvaluator):
            raise TypeError("evaluator must implement SignalEvaluator protocol")

        sig_id = evaluator.signal_id
        with self._lock:
            if sig_id in self._evaluators:
                raise ValueError(f"Signal '{sig_id}' is already registered")
            self._evaluators[sig_id] = evaluator
            self._execution_failures.setdefault(sig_id, 0)
            logger.info("Registered signal evaluator: %s (%s)", sig_id, evaluator.name)

    def unregister(self, signal_id: str) -> bool:
        """Unregister an evaluator by signal ID. Returns True if found and removed."""
        with self._lock:
            if signal_id in self._evaluators:
                del self._evaluators[signal_id]
                self._execution_failures.pop(signal_id, None)
                logger.info("Unregistered signal evaluator: %s", signal_id)
                return True
            return False

    def get(self, signal_id: str) -> SignalEvaluator | None:
        """Retrieve a registered evaluator by signal ID."""
        with self._lock:
            return self._evaluators.get(signal_id)

    def list_evaluators(self) -> list[SignalEvaluator]:
        """Return a snapshot of all registered evaluators."""
        with self._lock:
            return list(self._evaluators.values())

    def list_signal_ids(self) -> list[str]:
        """Return a list of all registered signal identifiers."""
        with self._lock:
            return list(self._evaluators.keys())

    def set_enabled(self, signal_id: str, enabled: bool) -> None:
        """Enable or disable a registered evaluator at runtime."""
        with self._lock:
            evaluator = self._evaluators.get(signal_id)
            if evaluator is None:
                raise KeyError(f"Signal '{signal_id}' not found in registry")
            if hasattr(evaluator, "is_enabled"):
                evaluator.is_enabled = bool(enabled)
            else:
                raise AttributeError(
                    f"Evaluator '{signal_id}' does not support setting is_enabled"
                )

    def set_threshold(self, signal_id: str, threshold: float) -> None:
        """Update the threshold for a registered evaluator."""
        if threshold < 0.0:
            raise ValueError(f"threshold must be non-negative, got {threshold}")
        with self._lock:
            evaluator = self._evaluators.get(signal_id)
            if evaluator is None:
                raise KeyError(f"Signal '{signal_id}' not found in registry")
            if hasattr(evaluator, "threshold"):
                evaluator.threshold = float(threshold)
            else:
                raise AttributeError(
                    f"Evaluator '{signal_id}' does not support setting threshold"
                )

    def get_failure_count(self, signal_id: str) -> int:
        """Return cumulative evaluation failure count for a specific signal."""
        with self._lock:
            return self._execution_failures.get(signal_id, 0)

    def evaluate_all(
        self,
        context: DetectionContext,
        target_signals: Sequence[str] | None = None,
    ) -> tuple[list[SignalResult], list[str]]:
        """Execute applicable signal evaluators with per-evaluator exception isolation.

        Args:
            context: DetectionContext containing root and window events.
            target_signals: Optional subset of signal IDs to evaluate.

        Returns:
            Tuple of (list of SignalResults, list of error descriptions).
        """
        results: list[SignalResult] = []
        errors: list[str] = []

        with self._lock:
            evaluators = list(self._evaluators.values())

        for evaluator in evaluators:
            sig_id = evaluator.signal_id
            if target_signals is not None and sig_id not in target_signals:
                continue

            if not evaluator.is_enabled:
                continue

            try:
                res = evaluator.evaluate(context)
                results.append(res)
            except Exception as exc:
                err_msg = (
                    f"Signal evaluator '{sig_id}' raised exception during "
                    f"evaluation on root '{context.root_id}': {exc}"
                )
                logger.exception(err_msg)
                with self._lock:
                    self._execution_failures[sig_id] = (
                        self._execution_failures.get(sig_id, 0) + 1
                    )
                errors.append(err_msg)

                # Return an explicit failure result so evidence reflects the failure
                results.append(
                    SignalResult(
                        signal_id=sig_id,
                        signal_name=evaluator.name,
                        family=evaluator.family,
                        triggered=False,
                        severity_score=0.0,
                        observed_metric=0.0,
                        threshold=evaluator.threshold,
                        explanation=f"Evaluation failed: {exc}",
                        evidence_event_ids=[],
                        evaluated_at_utc=datetime.now(UTC),
                        metadata={"error": str(exc)},
                    )
                )

        return results, errors

    def clear(self) -> None:
        """Clear all registered evaluators and metrics."""
        with self._lock:
            self._evaluators.clear()
            self._execution_failures.clear()
