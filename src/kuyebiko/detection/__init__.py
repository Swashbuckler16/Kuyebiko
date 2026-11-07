"""Kuyebiko ransomware behaviour detection engine subsystem."""

from kuyebiko.detection.context import DetectionContext
from kuyebiko.detection.contracts import DetectionEngineProtocol, SignalEvaluator
from kuyebiko.detection.engine import DetectionEngine
from kuyebiko.detection.models import (
    DetectionOutcome,
    DetectionResult,
    SignalFamily,
    SignalResult,
    WindowAggregateStats,
)
from kuyebiko.detection.registry import SignalRegistry
from kuyebiko.detection.signals.base import BaseSignalEvaluator
from kuyebiko.detection.signals.burst_write import BurstWriteSignalEvaluator
from kuyebiko.detection.signals.delete_ratio import DeleteRatioSignalEvaluator
from kuyebiko.detection.signals.directory_traversal import (
    DirectoryTraversalSignalEvaluator,
)
from kuyebiko.detection.signals.extension_convergence import (
    ExtensionConvergenceSignalEvaluator,
)
from kuyebiko.detection.signals.rename_ratio import RenameRatioSignalEvaluator
from kuyebiko.detection.window import RootSlidingWindow, SlidingWindowCorrelator

__all__ = [
    "BaseSignalEvaluator",
    "BurstWriteSignalEvaluator",
    "DeleteRatioSignalEvaluator",
    "DetectionContext",
    "DetectionEngine",
    "DetectionEngineProtocol",
    "DetectionOutcome",
    "DetectionResult",
    "DirectoryTraversalSignalEvaluator",
    "ExtensionConvergenceSignalEvaluator",
    "RenameRatioSignalEvaluator",
    "RootSlidingWindow",
    "SignalEvaluator",
    "SignalFamily",
    "SignalRegistry",
    "SignalResult",
    "SlidingWindowCorrelator",
    "WindowAggregateStats",
]
