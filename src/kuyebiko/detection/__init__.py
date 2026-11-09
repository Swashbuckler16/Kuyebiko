"""Kuyebiko ransomware behaviour detection engine subsystem."""

from kuyebiko.detection.advanced import (
    AdvancedSignalEvaluator,
    DiscoveryTelemetryEvent,
    EventLogTelemetryEvent,
    ProcessTelemetryEvent,
    SignalMetadata,
    TelemetryCapability,
)
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
from kuyebiko.detection.signals.data_destruction import DataDestructionSignalEvaluator
from kuyebiko.detection.signals.delete_ratio import DeleteRatioSignalEvaluator
from kuyebiko.detection.signals.directory_traversal import (
    DirectoryTraversalSignalEvaluator,
)
from kuyebiko.detection.signals.extension_convergence import (
    ExtensionConvergenceSignalEvaluator,
)
from kuyebiko.detection.signals.filesystem_discovery import (
    FilesystemDiscoverySignalEvaluator,
)
from kuyebiko.detection.signals.indicator_removal import IndicatorRemovalSignalEvaluator
from kuyebiko.detection.signals.recovery_inhibition import (
    RecoveryInhibitionSignalEvaluator,
)
from kuyebiko.detection.signals.rename_ratio import RenameRatioSignalEvaluator
from kuyebiko.detection.window import RootSlidingWindow, SlidingWindowCorrelator

__all__ = [
    "AdvancedSignalEvaluator",
    "BaseSignalEvaluator",
    "BurstWriteSignalEvaluator",
    "DataDestructionSignalEvaluator",
    "DeleteRatioSignalEvaluator",
    "DetectionContext",
    "DetectionEngine",
    "DetectionEngineProtocol",
    "DetectionOutcome",
    "DetectionResult",
    "DirectoryTraversalSignalEvaluator",
    "DiscoveryTelemetryEvent",
    "EventLogTelemetryEvent",
    "ExtensionConvergenceSignalEvaluator",
    "FilesystemDiscoverySignalEvaluator",
    "IndicatorRemovalSignalEvaluator",
    "ProcessTelemetryEvent",
    "RecoveryInhibitionSignalEvaluator",
    "RenameRatioSignalEvaluator",
    "RootSlidingWindow",
    "SignalEvaluator",
    "SignalFamily",
    "SignalMetadata",
    "SignalRegistry",
    "SignalResult",
    "SlidingWindowCorrelator",
    "TelemetryCapability",
    "WindowAggregateStats",
]
