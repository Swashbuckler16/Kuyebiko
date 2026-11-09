"""Kuyebiko behavioural detection correlation subsystem.

Provides multi-signal correlation, evidence deduplication, relationship modeling,
and explainability reporting for Windows ransomware detection.
"""

from kuyebiko.detection.correlation.engine import CorrelationEngine
from kuyebiko.detection.correlation.evidence import (
    DeduplicatedEvidence,
    deduplicate_evidence,
)
from kuyebiko.detection.correlation.explainability import (
    DetectionExplanation,
    ExplainabilityEngine,
)
from kuyebiko.detection.correlation.relationships import (
    BehaviourCategory,
    SignalRelationship,
    SignalRelationshipModel,
)

__all__ = [
    "BehaviourCategory",
    "CorrelationEngine",
    "DeduplicatedEvidence",
    "DetectionExplanation",
    "ExplainabilityEngine",
    "SignalRelationship",
    "SignalRelationshipModel",
    "deduplicate_evidence",
]
