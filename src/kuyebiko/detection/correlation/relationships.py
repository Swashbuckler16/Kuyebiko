"""Signal relationship and dependency model for behavioural detection correlation.

Defines behavioural categories, signal relationships, overlapping signal pairs,
and independent family accounting to prevent artificial confidence inflation.
"""

from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from kuyebiko.detection.models import SignalFamily


class BehaviourCategory(StrEnum):
    """Broad behavioural category across multiple signal families."""

    TRANSFORMATION = "transformation"
    DESTRUCTION = "destruction"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"
    ACTIVITY_VOLUME = "activity_volume"
    TRAVERSAL = "traversal"


class SignalRelationship(BaseModel):
    """Describes the relational properties of an individual detection signal."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    signal_id: str = Field(min_length=1)
    family: SignalFamily
    behaviour_category: BehaviourCategory
    related_signals: set[str] = Field(default_factory=set)
    is_primary_attack_indicator: bool = False
    base_confidence_weight: float = Field(default=1.0, ge=0.0, le=2.0)


_KNOWN_RELATIONSHIPS: dict[str, SignalRelationship] = {
    "FS_BURST_WRITE": SignalRelationship(
        signal_id="FS_BURST_WRITE",
        family=SignalFamily.FILESYSTEM_ACTIVITY,
        behaviour_category=BehaviourCategory.ACTIVITY_VOLUME,
        related_signals={"FS_IN_PLACE_TRANSFORMATION"},
        is_primary_attack_indicator=False,
        base_confidence_weight=0.8,
    ),
    "FS_DELETE_RATIO": SignalRelationship(
        signal_id="FS_DELETE_RATIO",
        family=SignalFamily.RENAME_DELETION,
        behaviour_category=BehaviourCategory.DESTRUCTION,
        related_signals={"FS_DATA_DESTRUCTION"},
        is_primary_attack_indicator=False,
        base_confidence_weight=0.8,
    ),
    "FS_DIRECTORY_TRAVERSAL": SignalRelationship(
        signal_id="FS_DIRECTORY_TRAVERSAL",
        family=SignalFamily.DIRECTORY_TRAVERSAL,
        behaviour_category=BehaviourCategory.TRAVERSAL,
        related_signals={"FS_FILESYSTEM_DISCOVERY"},
        is_primary_attack_indicator=False,
        base_confidence_weight=0.7,
    ),
    "FS_RENAME_RATIO": SignalRelationship(
        signal_id="FS_RENAME_RATIO",
        family=SignalFamily.RENAME_DELETION,
        behaviour_category=BehaviourCategory.TRANSFORMATION,
        related_signals={"FS_EXTENSION_CONVERGENCE"},
        is_primary_attack_indicator=True,
        base_confidence_weight=1.1,
    ),
    "FS_EXTENSION_CONVERGENCE": SignalRelationship(
        signal_id="FS_EXTENSION_CONVERGENCE",
        family=SignalFamily.FILE_TRANSFORMATION,
        behaviour_category=BehaviourCategory.TRANSFORMATION,
        related_signals={"FS_RENAME_RATIO", "FS_IN_PLACE_TRANSFORMATION"},
        is_primary_attack_indicator=True,
        base_confidence_weight=1.3,
    ),
    "FS_IN_PLACE_TRANSFORMATION": SignalRelationship(
        signal_id="FS_IN_PLACE_TRANSFORMATION",
        family=SignalFamily.FILE_TRANSFORMATION,
        behaviour_category=BehaviourCategory.TRANSFORMATION,
        related_signals={
            "FS_BURST_WRITE",
            "FS_EXTENSION_CONVERGENCE",
            "FS_LOW_AND_SLOW_ACTIVITY",
        },
        is_primary_attack_indicator=True,
        base_confidence_weight=1.2,
    ),
    "FS_LOW_AND_SLOW_ACTIVITY": SignalRelationship(
        signal_id="FS_LOW_AND_SLOW_ACTIVITY",
        family=SignalFamily.FILE_TRANSFORMATION,
        behaviour_category=BehaviourCategory.TRANSFORMATION,
        related_signals={"FS_IN_PLACE_TRANSFORMATION"},
        is_primary_attack_indicator=True,
        base_confidence_weight=1.2,
    ),
    "FS_RECOVERY_INHIBITION": SignalRelationship(
        signal_id="FS_RECOVERY_INHIBITION",
        family=SignalFamily.RECOVERY_INTERFERENCE,
        behaviour_category=BehaviourCategory.DEFENSE_EVASION,
        related_signals=set(),
        is_primary_attack_indicator=True,
        base_confidence_weight=1.4,
    ),
    "FS_DATA_DESTRUCTION": SignalRelationship(
        signal_id="FS_DATA_DESTRUCTION",
        family=SignalFamily.DATA_DESTRUCTION,
        behaviour_category=BehaviourCategory.DESTRUCTION,
        related_signals={"FS_DELETE_RATIO"},
        is_primary_attack_indicator=True,
        base_confidence_weight=1.3,
    ),
    "FS_FILESYSTEM_DISCOVERY": SignalRelationship(
        signal_id="FS_FILESYSTEM_DISCOVERY",
        family=SignalFamily.FILESYSTEM_DISCOVERY,
        behaviour_category=BehaviourCategory.DISCOVERY,
        related_signals={"FS_DIRECTORY_TRAVERSAL"},
        is_primary_attack_indicator=False,
        base_confidence_weight=0.9,
    ),
    "FS_INDICATOR_REMOVAL": SignalRelationship(
        signal_id="FS_INDICATOR_REMOVAL",
        family=SignalFamily.INDICATOR_REMOVAL,
        behaviour_category=BehaviourCategory.DEFENSE_EVASION,
        related_signals=set(),
        is_primary_attack_indicator=True,
        base_confidence_weight=1.4,
    ),
}


class SignalRelationshipModel:
    """Manages signal dependencies, overlaps, and independent family metrics."""

    def __init__(
        self,
        custom_relationships: dict[str, SignalRelationship] | None = None,
    ) -> None:
        self._relationships: dict[str, SignalRelationship] = dict(_KNOWN_RELATIONSHIPS)
        if custom_relationships:
            self._relationships.update(custom_relationships)

    def get_relationship(self, signal_id: str) -> SignalRelationship | None:
        """Retrieve the relationship definition for a given signal."""
        return self._relationships.get(signal_id)

    def are_signals_related(self, sig1: str, sig2: str) -> bool:
        """Check whether two signals share an overlapping behavioural scope."""
        if sig1 == sig2:
            return True
        rel1 = self._relationships.get(sig1)
        rel2 = self._relationships.get(sig2)

        if rel1 and sig2 in rel1.related_signals:
            return True
        if rel2 and sig1 in rel2.related_signals:
            return True

        if rel1 and rel2:
            return (
                rel1.family == rel2.family
                and rel1.behaviour_category == rel2.behaviour_category
            )

        return False

    def get_independent_families(
        self,
        triggered_signals: Sequence[str],
    ) -> set[SignalFamily]:
        """Return the set of unique signal families represented by triggered signals."""
        families: set[SignalFamily] = set()
        for sig_id in triggered_signals:
            rel = self._relationships.get(sig_id)
            if rel:
                families.add(rel.family)
        return families

    def get_independent_categories(
        self,
        triggered_signals: Sequence[str],
    ) -> set[BehaviourCategory]:
        """Return the set of unique behavioural categories among triggered signals."""
        categories: set[BehaviourCategory] = set()
        for sig_id in triggered_signals:
            rel = self._relationships.get(sig_id)
            if rel:
                categories.add(rel.behaviour_category)
        return categories

    def find_overlapping_pairs(
        self,
        triggered_signals: Sequence[str],
    ) -> list[tuple[str, str]]:
        """Identify pairs of triggered signals that share overlapping definitions."""
        overlaps: list[tuple[str, str]] = []
        sigs = list(triggered_signals)
        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                if self.are_signals_related(sigs[i], sigs[j]):
                    overlaps.append((sigs[i], sigs[j]))
        return overlaps

    def has_primary_attack_indicator(
        self,
        triggered_signals: Sequence[str],
    ) -> bool:
        """Check whether any triggered signal is a primary attack indicator."""
        for sig_id in triggered_signals:
            rel = self._relationships.get(sig_id)
            if rel and rel.is_primary_attack_indicator:
                return True
        return False
