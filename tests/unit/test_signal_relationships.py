"""Unit tests for the signal relationship and dependency model."""

from kuyebiko.detection.correlation.relationships import (
    BehaviourCategory,
    SignalRelationship,
    SignalRelationshipModel,
)
from kuyebiko.detection.models import SignalFamily


def test_default_relationships_coverage() -> None:
    """Verify default signals have structured relationship definitions."""
    model = SignalRelationshipModel()
    expected_signals = [
        "FS_BURST_WRITE",
        "FS_DELETE_RATIO",
        "FS_DIRECTORY_TRAVERSAL",
        "FS_RENAME_RATIO",
        "FS_EXTENSION_CONVERGENCE",
        "FS_IN_PLACE_TRANSFORMATION",
        "FS_LOW_AND_SLOW_ACTIVITY",
        "FS_RECOVERY_INHIBITION",
        "FS_DATA_DESTRUCTION",
        "FS_FILESYSTEM_DISCOVERY",
        "FS_INDICATOR_REMOVAL",
    ]
    for sig_id in expected_signals:
        rel = model.get_relationship(sig_id)
        assert rel is not None
        assert rel.signal_id == sig_id
        assert isinstance(rel.family, SignalFamily)
        assert isinstance(rel.behaviour_category, BehaviourCategory)


def test_signal_overlap_detection() -> None:
    """Verify known overlapping signal pairs are identified as related."""
    model = SignalRelationshipModel()

    # Known overlapping pairs
    assert model.are_signals_related("FS_DELETE_RATIO", "FS_DATA_DESTRUCTION")
    assert model.are_signals_related("FS_DATA_DESTRUCTION", "FS_DELETE_RATIO")
    assert model.are_signals_related("FS_BURST_WRITE", "FS_IN_PLACE_TRANSFORMATION")
    assert model.are_signals_related("FS_RENAME_RATIO", "FS_EXTENSION_CONVERGENCE")
    assert model.are_signals_related(
        "FS_DIRECTORY_TRAVERSAL", "FS_FILESYSTEM_DISCOVERY"
    )

    # Independent signals
    assert not model.are_signals_related("FS_BURST_WRITE", "FS_RECOVERY_INHIBITION")
    assert not model.are_signals_related("FS_DATA_DESTRUCTION", "FS_INDICATOR_REMOVAL")


def test_independent_family_and_category_accounting() -> None:
    """Verify independent family and category sets are accurately computed."""
    model = SignalRelationshipModel()

    triggered = ["FS_DELETE_RATIO", "FS_DATA_DESTRUCTION"]
    families = model.get_independent_families(triggered)
    categories = model.get_independent_categories(triggered)

    # Note: DELETE_RATIO is RENAME_DELETION, DATA_DESTRUCTION is DATA_DESTRUCTION
    assert len(families) == 2
    # Both belong to DESTRUCTION category
    assert len(categories) == 1
    assert BehaviourCategory.DESTRUCTION in categories

    multi_triggered = [
        "FS_BURST_WRITE",
        "FS_RECOVERY_INHIBITION",
        "FS_EXTENSION_CONVERGENCE",
    ]
    multi_families = model.get_independent_families(multi_triggered)
    multi_categories = model.get_independent_categories(multi_triggered)

    assert len(multi_families) == 3
    assert len(multi_categories) == 3


def test_custom_relationship_injection() -> None:
    """Verify custom signal relationships can extend or override defaults."""
    custom = {
        "CUSTOM_CANARY": SignalRelationship(
            signal_id="CUSTOM_CANARY",
            family=SignalFamily.CANARY_INTERACTION,
            behaviour_category=BehaviourCategory.DEFENSE_EVASION,
            related_signals={"CUSTOM_TRIGGER"},
            is_primary_attack_indicator=True,
        )
    }
    model = SignalRelationshipModel(custom_relationships=custom)
    rel = model.get_relationship("CUSTOM_CANARY")
    assert rel is not None
    assert rel.is_primary_attack_indicator
    assert model.are_signals_related("CUSTOM_CANARY", "CUSTOM_TRIGGER")
