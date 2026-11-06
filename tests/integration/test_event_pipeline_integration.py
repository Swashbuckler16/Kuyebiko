import sys
import time
from pathlib import Path

import pytest

from kuyebiko.collectors.models import MonitoredRoot
from kuyebiko.collectors.registry import MonitoredRootRegistry
from kuyebiko.collectors.windows.watcher import WindowsDirectoryWatcher
from kuyebiko.models.events import EventType
from kuyebiko.processing.contracts import InMemoryEventConsumer
from kuyebiko.processing.ingestion import EventIngestor
from kuyebiko.processing.pipeline import EventPipeline, PipelineLifecycleState
from kuyebiko.processing.queue import BoundedEventQueue
from kuyebiko.processing.telemetry import PipelineHealth
from kuyebiko.processing.worker import EventProcessingWorker

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Requires native Windows ReadDirectoryChangesW",
)


def _wait_for_condition(
    predicate,
    timeout: float = 3.0,
    poll_interval: float = 0.05,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(poll_interval)
    return False


def test_live_windows_watcher_to_processing_pipeline(tmp_path: Path):
    """Verify notifications flow end-to-end through the processing pipeline."""
    monitored_dir = tmp_path / "monitored_pipeline"
    monitored_dir.mkdir()

    root = MonitoredRoot(root_id="pipeline-root", path=monitored_dir)
    queue = BoundedEventQueue(capacity=100)
    ingestor = EventIngestor(queue=queue)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)
    watcher = WindowsDirectoryWatcher(root=root, callback=ingestor)

    worker.start()
    watcher.start()
    time.sleep(0.1)

    try:
        # 1. Create file
        test_file = monitored_dir / "target.txt"
        test_file.write_text("initial content", encoding="utf-8")
        assert _wait_for_condition(
            lambda: any(
                e.event_type == EventType.CREATED for e in consumer.get_events()
            )
        )

        # 2. Modify file
        test_file.write_text("updated content", encoding="utf-8")
        assert _wait_for_condition(
            lambda: any(
                e.event_type == EventType.MODIFIED for e in consumer.get_events()
            )
        )

        # 3. Rename file
        renamed_file = monitored_dir / "target_renamed.txt"
        test_file.rename(renamed_file)
        assert _wait_for_condition(
            lambda: any(
                e.event_type == EventType.RENAMED
                and e.old_path == "target.txt"
                and e.new_path == "target_renamed.txt"
                for e in consumer.get_events()
            )
        )

        # 4. Delete file
        renamed_file.unlink()
        assert _wait_for_condition(
            lambda: any(
                e.event_type == EventType.DELETED for e in consumer.get_events()
            )
        )

    finally:
        watcher.stop()
        worker.stop(timeout=2.0, drain=True)

    events = consumer.get_events()
    assert len(events) >= 4
    for event in events:
        assert event.root_id == "pipeline-root"
        assert event.sequence_number > 0


def test_multi_root_registry_to_event_pipeline(tmp_path: Path):
    """Verify registry routes multiple roots to a shared processing pipeline."""
    dir_a = tmp_path / "root_alpha"
    dir_b = tmp_path / "root_beta"
    dir_a.mkdir()
    dir_b.mkdir()

    root_a = MonitoredRoot(root_id="root-alpha", path=dir_a)
    root_b = MonitoredRoot(root_id="root-beta", path=dir_b)

    queue = BoundedEventQueue(capacity=200)
    ingestor = EventIngestor(queue=queue)
    consumer = InMemoryEventConsumer()
    worker = EventProcessingWorker(queue=queue, consumer=consumer)

    registry = MonitoredRootRegistry(default_callback=ingestor)
    registry.register(root_a)
    registry.register(root_b)

    worker.start()
    registry.start_all()
    time.sleep(0.1)

    try:
        # Create files in both roots
        file_a = dir_a / "alpha_doc.txt"
        file_b = dir_b / "beta_doc.txt"

        file_a.write_text("alpha", encoding="utf-8")
        file_b.write_text("beta", encoding="utf-8")

        assert _wait_for_condition(
            lambda: (
                any(e.root_id == "root-alpha" for e in consumer.get_events())
                and any(e.root_id == "root-beta" for e in consumer.get_events())
            )
        )
    finally:
        registry.stop_all()
        worker.stop(timeout=2.0, drain=True)

    events = consumer.get_events()
    alpha_events = [e for e in events if e.root_id == "root-alpha"]
    beta_events = [e for e in events if e.root_id == "root-beta"]

    assert len(alpha_events) >= 1
    assert len(beta_events) >= 1
    assert alpha_events[0].file_path == "alpha_doc.txt"
    assert beta_events[0].file_path == "beta_doc.txt"


def test_event_pipeline_coordinator_live_windows(tmp_path: Path):
    """End-to-end integration test of EventPipeline with live directory watcher."""
    work_dir = tmp_path / "coordinator_root"
    work_dir.mkdir()

    root = MonitoredRoot(root_id="live-root", path=work_dir)
    consumer = InMemoryEventConsumer()
    pipeline = EventPipeline(consumer=consumer, poll_timeout=0.01)
    pipeline.register_root(root)

    assert pipeline.state == PipelineLifecycleState.STOPPED
    pipeline.start()
    assert pipeline.state == PipelineLifecycleState.RUNNING

    try:
        # Create a file
        f = work_dir / "live_test.txt"
        f.write_text("live data", encoding="utf-8")

        assert _wait_for_condition(
            lambda: any(e.file_path == "live_test.txt" for e in consumer.get_events()),
            timeout=3.0,
        )

        snap = pipeline.snapshot()
        assert snap.health == PipelineHealth.HEALTHY
        assert snap.registered_watchers == 1
        assert snap.active_watchers == 1
        assert snap.total_submitted >= 1
    finally:
        pipeline.stop(timeout=3.0, drain=True)

    assert pipeline.state == PipelineLifecycleState.STOPPED
    assert pipeline.is_running is False
