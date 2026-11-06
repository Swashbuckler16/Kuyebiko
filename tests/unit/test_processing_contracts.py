import threading
from datetime import UTC, datetime

import pytest

from kuyebiko.models.events import EventSource, EventType, FileEvent, TelemetryQuality
from kuyebiko.processing.contracts import (
    CallbackEventConsumer,
    EventConsumer,
    IngestionOutcome,
    InMemoryEventConsumer,
)


def _make_dummy_event(sequence_number: int = 1) -> FileEvent:
    return FileEvent(
        event_id=f"evt-{sequence_number}",
        root_id="root-1",
        file_path="test.txt",
        event_type=EventType.CREATED,
        timestamp_utc=datetime.now(UTC),
        monotonic_ns=1000 + sequence_number,
        source=EventSource.WINDOWS_WATCHER,
        sequence_number=sequence_number,
        quality=TelemetryQuality.NORMAL,
    )


def test_ingestion_outcome_enum_values():
    assert IngestionOutcome.ACCEPTED == "accepted"
    assert IngestionOutcome.QUEUE_FULL == "queue_full"
    assert IngestionOutcome.REJECTED == "rejected"
    assert IngestionOutcome.SHUTTING_DOWN == "shutting_down"


def test_event_consumer_protocol_conformance():
    class CustomConsumer:
        def handle_event(self, event: FileEvent) -> None:
            pass

    assert isinstance(CustomConsumer(), EventConsumer)
    assert isinstance(CallbackEventConsumer(lambda e: None), EventConsumer)
    assert isinstance(InMemoryEventConsumer(), EventConsumer)


def test_callback_event_consumer_dispatch():
    received = []

    def callback(event: FileEvent) -> None:
        received.append(event)

    consumer = CallbackEventConsumer(callback)
    evt = _make_dummy_event(1)
    consumer.handle_event(evt)

    assert len(received) == 1
    assert received[0] == evt


def test_callback_event_consumer_rejects_non_callable():
    with pytest.raises(TypeError, match="callback must be callable"):
        CallbackEventConsumer("not_callable")  # type: ignore[arg-type]


def test_in_memory_event_consumer_buffering():
    consumer = InMemoryEventConsumer(max_events=10)
    assert len(consumer) == 0

    evt1 = _make_dummy_event(1)
    evt2 = _make_dummy_event(2)

    consumer.handle_event(evt1)
    consumer.handle_event(evt2)

    assert len(consumer) == 2
    events = consumer.get_events()
    assert events == [evt1, evt2]

    # Verify returned list is a copy
    events.clear()
    assert len(consumer) == 2

    consumer.clear()
    assert len(consumer) == 0
    assert consumer.get_events() == []


def test_in_memory_event_consumer_maxlen():
    consumer = InMemoryEventConsumer(max_events=2)
    consumer.handle_event(_make_dummy_event(1))
    consumer.handle_event(_make_dummy_event(2))
    consumer.handle_event(_make_dummy_event(3))

    assert len(consumer) == 2
    events = consumer.get_events()
    assert [e.sequence_number for e in events] == [2, 3]


def test_in_memory_event_consumer_thread_safety():
    consumer = InMemoryEventConsumer()
    num_threads = 8
    events_per_thread = 50

    def worker(thread_idx: int) -> None:
        for i in range(events_per_thread):
            consumer.handle_event(_make_dummy_event(thread_idx * 1000 + i))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(consumer) == num_threads * events_per_thread
