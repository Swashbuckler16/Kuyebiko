"""Architectural contracts and consumer interfaces for event processing.

Defines the ingestion outcome states, downstream event consumer protocols,
event envelopes with ordering metadata, and reference consumer implementations
connecting Phase 2 filesystem watchers to downstream components.
"""

import threading
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from kuyebiko.models.events import FileEvent
from kuyebiko.processing.ordering import EventOrderingMetadata


class IngestionOutcome(StrEnum):
    """Outcome of submitting a raw notification to the ingestion interface."""

    ACCEPTED = "accepted"
    QUEUE_FULL = "queue_full"
    REJECTED = "rejected"
    SHUTTING_DOWN = "shutting_down"


class EventEnvelope(BaseModel):
    """Container pairing a validated FileEvent with ordering metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event: FileEvent
    ordering: EventOrderingMetadata


@runtime_checkable
class EventConsumer(Protocol):
    """Downstream consumer interface for receiving normalized FileEvent objects."""

    def handle_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
    ) -> None:
        """Process a validated and normalized FileEvent.

        Args:
            event: Validated FileEvent produced by the normalization pipeline.
            ordering: Optional chronology and latency metadata for the event.
        """
        ...


class CallbackEventConsumer:
    """Event consumer that delegates each FileEvent to a callable."""

    def __init__(self, callback: Callable[..., None]) -> None:
        if not callable(callback):
            raise TypeError("callback must be callable")
        self._callback = callback

    def handle_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
    ) -> None:
        """Delegate event and ordering metadata to the registered callable.

        Supports callbacks accepting either `(event, ordering)` or `(event)`.
        """
        try:
            self._callback(event, ordering)
        except TypeError:
            self._callback(event)


class InMemoryEventConsumer:
    """Thread-safe in-memory event consumer for testing, inspection, and telemetry."""

    def __init__(self, max_events: int | None = None) -> None:
        self._max_events = max_events
        self._events: deque[FileEvent] = deque(maxlen=max_events)
        self._envelopes: deque[EventEnvelope] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def handle_event(
        self,
        event: FileEvent,
        ordering: EventOrderingMetadata | None = None,
    ) -> None:
        """Append event and its envelope to thread-safe internal buffers."""
        with self._lock:
            self._events.append(event)
            if ordering is not None:
                self._envelopes.append(EventEnvelope(event=event, ordering=ordering))

    def get_events(self) -> list[FileEvent]:
        """Return a snapshot copy of all buffered events."""
        with self._lock:
            return list(self._events)

    def get_envelopes(self) -> list[EventEnvelope]:
        """Return a snapshot copy of all event envelopes with ordering metadata."""
        with self._lock:
            return list(self._envelopes)

    def clear(self) -> None:
        """Clear all buffered events and envelopes."""
        with self._lock:
            self._events.clear()
            self._envelopes.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
