"""Architectural contracts and consumer interfaces for event processing.

Defines the ingestion outcome states, downstream event consumer protocols,
and reference consumer implementations connecting Phase 2 filesystem watchers
to downstream correlation and detection components.
"""

import threading
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Protocol, runtime_checkable

from kuyebiko.models.events import FileEvent


class IngestionOutcome(StrEnum):
    """Outcome of submitting a raw notification to the ingestion interface."""

    ACCEPTED = "accepted"
    QUEUE_FULL = "queue_full"
    REJECTED = "rejected"
    SHUTTING_DOWN = "shutting_down"


@runtime_checkable
class EventConsumer(Protocol):
    """Downstream consumer interface for receiving normalized FileEvent objects."""

    def handle_event(self, event: FileEvent) -> None:
        """Process a validated and normalized FileEvent.

        Args:
            event: Validated FileEvent produced by the normalization pipeline.
        """
        ...


class CallbackEventConsumer:
    """Event consumer that delegates each FileEvent to a callable."""

    def __init__(self, callback: Callable[[FileEvent], None]) -> None:
        if not callable(callback):
            raise TypeError("callback must be callable")
        self._callback = callback

    def handle_event(self, event: FileEvent) -> None:
        """Delegate event to the registered callable."""
        self._callback(event)


class InMemoryEventConsumer:
    """Thread-safe in-memory event consumer for testing, inspection, and telemetry."""

    def __init__(self, max_events: int | None = None) -> None:
        self._max_events = max_events
        self._events: deque[FileEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def handle_event(self, event: FileEvent) -> None:
        """Append event to thread-safe internal buffer."""
        with self._lock:
            self._events.append(event)

    def get_events(self) -> list[FileEvent]:
        """Return a snapshot copy of all buffered events."""
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        """Clear all buffered events."""
        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
