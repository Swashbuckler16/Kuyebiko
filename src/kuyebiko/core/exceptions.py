"""Domain-specific exceptions for the Kuyebiko platform."""


class KuyebikoError(Exception):
    """Base exception for all Kuyebiko errors."""


class CollectorError(KuyebikoError):
    """Base exception for filesystem telemetry collector errors."""


class WatcherError(CollectorError):
    """Raised when a directory watcher fails or encounters invalid operations."""


class RegistryError(CollectorError):
    """Raised when a monitored root registry operation fails."""


class BufferParseError(CollectorError):
    """Raised when raw filesystem notification buffer data is malformed."""


class PathValidationError(CollectorError):
    """Raised when a path fails security or validation rules."""


class NormalizationError(CollectorError, ValueError):
    """Raised when a raw notification cannot be normalized into a valid FileEvent."""


class ProcessingError(KuyebikoError):
    """Base exception for event processing pipeline errors."""


class QueueFullError(ProcessingError):
    """Raised when a bounded event queue cannot accept further notifications."""


class WorkerLifecycleError(ProcessingError):
    """Raised when an invalid worker lifecycle state transition is attempted."""


class PipelineLifecycleError(ProcessingError):
    """Raised when an invalid pipeline lifecycle transition occurs or stop fails."""
