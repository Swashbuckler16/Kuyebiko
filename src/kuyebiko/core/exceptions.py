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
