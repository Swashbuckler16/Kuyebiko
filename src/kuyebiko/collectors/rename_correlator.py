import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from kuyebiko.collectors.models import RawFileNotification, WindowsFileAction

logger = logging.getLogger("kuyebiko.collectors.rename_correlator")


@dataclass(frozen=True, slots=True)
class CorrelatedRenameNotification:
    """A verified, correlated rename pair containing both old and new paths."""

    root_id: str
    old_path: str
    new_path: str
    observed_at: datetime
    monotonic_ns: int
    is_directory: bool | None = None
    old_notification: RawFileNotification | None = None
    new_notification: RawFileNotification | None = None


class RenameCorrelator:
    """Thread-safe stateful correlator for Windows two-part rename notifications.

    Correlates FILE_ACTION_RENAMED_OLD_NAME and FILE_ACTION_RENAMED_NEW_NAME
    notifications within a bounded time window. Enforces strict root isolation,
    bounded memory, temporal proximity pairing, and expired notification eviction.
    """

    def __init__(
        self,
        correlation_window_ns: int = 1_000_000_000,  # 1.0 second default
        max_pending_per_root: int = 1000,
    ) -> None:
        self._window_ns = max(10_000_000, correlation_window_ns)
        self._max_pending = max(1, max_pending_per_root)
        self._pending: dict[str, deque[RawFileNotification]] = {}
        self._lock = threading.Lock()

    def process_notification(
        self,
        notification: RawFileNotification,
    ) -> CorrelatedRenameNotification | None:
        """Process a notification and attempt correlation if it is a rename action.

        If notification is RENAMED_OLD_NAME:
            Buffers it pending correlation, evicts oldest if queue full,
            and returns None.

        If notification is RENAMED_NEW_NAME:
            Finds the best-matching unexpired RENAMED_OLD_NAME for the same root_id
            using temporal proximity and directory alignment.
            If matched, returns CorrelatedRenameNotification, otherwise None.

        If notification is any other action:
            Returns None (not a rename action).
        """
        if notification.action == WindowsFileAction.RENAMED_OLD_NAME:
            with self._lock:
                queue = self._pending.setdefault(notification.root_id, deque())
                if len(queue) >= self._max_pending:
                    dropped = queue.popleft()
                    logger.warning(
                        "Pending rename buffer full for root '%s'; "
                        "evicted oldest entry '%s'",
                        notification.root_id,
                        dropped.relative_path,
                    )
                queue.append(notification)
            return None

        if notification.action == WindowsFileAction.RENAMED_NEW_NAME:
            with self._lock:
                queue = self._pending.get(notification.root_id)
                if not queue:
                    logger.warning(
                        "Received RENAMED_NEW_NAME for '%s' without pending "
                        "old name in root '%s'",
                        notification.relative_path,
                        notification.root_id,
                    )
                    return None

                now_ns = notification.monotonic_ns
                new_parent = Path(notification.relative_path).parent

                # Separate unexpired candidates from expired ones
                unexpired: list[RawFileNotification] = []
                while queue:
                    item = queue.popleft()
                    if now_ns - item.monotonic_ns <= self._window_ns:
                        unexpired.append(item)
                    else:
                        logger.warning(
                            "Evicting expired unmatched old rename '%s' "
                            "(age %.3fs) in root '%s'",
                            item.relative_path,
                            (now_ns - item.monotonic_ns) / 1e9,
                            item.root_id,
                        )

                if not unexpired:
                    logger.warning(
                        "No unexpired old name found for RENAMED_NEW_NAME '%s' "
                        "in root '%s'",
                        notification.relative_path,
                        notification.root_id,
                    )
                    return None

                # Find best matching candidate:
                # 1. Candidate with smallest time delta to this new notification
                # 2. Preference given to same parent directory if time deltas are equal
                def match_score(candidate: RawFileNotification) -> tuple[int, int]:
                    time_delta = abs(candidate.monotonic_ns - now_ns)
                    same_parent = (
                        0 if Path(candidate.relative_path).parent == new_parent else 1
                    )
                    return (time_delta, same_parent)

                best_idx = 0
                best_score = match_score(unexpired[0])
                for idx in range(1, len(unexpired)):
                    score = match_score(unexpired[idx])
                    if score < best_score:
                        best_score = score
                        best_idx = idx

                matched_old = unexpired.pop(best_idx)

                # Re-queue remaining unexpired candidates for future renames
                for remaining in unexpired:
                    queue.append(remaining)

                if matched_old.relative_path == notification.relative_path:
                    logger.warning(
                        "Rename old and new paths are identical ('%s'); "
                        "rejected self-rename anomaly",
                        notification.relative_path,
                    )
                    return None

                return CorrelatedRenameNotification(
                    root_id=notification.root_id,
                    old_path=matched_old.relative_path,
                    new_path=notification.relative_path,
                    observed_at=notification.observed_at,
                    monotonic_ns=notification.monotonic_ns,
                    is_directory=(
                        notification.is_directory or matched_old.is_directory
                    ),
                    old_notification=matched_old,
                    new_notification=notification,
                )

        return None

    def evict_expired(self, current_monotonic_ns: int) -> list[RawFileNotification]:
        """Evict and return all pending old notifications older than window."""
        evicted: list[RawFileNotification] = []
        with self._lock:
            for root_id, queue in list(self._pending.items()):
                remaining: deque[RawFileNotification] = deque()
                while queue:
                    item = queue.popleft()
                    if current_monotonic_ns - item.monotonic_ns > self._window_ns:
                        evicted.append(item)
                    else:
                        remaining.append(item)
                if remaining:
                    self._pending[root_id] = remaining
                else:
                    self._pending.pop(root_id, None)
        return evicted

    def pending_count(self, root_id: str | None = None) -> int:
        """Return count of currently pending old rename notifications."""
        with self._lock:
            if root_id is not None:
                return len(self._pending.get(root_id, []))
            return sum(len(q) for q in self._pending.values())

    def clear(self, root_id: str | None = None) -> None:
        """Clear pending renames for a root or all roots."""
        with self._lock:
            if root_id is not None:
                self._pending.pop(root_id, None)
            else:
                self._pending.clear()
