# Filename: src/lsoph/monitor/_fileinfo.py
"""
Dataclass definition for storing information about a single tracked file.
"""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# --- Constants ---
# These constants are closely tied to FileInfo state
DEFAULT_EVENT_HISTORY_SIZE = 100
DEFAULT_RECENT_EVENT_TYPES_SIZE = 5


# --- File State Information ---
@dataclass
class FileInfo:
    """Holds state information about a single tracked file."""

    path: str
    status: str = "unknown"  # e.g., unknown, open, closed, active, deleted, error
    last_activity_ts: float = field(default_factory=time.time)
    # Maps PID -> set of open FDs for that PID
    open_by_pids: dict[int, set[int]] = field(default_factory=dict)
    last_event_type: str = ""  # e.g., OPEN, CLOSE, READ, WRITE, STAT, DELETE, RENAME
    last_error_enoent: bool = False  # True if last relevant op failed with ENOENT
    # Stores last N successful event types (e.g., READ, WRITE)
    recent_event_types: deque[str] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_RECENT_EVENT_TYPES_SIZE)
    )
    # Stores history of events (simplified)
    event_history: deque[dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_EVENT_HISTORY_SIZE)
    )
    bytes_read: int = 0
    bytes_written: int = 0
    # Stores additional details from backend events (e.g., mode, source)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        """Checks if any process currently holds this file open according to state."""
        return bool(self.open_by_pids)
