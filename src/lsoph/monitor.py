import logging
import os
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Dict, Set  # Added Dict, Any, Set for type hints

from lsoph.util.versioned import Versioned, changes, waits

# --- Setup Logging ---
log = logging.getLogger("lsoph.monitor")  # Use package-aware logger name

# --- Constants ---
STDIN_PATH = "<STDIN>"
STDOUT_PATH = "<STDOUT>"
STDERR_PATH = "<STDERR>"
STD_PATHS = {STDIN_PATH, STDOUT_PATH, STDERR_PATH}


# --- File State Information ---
@dataclass
class FileInfo:
    """Holds state information about a single tracked file."""

    path: str
    status: str = "unknown"
    last_activity_ts: float = field(default_factory=time.time)
    open_by_pids: Dict[int, Set[int]] = field(
        default_factory=dict
    )  # Key: pid, Value: set[fd]
    last_event_type: str = ""
    last_error_enoent: bool = False
    recent_event_types: deque[str] = field(default_factory=lambda: deque(maxlen=5))
    event_history: deque[Dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=100)
    )
    bytes_read: int = 0
    bytes_written: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        """Checks if any process currently holds this file open according to state."""
        return bool(self.open_by_pids)


# --- Monitor Class (Manages State for a Monitored Target) ---
class Monitor(Versioned):
    """
    Manages the state of files accessed by a monitored target (process group).
    Inherits from Versioned for change tracking and thread safety.
    Provides direct iteration and dictionary-style access.
    """

    def __init__(self, identifier: str):
        """Initialize the Monitor.

        Args:
            identifier: A string identifying the monitoring session (e.g., command or PIDs).
        """
        super().__init__()
        self.identifier = identifier
        self.ignored_paths: Set[str] = set()
        self.pid_fd_map: Dict[int, Dict[int, str]] = {}  # PID -> FD -> Path
        self.files: Dict[str, FileInfo] = {}  # Path -> FileInfo
        # --- ADDED: Store the PID of the backend process (e.g., strace) ---
        self.backend_pid: int | None = None
        # -----------------------------------------------------------------
        log.info(f"Initialized Monitor for identifier: '{identifier}'")

    def _cache_info(self, path: str, timestamp: float) -> FileInfo | None:
        """Gets existing FileInfo or creates a new one, checking ignore list."""
        if path in self.ignored_paths or path in STD_PATHS:
            log.debug(f"Ignoring event for path: {path}")
            return None
        if path not in self.files:
            log.debug(f"Creating new FileInfo for path: {path}")
            self.files[path] = FileInfo(
                path=path, last_activity_ts=timestamp, status="accessed"
            )
        self.files[path].last_activity_ts = timestamp
        return self.files[path]

    def _add_event_to_history(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: dict,
    ):
        """Adds a simplified event representation to the file's history."""
        simple_details = {
            k: v for k, v in details.items() if k not in ["read_data", "write_data"]
        }
        info.event_history.append(
            {
                "ts": timestamp,
                "type": event_type,
                "success": success,
                "details": simple_details,
            }
        )
        if success:
            if not info.recent_event_types or info.recent_event_types[-1] != event_type:
                info.recent_event_types.append(event_type)

    # --- Public Handler Methods ---
    @changes
    def ignore(self, path: str):
        """Adds a path to the ignore list (in-memory only)."""
        if (
            not isinstance(path, str)
            or not path
            or path in STD_PATHS
            or path in self.ignored_paths
        ):
            return
        log.info(f"Adding path to ignore list for '{self.identifier}': {path}")
        self.ignored_paths.add(path)
        if path not in self.files:
            return

        log.debug(f"Removing ignored path from active state: {path}")
        pids_with_path = []
        for pid, fd_map in list(self.pid_fd_map.items()):
            fds_to_remove = {fd for fd, p in fd_map.items() if p == path}
            if fds_to_remove:
                pids_with_path.append(pid)
                for fd in fds_to_remove:
                    log.debug(
                        f"Removing FD mapping for ignored path: PID {pid}, FD {fd}"
                    )
                    del fd_map[fd]
        for pid in pids_with_path:
            if pid in self.pid_fd_map and not self.pid_fd_map[pid]:
                del self.pid_fd_map[pid]
        del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list (in-memory only)."""
        log.info(f"Ignoring all currently tracked files for '{self.identifier}'")
        ignores = [p for p in self.files.keys() if p not in STD_PATHS]
        count = 0
        for path in ignores:
            if path not in self.ignored_paths:
                self.ignore(path)
                count += 1
        log.info(f"Added {count} paths to ignore list via ignore_all.")

    @changes
    def open(
        self, pid: int, path: str, fd: int, success: bool, timestamp: float, **details
    ):
        log.debug(f"open: pid={pid}, path={path}, fd={fd}, success={success}")
        info = self._cache_info(path, timestamp)
        if not info:
            return
        details_for_finalize = details.copy()
        self._finalize_update(info, "OPEN", success, timestamp, details_for_finalize)
        if success and fd >= 0:
            if info.status != "deleted":
                info.status = "open"
            if pid not in self.pid_fd_map:
                self.pid_fd_map[pid] = {}
            self.pid_fd_map[pid][fd] = path
            if pid not in info.open_by_pids:
                info.open_by_pids[pid] = set()
            info.open_by_pids[pid].add(fd)
            log.debug(
                f"Mapped PID {pid} FD {fd} -> '{path}', PIDs with open FDs: {list(info.open_by_pids.keys())}"
            )
        elif not success:
            if info.status != "deleted":
                info.status = "error"
        elif success and fd < 0:
            log.warning(
                f"Successful open reported for path '{path}' but FD is invalid ({fd})"
            )
            if info.status != "deleted":
                info.status = "error"

    @changes
    def close(self, pid: int, fd: int, success: bool, timestamp: float, **details):
        log.debug(f"close: pid={pid}, fd={fd}, success={success}")
        path = self.get_path(pid, fd)
        if success and pid in self.pid_fd_map and fd in self.pid_fd_map.get(pid, {}):
            mapped_path = self.pid_fd_map[pid][fd]
            if path is None or mapped_path == path:
                del self.pid_fd_map[pid][fd]
                log.debug(
                    f"Removed mapping for PID {pid} FD {fd} (path: {mapped_path})"
                )
                if not self.pid_fd_map[pid]:
                    del self.pid_fd_map[pid]
            else:
                log.warning(
                    f"Close success for PID {pid} FD {fd}, but map pointed to '{mapped_path}' instead of expected '{path}'. Map not removed."
                )

        if not path or path in STD_PATHS:
            if not path:
                log.debug(
                    f"Close event for unknown PID {pid} FD {fd}, no FileInfo update."
                )
            else:
                log.debug(
                    f"Ignoring close event state update for standard stream: {path}"
                )
            return

        info = self.files.get(path)
        if not info:
            log.warning(
                f"Close event for PID {pid} FD {fd} refers to path '{path}' not in state. No FileInfo update."
            )
            return

        details_for_finalize = details.copy()
        self._finalize_update(info, "CLOSE", success, timestamp, details_for_finalize)
        if not success:
            if info.status == "deleted":
                pass
            elif info.is_open:
                info.status = "open"
            else:
                info.status = "error"
            return

        if pid in info.open_by_pids:
            if fd in info.open_by_pids[pid]:
                info.open_by_pids[pid].remove(fd)
                log.debug(f"Removed FD {fd} from open set for PID {pid} ('{path}')")
            if not info.open_by_pids[pid]:
                del info.open_by_pids[pid]

        if not info.is_open and info.status != "deleted":
            info.status = "closed"
            log.debug(f"Path '{path}' marked as closed.")
        elif info.is_open and info.status != "deleted":
            info.status = "open"

    @changes
    def read(
        self,
        pid: int,
        fd: int,
        path: str | None,
        success: bool,
        timestamp: float,
        **details,
    ):
        log.debug(
            f"read: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        if path is None:
            path = self.get_path(pid, fd)
        if not path or path in STD_PATHS:
            if not path:
                log.debug(f"Read event for PID {pid} FD {fd} could not resolve path.")
            else:
                log.debug(f"Ignoring read event details for standard stream: {path}")
            return

        info = self._cache_info(path, timestamp)
        if not info:
            return
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
            info.bytes_read += byte_count
        details_for_finalize = details.copy()
        self._finalize_update(info, "READ", success, timestamp, details_for_finalize)
        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in ["deleted", "open"]:
            info.status = "error"

    @changes
    def write(
        self,
        pid: int,
        fd: int,
        path: str | None,
        success: bool,
        timestamp: float,
        **details,
    ):
        log.debug(
            f"write: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        if path is None:
            path = self.get_path(pid, fd)
        if not path or path in STD_PATHS:
            if not path:
                log.debug(f"Write event for PID {pid} FD {fd} could not resolve path.")
            else:
                log.debug(f"Ignoring write event details for standard stream: {path}")
            return

        info = self._cache_info(path, timestamp)
        if not info:
            return
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count > 0:
            info.bytes_written += byte_count
        details_for_finalize = details.copy()
        self._finalize_update(info, "WRITE", success, timestamp, details_for_finalize)
        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in ["deleted", "open"]:
            info.status = "error"

    @changes
    def stat(self, pid: int, path: str, success: bool, timestamp: float, **details):
        log.debug(f"stat: pid={pid}, path={path}, success={success}")
        info = self._cache_info(path, timestamp)
        if not info:
            return
        details_for_finalize = details.copy()
        self._finalize_update(info, "STAT", success, timestamp, details_for_finalize)
        if success:
            if info.status not in ["open", "deleted", "active", "error"]:
                info.status = "accessed"
        else:
            if info.status != "deleted":
                info.status = "error"

    @changes
    def delete(self, pid: int, path: str, success: bool, timestamp: float, **details):
        log.debug(f"delete: pid={pid}, path={path}, success={success}")
        info = self.files.get(path)
        if not info:
            log.debug(f"Delete event for untracked path: {path}")
            return

        details_for_finalize = details.copy()
        self._finalize_update(info, "DELETE", success, timestamp, details_for_finalize)
        if not success:
            if info.status not in ["deleted", "open"]:
                info.status = "error"
            return

        info.status = "deleted"
        pids_holding_open = list(info.open_by_pids.keys())
        for check_pid in pids_holding_open:
            fds_to_remove = set(info.open_by_pids.get(check_pid, set()))
            for fd in fds_to_remove:
                log.debug(
                    f"Removing FD mapping due to delete: PID {check_pid}, FD {fd}"
                )
                if (
                    check_pid in self.pid_fd_map
                    and fd in self.pid_fd_map.get(check_pid, {})
                    and self.pid_fd_map[check_pid][fd] == path
                ):
                    del self.pid_fd_map[check_pid][fd]
                    if not self.pid_fd_map[check_pid]:
                        del self.pid_fd_map[check_pid]
            if check_pid in info.open_by_pids:
                del info.open_by_pids[check_pid]
        info.open_by_pids.clear()

    @changes
    def rename(
        self,
        pid: int,
        old_path: str,
        new_path: str,
        success: bool,
        timestamp: float,
        **details,
    ):
        log.debug(
            f"rename: pid={pid}, old={old_path}, new={new_path}, success={success}"
        )
        old_is_ignored = old_path in self.ignored_paths
        new_is_ignored = new_path in self.ignored_paths
        if new_is_ignored:
            log.info(f"Rename target path '{new_path}' is ignored.")
            if success and not old_is_ignored and old_path in self.files:
                self.delete(
                    pid, old_path, True, timestamp, {"renamed_to_ignored": new_path}
                )
            elif not success and not old_is_ignored and old_path in self.files:
                info_old = self.files[old_path]
                details_for_finalize = details.copy()
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, details_for_finalize
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            return
        if old_is_ignored:
            log.warning(
                f"Rename source path '{old_path}' is ignored (event on PID {pid})."
            )
            if success:
                self.stat(
                    pid, new_path, True, timestamp, {"renamed_from_ignored": old_path}
                )
            return

        if not success:
            info = self.files.get(old_path)
            if not info:
                return
            details_for_finalize = details.copy()
            self._finalize_update(
                info, "RENAME", success, timestamp, details_for_finalize
            )
            if info.status != "deleted":
                info.status = "error"
            return

        old_info = self.files.get(old_path)
        if not old_info:
            log.debug(
                f"Rename source path '{old_path}' not tracked. Treating as access to target '{new_path}'."
            )
            self.stat(
                pid, new_path, True, timestamp, {"renamed_from_unknown": old_path}
            )
            return

        log.info(f"Processing successful rename: '{old_path}' -> '{new_path}'")
        new_info = self._cache_info(new_path, timestamp)
        if not new_info:
            log.error(
                f"Could not get/create FileInfo for rename target '{new_path}'. State may be inconsistent."
            )
            self.delete(
                pid,
                old_path,
                True,
                timestamp,
                {"error": "Rename target state creation failed"},
            )
            return

        new_info.status = (
            old_info.status if old_info.status != "deleted" else "accessed"
        )
        new_info.open_by_pids = old_info.open_by_pids
        new_info.bytes_read = old_info.bytes_read
        new_info.bytes_written = old_info.bytes_written
        new_info.last_event_type = old_info.last_event_type
        new_info.last_error_enoent = old_info.last_error_enoent
        new_info.details = old_info.details

        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        self._add_event_to_history(
            old_info, "RENAME", success, timestamp, details_for_old
        )
        self._add_event_to_history(
            new_info, "RENAME", success, timestamp, details_for_new
        )
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        pids_fds_to_update: list[tuple[int, int]] = []
        for map_pid, fd_map in self.pid_fd_map.items():
            for map_fd, map_path in fd_map.items():
                if map_path == old_path:
                    pids_fds_to_update.append((map_pid, map_fd))
        if pids_fds_to_update:
            log.info(
                f"Rename: Updating {len(pids_fds_to_update)} FD map entries: '{old_path}' -> '{new_path}'"
            )
            for update_pid, update_fd in pids_fds_to_update:
                if (
                    update_pid in self.pid_fd_map
                    and update_fd in self.pid_fd_map[update_pid]
                ):
                    self.pid_fd_map[update_pid][update_fd] = new_path

        log.debug(f"Removing old path state after successful rename: {old_path}")
        del self.files[old_path]

    # --- Public Query/Access Methods ---
    @waits
    def __iter__(self) -> Iterator[FileInfo]:
        yield from list(self.files.values())

    @waits
    def __getitem__(self, path: str) -> FileInfo:
        return self.files[path]

    @waits
    def __contains__(self, path: str) -> bool:
        if not isinstance(path, str):
            return False
        return path in self.files

    @waits
    def __len__(self) -> int:
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> str | None:
        path = self.pid_fd_map.get(pid, {}).get(fd)
        if path is not None:
            return path
        if fd == 0:
            return STDIN_PATH
        if fd == 1:
            return STDOUT_PATH
        if fd == 2:
            return STDERR_PATH
        return None

    # --- Helper for common state updates ---
    def _finalize_update(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: dict,
    ):
        """Helper to apply common updates to FileInfo state after an event."""
        info.last_activity_ts = timestamp
        info.last_event_type = event_type
        if event_type in ["OPEN", "STAT", "DELETE", "RENAME", "ACCESS", "CHDIR"]:
            info.last_error_enoent = (
                not success and details.get("error_name") == "ENOENT"
            )
        elif success and event_type != "DELETE":
            info.last_error_enoent = False

        current_details = info.details
        current_details.update(details)
        if not success and "error_name" in details:
            current_details["last_error_name"] = details["error_name"]
        elif success and "last_error_name" in current_details:
            del current_details["last_error_name"]
        info.details = current_details
        self._add_event_to_history(info, event_type, success, timestamp, info.details)

    @changes
    def process_exit(self, pid: int, timestamp: float):
        """Handles cleanup when a process exits (e.g., receives exit_group)."""
        log.info(f"Processing exit for PID: {pid}")
        if pid not in self.pid_fd_map:
            log.debug(f"PID {pid} not found in fd map, no FD cleanup needed.")
            return

        fds_to_close = list(self.pid_fd_map.get(pid, {}).keys())
        log.debug(f"PID {pid} exited, closing associated FDs: {fds_to_close}")
        for fd in fds_to_close:
            self.close(
                pid,
                fd,
                success=True,
                timestamp=timestamp,
                details={"process_exited": True},
            )

        if pid in self.pid_fd_map:
            log.warning(
                f"Removing PID {pid} from pid_fd_map post-exit (may indicate prior inconsistency)."
            )
            del self.pid_fd_map[pid]
        else:
            log.debug(f"PID {pid} already removed from pid_fd_map by close handlers.")
