# Filename: src/lsoph/monitor.py
import logging
import os
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple, Union

from lsoph.util.versioned import Versioned, changes, waits

# --- Setup Logging ---
log = logging.getLogger("lsoph.monitor")

# --- Constants ---
STDIN_PATH = "<STDIN>"
STDOUT_PATH = "<STDOUT>"
STDERR_PATH = "<STDERR>"
STD_PATHS: Set[str] = {STDIN_PATH, STDOUT_PATH, STDERR_PATH}
DEFAULT_EVENT_HISTORY_SIZE = 100
DEFAULT_RECENT_EVENT_TYPES_SIZE = 5


# --- File State Information ---
@dataclass
class FileInfo:
    """Holds state information about a single tracked file."""

    path: str
    status: str = "unknown"
    last_activity_ts: float = field(default_factory=time.time)
    open_by_pids: Dict[int, Set[int]] = field(default_factory=dict)
    last_event_type: str = ""
    last_error_enoent: bool = False
    recent_event_types: deque[str] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_RECENT_EVENT_TYPES_SIZE)
    )
    event_history: deque[Dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_EVENT_HISTORY_SIZE)
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
    Inherits from Versioned for change tracking and thread safety via decorators.
    Provides methods for backends to report file events (open, close, read, etc.).
    """

    def __init__(self, identifier: str):
        super().__init__()
        self.identifier = identifier
        self.ignored_paths: Set[str] = set()
        self.pid_fd_map: Dict[int, Dict[int, str]] = {}
        self.files: Dict[str, FileInfo] = {}
        self.backend_pid: Optional[int] = None
        log.info(f"Initialized Monitor for identifier: '{identifier}'")

    # --- Internal Helper Methods ---

    def _get_or_create_fileinfo(
        self, path: str, timestamp: float
    ) -> Optional[FileInfo]:
        """Gets existing FileInfo or creates one. Returns None if ignored/invalid."""
        if not path or not isinstance(path, str):
            log.debug(f"Ignoring event for invalid path: {path!r}")
            return None
        if path in self.ignored_paths or path in STD_PATHS:
            log.debug(f"Ignoring event for standard or ignored path: {path}")
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
        details: Dict[str, Any],
    ):
        """Adds a simplified event representation to the file's history deque."""
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

    def _update_pid_fd_map(self, pid: int, fd: int, path: Optional[str]):
        """Safely updates or removes entries in the pid_fd_map."""
        pid_map = self.pid_fd_map.get(pid)
        current_path = pid_map.get(fd) if pid_map else None

        if path:  # Add or update mapping
            if pid not in self.pid_fd_map:
                self.pid_fd_map[pid] = {}
            if current_path != path:
                log.debug(f"Mapping PID {pid} FD {fd} -> '{path}'")
                self.pid_fd_map[pid][fd] = path
        else:  # Remove mapping (path is None)
            if pid_map and fd in pid_map:
                removed_path = self.pid_fd_map[pid].pop(fd)
                log.debug(
                    f"Removed mapping for PID {pid} FD {fd} (was path: '{removed_path}')"
                )
                if not self.pid_fd_map[pid]:
                    del self.pid_fd_map[pid]
                    log.debug(f"Removed empty FD map for PID {pid}")

    @changes  # Added decorator as this method modifies state (FileInfo status, open_by_pids)
    def _remove_fd(self, pid: int, fd: int) -> Optional[FileInfo]:
        """
        Internal helper to remove an FD mapping for a PID and update FileInfo state.
        Handles removal from pid_fd_map and FileInfo.open_by_pids, and updates status.
        NOTE: This method modifies state and bumps the version via @changes.

        Args:
            pid: The process ID.
            fd: The file descriptor to remove.

        Returns:
            The updated FileInfo object if found and modified, otherwise None.
        """
        log.debug(f"Attempting to remove FD {fd} for PID {pid}")
        path = self.get_path(pid, fd)  # Get path *before* removing mapping

        # 1. Remove from pid_fd_map
        self._update_pid_fd_map(pid, fd, None)  # Use helper to ensure cleanup

        # 2. If path is unknown or standard, no FileInfo to update
        if not path or path in STD_PATHS:
            log.debug(
                f"_remove_fd: Path ('{path}') unknown or standard stream. No FileInfo update."
            )
            return None

        # 3. Get FileInfo
        info = self.files.get(path)
        if not info:
            log.warning(
                f"_remove_fd: Path '{path}' (from PID {pid} FD {fd}) not found in state."
            )
            return None

        # 4. Remove from FileInfo.open_by_pids
        if pid in info.open_by_pids:
            if fd in info.open_by_pids[pid]:
                info.open_by_pids[pid].remove(fd)
                log.debug(
                    f"_remove_fd: Removed FD {fd} from open set for PID {pid} ('{path}')"
                )
            if not info.open_by_pids[pid]:  # If set is empty, remove PID entry
                del info.open_by_pids[pid]
                log.debug(
                    f"_remove_fd: Removed PID {pid} from open_by_pids for '{path}'."
                )

        # 5. Update FileInfo.status
        if not info.is_open and info.status != "deleted":
            info.status = "closed"
            log.debug(f"_remove_fd: Path '{path}' marked as closed.")
        elif info.is_open and info.status != "deleted":
            info.status = "open"  # Still open by others

        return info  # Return the modified FileInfo

    def _finalize_update(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: Dict[str, Any],
    ):
        """Helper to apply common updates (history, details, errors) to FileInfo state."""
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
            current_details["last_error_msg"] = details.get("error_msg")
        elif success and "last_error_name" in current_details:
            current_details.pop("last_error_name", None)
            current_details.pop("last_error_msg", None)
        info.details = current_details

        self._add_event_to_history(info, event_type, success, timestamp, info.details)

    # --- Public Handler Methods ---

    @changes
    def ignore(self, path: str):
        """Adds a path to the ignore list and removes existing state for it."""
        if (
            not isinstance(path, str)
            or not path
            or path in STD_PATHS
            or path in self.ignored_paths
        ):
            return
        log.info(f"Adding path to ignore list for '{self.identifier}': {path}")
        self.ignored_paths.add(path)
        if path in self.files:
            log.debug(f"Removing ignored path from active state: {path}")
            # Clean up FDs associated with this path
            pids_fds_to_remove: List[Tuple[int, int]] = []
            for pid, fd_map in self.pid_fd_map.items():
                for fd, p in fd_map.items():
                    if p == path:
                        pids_fds_to_remove.append((pid, fd))
            for pid, fd in pids_fds_to_remove:
                self._remove_fd(pid, fd)  # Use helper to ensure full cleanup
            # Remove from files map
            if (
                path in self.files
            ):  # Check again as _remove_fd might affect it indirectly
                del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list."""
        log.info(f"Ignoring all currently tracked files for '{self.identifier}'")
        paths_to_ignore = [p for p in self.files.keys() if p not in STD_PATHS]
        count = 0
        for path in paths_to_ignore:
            if path not in self.ignored_paths:
                self.ignore(path)
                count += 1
        log.info(f"Added {count} paths to ignore list via ignore_all.")

    @changes
    def open(
        self, pid: int, path: str, fd: int, success: bool, timestamp: float, **details
    ):
        """Handles an 'open' or 'creat' event."""
        log.debug(
            f"Monitor.open: pid={pid}, path={path}, fd={fd}, success={success}, details={details}"
        )
        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return

        event_details = details.copy()
        event_details["fd"] = fd
        self._finalize_update(info, "OPEN", success, timestamp, event_details)

        if success and fd >= 0:
            if info.status != "deleted":
                info.status = "open"
            self._update_pid_fd_map(pid, fd, path)  # Add mapping
            # Add FD to FileInfo's open set
            if pid not in info.open_by_pids:
                info.open_by_pids[pid] = set()
            info.open_by_pids[pid].add(fd)
            log.debug(
                f"FileInfo updated for open: PID {pid} FD {fd}. Open PIDs: {list(info.open_by_pids.keys())}"
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
        """Handles a 'close' event."""
        log.debug(
            f"Monitor.close: pid={pid}, fd={fd}, success={success}, details={details}"
        )

        # Use the helper to remove the FD mapping and update FileInfo state
        info = self._remove_fd(pid, fd)  # This handles map removal and status update

        if info:  # If FileInfo was found and updated
            event_details = details.copy()
            event_details["fd"] = fd
            # Finalize adds history entry and handles error details
            self._finalize_update(info, "CLOSE", success, timestamp, event_details)
            # Update status again if close failed after helper potentially set it to 'closed'
            if not success and info.status not in ["deleted", "open"]:
                info.status = "error"
        else:
            log.debug(
                f"Close event for PID {pid} FD {fd} did not correspond to a tracked file state."
            )

    @changes
    def read(
        self,
        pid: int,
        fd: int,
        path: Optional[str],
        success: bool,
        timestamp: float,
        **details,
    ):
        """Handles a 'read' (or similar) event."""
        log.debug(
            f"Monitor.read: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        if path is None:
            path = self.get_path(pid, fd)
        if not path or path in STD_PATHS:
            return
        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return

        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
            info.bytes_read += byte_count

        event_details = details.copy()
        event_details["fd"] = fd
        self._finalize_update(info, "READ", success, timestamp, event_details)

        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in ["deleted", "open"]:
            info.status = "error"

    @changes
    def write(
        self,
        pid: int,
        fd: int,
        path: Optional[str],
        success: bool,
        timestamp: float,
        **details,
    ):
        """Handles a 'write' (or similar) event."""
        log.debug(
            f"Monitor.write: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        if path is None:
            path = self.get_path(pid, fd)
        if not path or path in STD_PATHS:
            return
        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return

        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count > 0:
            info.bytes_written += byte_count

        event_details = details.copy()
        event_details["fd"] = fd
        self._finalize_update(info, "WRITE", success, timestamp, event_details)

        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in ["deleted", "open"]:
            info.status = "error"

    @changes
    def stat(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles a 'stat', 'access', 'lstat' etc. event."""
        log.debug(
            f"Monitor.stat: pid={pid}, path={path}, success={success}, details={details}"
        )
        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return

        event_details = details.copy()
        self._finalize_update(info, "STAT", success, timestamp, event_details)

        if success:
            if info.status in ["unknown", "closed", "accessed"]:
                info.status = "accessed"
        else:
            if info.status != "deleted":
                info.status = "error"

    @changes
    def delete(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles an 'unlink', 'rmdir' event."""
        log.debug(
            f"Monitor.delete: pid={pid}, path={path}, success={success}, details={details}"
        )
        info = self.files.get(path)
        if not info:
            log.debug(f"Delete event for untracked path: {path}")
            return

        event_details = details.copy()
        self._finalize_update(info, "DELETE", success, timestamp, event_details)

        if not success:
            if info.status not in ["deleted", "open"]:
                info.status = "error"
            return

        # --- Successful Delete ---
        info.status = "deleted"
        log.info(f"Path '{path}' marked as deleted.")

        # Clean up associated state using the helper for each open FD
        pids_fds_to_remove: List[Tuple[int, int]] = []
        for open_pid, open_fds in list(info.open_by_pids.items()):  # Iterate copy
            for open_fd in list(open_fds):  # Iterate copy
                pids_fds_to_remove.append((open_pid, open_fd))

        log.debug(
            f"Cleaning up {len(pids_fds_to_remove)} FD mappings for deleted path '{path}'."
        )
        for remove_pid, remove_fd in pids_fds_to_remove:
            self._remove_fd(remove_pid, remove_fd)  # Use helper

        # Ensure open_by_pids is empty after cleanup
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
        """Handles a 'rename' event."""
        log.debug(
            f"Monitor.rename: pid={pid}, old={old_path}, new={new_path}, success={success}, details={details}"
        )

        old_is_ignored = old_path in self.ignored_paths or old_path in STD_PATHS
        new_is_ignored = new_path in self.ignored_paths or new_path in STD_PATHS

        # --- Handle cases involving ignored paths ---
        if new_is_ignored:
            log.info(f"Rename target path '{new_path}' is ignored.")
            if success and not old_is_ignored and old_path in self.files:
                self.delete(
                    pid, old_path, True, timestamp, {"renamed_to_ignored": new_path}
                )
            elif not success and not old_is_ignored and old_path in self.files:
                info_old = self.files[old_path]
                event_details = details.copy()
                event_details["target_path"] = new_path
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, event_details
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

        # --- Handle rename failure (neither path ignored) ---
        if not success:
            info_old = self.files.get(old_path)
            if info_old:
                event_details = details.copy()
                event_details["target_path"] = new_path
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, event_details
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            info_new = self._get_or_create_fileinfo(new_path, timestamp)
            if info_new:
                event_details = details.copy()
                event_details["source_path"] = old_path
                self._finalize_update(
                    info_new, "RENAME_TARGET", success, timestamp, event_details
                )
                if info_new.status != "deleted":
                    info_new.status = "error"
            return

        # --- Handle successful rename (neither path ignored) ---
        log.info(f"Processing successful rename: '{old_path}' -> '{new_path}'")
        old_info = self.files.get(old_path)
        if not old_info:
            log.debug(
                f"Rename source path '{old_path}' not tracked. Treating as access to target '{new_path}'."
            )
            self.stat(
                pid, new_path, True, timestamp, {"renamed_from_unknown": old_path}
            )
            return

        new_info = self._get_or_create_fileinfo(new_path, timestamp)
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

        # Transfer state
        new_info.status = (
            old_info.status if old_info.status != "deleted" else "accessed"
        )
        new_info.open_by_pids = old_info.open_by_pids
        new_info.bytes_read = old_info.bytes_read
        new_info.bytes_written = old_info.bytes_written
        new_info.last_event_type = old_info.last_event_type
        new_info.last_error_enoent = old_info.last_error_enoent
        new_info.details = old_info.details
        # new_info.event_history = old_info.event_history # Decide whether to transfer history
        # new_info.recent_event_types = old_info.recent_event_types

        # Add history entries
        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        self._add_event_to_history(
            old_info, "RENAME", success, timestamp, details_for_old
        )
        self._add_event_to_history(
            new_info, "RENAME", success, timestamp, details_for_new
        )
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        # Update pid_fd_map
        pids_fds_to_update: List[Tuple[int, int]] = []
        for map_pid, fd_map in self.pid_fd_map.items():
            for map_fd, map_path in fd_map.items():
                if map_path == old_path:
                    pids_fds_to_update.append((map_pid, map_fd))
        if pids_fds_to_update:
            log.info(
                f"Rename: Updating {len(pids_fds_to_update)} FD map entries: '{old_path}' -> '{new_path}'"
            )
            for update_pid, update_fd in pids_fds_to_update:
                self._update_pid_fd_map(update_pid, update_fd, new_path)

        # Remove old path state
        log.debug(f"Removing old path state after successful rename: {old_path}")
        del self.files[old_path]

    @changes
    def process_exit(self, pid: int, timestamp: float):
        """Handles cleanup when a process exits."""
        log.info(f"Processing exit for PID: {pid}")
        if pid not in self.pid_fd_map:
            log.debug(
                f"PID {pid} not found in fd map, no FD cleanup needed via process_exit."
            )
            return

        fds_to_close = list(self.pid_fd_map.get(pid, {}).keys())
        log.debug(f"PID {pid} exited, closing its associated FDs: {fds_to_close}")
        for fd in fds_to_close:
            # Use the close handler, which now uses _remove_fd internally
            self.close(
                pid,
                fd,
                success=True,
                timestamp=timestamp,
                details={"process_exited": True},
            )

        # Verify the PID entry is gone from pid_fd_map
        if pid in self.pid_fd_map:
            log.warning(
                f"PID {pid} still present in pid_fd_map after process_exit close loop. Forcing removal."
            )
            del self.pid_fd_map[pid]
        else:
            log.debug(
                f"PID {pid} successfully removed from pid_fd_map by close handlers during process_exit."
            )

    # --- Public Query/Access Methods ---

    @waits
    def __iter__(self) -> Iterator[FileInfo]:
        yield from list(self.files.values())

    @waits
    def __getitem__(self, path: str) -> FileInfo:
        return self.files[path]

    @waits
    def __contains__(self, path: str) -> bool:
        return isinstance(path, str) and path in self.files

    @waits
    def __len__(self) -> int:
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> Optional[str]:
        """Retrieves the path for a PID/FD, handling standard streams."""
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
