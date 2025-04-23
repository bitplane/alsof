# Filename: src/lsoph/monitor.py
import logging
import os
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple, Union  # Added Optional, Union

from lsoph.util.versioned import Versioned, changes, waits

# --- Setup Logging ---
log = logging.getLogger("lsoph.monitor")

# --- Constants ---
STDIN_PATH = "<STDIN>"
STDOUT_PATH = "<STDOUT>"
STDERR_PATH = "<STDERR>"
# Set of standard stream paths that are generally not tracked like regular files
STD_PATHS: Set[str] = {STDIN_PATH, STDOUT_PATH, STDERR_PATH}
# Maximum number of events to keep in the history per file
DEFAULT_EVENT_HISTORY_SIZE = 100
# Maximum number of recent distinct event types to track per file
DEFAULT_RECENT_EVENT_TYPES_SIZE = 5


# --- File State Information ---
@dataclass
class FileInfo:
    """Holds state information about a single tracked file."""

    path: str
    # Current status (e.g., "open", "closed", "active", "deleted", "error", "accessed", "unknown")
    status: str = "unknown"
    # Timestamp of the last recorded activity related to this file
    last_activity_ts: float = field(default_factory=time.time)
    # Tracks which PIDs have this file open and via which file descriptors
    # Format: {pid: {fd1, fd2, ...}}
    open_by_pids: Dict[int, Set[int]] = field(default_factory=dict)
    # The type of the last event processed for this file (e.g., "OPEN", "READ")
    last_event_type: str = ""
    # Flag indicating if the last access attempt resulted in "No such file or directory"
    last_error_enoent: bool = False
    # A deque holding the most recent distinct *successful* event types
    recent_event_types: deque[str] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_RECENT_EVENT_TYPES_SIZE)
    )
    # A deque holding a history of processed events for this file
    event_history: deque[Dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_EVENT_HISTORY_SIZE)
    )
    # Cumulative bytes read from the file (based on reported syscall results)
    bytes_read: int = 0
    # Cumulative bytes written to the file (based on reported syscall results)
    bytes_written: int = 0
    # Dictionary to store additional details from backend events (e.g., mode, fd_str)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        """Checks if any process currently holds this file open according to state."""
        # Returns True if the open_by_pids dictionary is not empty
        return bool(self.open_by_pids)


# --- Monitor Class (Manages State for a Monitored Target) ---
class Monitor(Versioned):
    """
    Manages the state of files accessed by a monitored target (process group).
    Inherits from Versioned for change tracking and thread safety via decorators.
    Provides methods for backends to report file events (open, close, read, etc.).
    """

    def __init__(self, identifier: str):
        """Initialize the Monitor.

        Args:
            identifier: A string identifying the monitoring session (e.g., command or PIDs).
        """
        super().__init__()  # Initialize Versioned base class (version counter and lock)
        self.identifier = identifier
        # Set of paths explicitly ignored by the user
        self.ignored_paths: Set[str] = set()
        # Main state mapping: PID -> { FD -> Path }
        self.pid_fd_map: Dict[int, Dict[int, str]] = {}
        # Main state mapping: Path -> FileInfo object
        self.files: Dict[str, FileInfo] = {}
        # Stores the PID of the backend process (e.g., strace) if applicable
        self.backend_pid: Optional[int] = None
        log.info(f"Initialized Monitor for identifier: '{identifier}'")

    def _get_or_create_fileinfo(
        self, path: str, timestamp: float
    ) -> Optional[FileInfo]:
        """
        Retrieves existing FileInfo for a path or creates a new one.
        Returns None if the path is ignored or invalid.
        Updates the last activity timestamp.
        """
        # Basic path validation
        if not path or not isinstance(path, str):
            log.debug(f"Ignoring event for invalid path: {path!r}")
            return None
        # Check against ignored paths and standard streams
        if path in self.ignored_paths or path in STD_PATHS:
            log.debug(f"Ignoring event for standard or ignored path: {path}")
            return None

        # Get existing or create new FileInfo
        if path not in self.files:
            log.debug(f"Creating new FileInfo for path: {path}")
            # Create a new FileInfo instance, setting initial status and timestamp
            self.files[path] = FileInfo(
                path=path, last_activity_ts=timestamp, status="accessed"
            )
        # Update last activity time for existing or new entry
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
        # Create a copy of details, potentially filtering large data fields if needed
        simple_details = {
            k: v
            for k, v in details.items()
            if k not in ["read_data", "write_data"]  # Example filter
        }
        # Append the event record to the history deque
        info.event_history.append(
            {
                "ts": timestamp,
                "type": event_type,
                "success": success,
                "details": simple_details,
            }
        )
        # Track recent *distinct* successful event types
        if success:
            # Add only if it's different from the last added type
            if not info.recent_event_types or info.recent_event_types[-1] != event_type:
                info.recent_event_types.append(event_type)

    def _update_pid_fd_map(self, pid: int, fd: int, path: Optional[str]):
        """Safely updates or removes entries in the pid_fd_map."""
        if path:  # Add or update mapping
            if pid not in self.pid_fd_map:
                self.pid_fd_map[pid] = {}
            # Only log if the mapping is new or changing
            if self.pid_fd_map[pid].get(fd) != path:
                log.debug(f"Mapping PID {pid} FD {fd} -> '{path}'")
                self.pid_fd_map[pid][fd] = path
        else:  # Remove mapping (path is None)
            if pid in self.pid_fd_map and fd in self.pid_fd_map[pid]:
                removed_path = self.pid_fd_map[pid].pop(fd)
                log.debug(
                    f"Removed mapping for PID {pid} FD {fd} (was path: '{removed_path}')"
                )
                # Clean up PID entry if no FDs remain
                if not self.pid_fd_map[pid]:
                    del self.pid_fd_map[pid]
                    log.debug(f"Removed empty FD map for PID {pid}")

    # --- Public Handler Methods (decorated with @changes for versioning) ---

    @changes
    def ignore(self, path: str):
        """Adds a path to the ignore list and removes existing state for it."""
        if (
            not isinstance(path, str)
            or not path
            or path in STD_PATHS
            or path in self.ignored_paths
        ):
            return  # Ignore invalid, standard, or already ignored paths

        log.info(f"Adding path to ignore list for '{self.identifier}': {path}")
        self.ignored_paths.add(path)

        # Remove state if the path was previously tracked
        if path in self.files:
            log.debug(f"Removing ignored path from active state: {path}")
            # Remove from pid_fd_map
            pids_with_path = []
            for pid, fd_map in list(self.pid_fd_map.items()):
                fds_to_remove = {fd for fd, p in fd_map.items() if p == path}
                if fds_to_remove:
                    pids_with_path.append(pid)
                    for fd in fds_to_remove:
                        self._update_pid_fd_map(pid, fd, None)  # Use helper to remove

            # Remove from files map
            del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list."""
        log.info(f"Ignoring all currently tracked files for '{self.identifier}'")
        # Create a list of paths to ignore to avoid modifying dict while iterating
        paths_to_ignore = [p for p in self.files.keys() if p not in STD_PATHS]
        count = 0
        for path in paths_to_ignore:
            if path not in self.ignored_paths:
                self.ignore(path)  # Call the ignore method to handle state cleanup
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
            return  # Path was ignored or invalid

        # Add event details (copy details to avoid modifying caller's dict)
        event_details = details.copy()
        event_details["fd"] = fd  # Ensure FD is in details for history

        # Finalize common updates (history, last event type, etc.)
        self._finalize_update(info, "OPEN", success, timestamp, event_details)

        if success and fd >= 0:
            # Update internal state for successful open with valid FD
            if info.status != "deleted":  # Don't reopen a deleted file logically
                info.status = "open"
            # Update the PID -> FD -> Path map
            self._update_pid_fd_map(pid, fd, path)
            # Add the FD to the set of open FDs for this PID in FileInfo
            if pid not in info.open_by_pids:
                info.open_by_pids[pid] = set()
            info.open_by_pids[pid].add(fd)
            log.debug(
                f"FileInfo updated for open: PID {pid} FD {fd}. Open PIDs: {list(info.open_by_pids.keys())}"
            )
        elif not success:
            # Update status on failure
            if info.status != "deleted":
                info.status = "error"
        elif success and fd < 0:
            # Log warning for successful open but invalid FD
            log.warning(
                f"Successful open reported for path '{path}' but FD is invalid ({fd})"
            )
            if info.status != "deleted":
                info.status = "error"  # Treat as error state

    @changes
    def close(self, pid: int, fd: int, success: bool, timestamp: float, **details):
        """Handles a 'close' event."""
        log.debug(
            f"Monitor.close: pid={pid}, fd={fd}, success={success}, details={details}"
        )

        # Find the path associated with this PID/FD *before* removing the mapping
        path = self.get_path(pid, fd)

        # Always remove the mapping on a close attempt, regardless of success reported by backend,
        # as the kernel likely closed the FD anyway if the syscall was made.
        # Success flag mainly affects FileInfo status update.
        self._update_pid_fd_map(pid, fd, None)  # Remove mapping

        # If path couldn't be resolved or is standard stream, nothing more to do for FileInfo
        if not path or path in STD_PATHS:
            log.debug(
                f"Close event for PID {pid} FD {fd} - Path ('{path}') unknown or standard stream. No FileInfo update."
            )
            return

        # Get FileInfo for the path
        info = self.files.get(path)
        if not info:
            log.warning(
                f"Close event for PID {pid} FD {fd} refers to path '{path}' not in state. No FileInfo update."
            )
            return

        # Add event details
        event_details = details.copy()
        event_details["fd"] = fd

        # Finalize common updates
        self._finalize_update(info, "CLOSE", success, timestamp, event_details)

        # Remove FD from the FileInfo's open set
        if pid in info.open_by_pids:
            if fd in info.open_by_pids[pid]:
                info.open_by_pids[pid].remove(fd)
                log.debug(f"Removed FD {fd} from open set for PID {pid} ('{path}')")
            if not info.open_by_pids[pid]:  # If set is empty, remove PID entry
                del info.open_by_pids[pid]
                log.debug(
                    f"Removed PID {pid} from open_by_pids for '{path}' as FD set is empty."
                )

        # Update overall file status based on whether any process still holds it open
        if not info.is_open and info.status != "deleted":
            info.status = "closed"
            log.debug(
                f"Path '{path}' marked as closed (no longer open by any tracked PID)."
            )
        elif info.is_open and info.status != "deleted":
            info.status = "open"  # Still open by other PIDs/FDs

        # If close failed, but file isn't deleted or still open, mark as error
        if not success and info.status not in ["deleted", "open"]:
            info.status = "error"

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
        # Resolve path if not provided
        if path is None:
            path = self.get_path(pid, fd)

        if not path or path in STD_PATHS:
            log.debug(
                f"Read event for PID {pid} FD {fd} - Path ('{path}') unknown or standard stream."
            )
            return

        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return  # Path ignored

        # Update byte count if successful and bytes provided
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
            info.bytes_read += byte_count

        # Add event details
        event_details = details.copy()
        event_details["fd"] = fd

        # Finalize common updates
        self._finalize_update(info, "READ", success, timestamp, event_details)

        # Update status: mark as active on success if not deleted
        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in [
            "deleted",
            "open",
        ]:  # If read fails on closed/accessed file
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
            log.debug(
                f"Write event for PID {pid} FD {fd} - Path ('{path}') unknown or standard stream."
            )
            return

        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return  # Path ignored

        byte_count = details.get("bytes")
        if (
            success and isinstance(byte_count, int) and byte_count > 0
        ):  # Only count actual bytes written
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
            return  # Path ignored

        event_details = details.copy()
        self._finalize_update(info, "STAT", success, timestamp, event_details)

        # Update status based on success and current state
        if success:
            # If file was unknown/closed/accessed, mark as accessed
            if info.status in ["unknown", "closed", "accessed"]:
                info.status = "accessed"
            # If it was error/deleted, successful stat implies it exists now (unless deleted remains sticky)
            # Keep open/active status if it was already open/active
        else:
            # If stat fails and file isn't deleted, mark as error
            if info.status != "deleted":
                info.status = "error"

    @changes
    def delete(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles an 'unlink', 'rmdir' event."""
        log.debug(
            f"Monitor.delete: pid={pid}, path={path}, success={success}, details={details}"
        )
        info = self.files.get(path)  # Get existing info, don't create on delete attempt
        if not info:
            log.debug(f"Delete event for untracked path: {path}")
            return  # Can't delete something we aren't tracking

        event_details = details.copy()
        self._finalize_update(info, "DELETE", success, timestamp, event_details)

        if not success:
            # If delete failed, mark as error if not already deleted/open
            if info.status not in ["deleted", "open"]:
                info.status = "error"
            return  # Don't proceed with cleanup if delete failed

        # --- Successful Delete ---
        info.status = "deleted"
        log.info(f"Path '{path}' marked as deleted.")

        # Clean up associated state: remove from pid_fd_map and open_by_pids
        pids_holding_open = list(info.open_by_pids.keys())
        log.debug(
            f"Cleaning up state for deleted path '{path}'. Was open by PIDs: {pids_holding_open}"
        )
        for check_pid in pids_holding_open:
            fds_to_remove = set(info.open_by_pids.get(check_pid, set()))
            for fd in fds_to_remove:
                # Remove from main pid->fd map
                self._update_pid_fd_map(check_pid, fd, None)
            # Clear entry in FileInfo's open_by_pids
            if check_pid in info.open_by_pids:
                del info.open_by_pids[check_pid]

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
                # If rename succeeded to an ignored path, treat old path as deleted
                log.debug(
                    f"Treating successful rename source '{old_path}' as deleted (target ignored)."
                )
                self.delete(
                    pid, old_path, True, timestamp, {"renamed_to_ignored": new_path}
                )
            elif not success and not old_is_ignored and old_path in self.files:
                # If rename failed, just record the failed attempt on the old path
                info_old = self.files[old_path]
                event_details = details.copy()
                event_details["target_path"] = new_path
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, event_details
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            return  # Target is ignored, no further processing needed

        if old_is_ignored:
            log.warning(
                f"Rename source path '{old_path}' is ignored (event on PID {pid})."
            )
            if success:
                # If rename succeeded from ignored path, treat new path as accessed/stat'd
                log.debug(
                    f"Treating successful rename target '{new_path}' as accessed (source ignored)."
                )
                self.stat(
                    pid, new_path, True, timestamp, {"renamed_from_ignored": old_path}
                )
            # If rename failed from ignored source, do nothing
            return

        # --- Handle rename failure (neither path ignored) ---
        if not success:
            info_old = self.files.get(old_path)
            if info_old:  # Record failed attempt on old path if tracked
                event_details = details.copy()
                event_details["target_path"] = new_path
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, event_details
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            # Also record failed attempt on new path (might create FileInfo)
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
            # Source path wasn't tracked, treat as simple access to new path
            log.debug(
                f"Rename source path '{old_path}' not tracked. Treating as access to target '{new_path}'."
            )
            self.stat(
                pid, new_path, True, timestamp, {"renamed_from_unknown": old_path}
            )
            return

        # Get or create FileInfo for the new path
        new_info = self._get_or_create_fileinfo(new_path, timestamp)
        if not new_info:
            # This should not happen if new_path isn't ignored, but handle defensively
            log.error(
                f"Could not get/create FileInfo for rename target '{new_path}'. State may be inconsistent."
            )
            # Mark old path as deleted as it was successfully renamed away
            self.delete(
                pid,
                old_path,
                True,
                timestamp,
                {"error": "Rename target state creation failed"},
            )
            return

        # Transfer state from old_info to new_info
        new_info.status = (
            old_info.status if old_info.status != "deleted" else "accessed"
        )
        new_info.open_by_pids = old_info.open_by_pids  # Transfer ownership of the dict
        new_info.bytes_read = old_info.bytes_read
        new_info.bytes_written = old_info.bytes_written
        new_info.last_event_type = (
            old_info.last_event_type
        )  # Keep last event before rename
        new_info.last_error_enoent = old_info.last_error_enoent
        new_info.details = old_info.details  # Transfer details
        # Transfer event history (optional, could merge or just start fresh)
        # new_info.event_history = old_info.event_history # Example: transfer history
        # new_info.recent_event_types = old_info.recent_event_types # Example: transfer recent

        # Add rename event to history for both paths
        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        self._add_event_to_history(
            old_info, "RENAME", success, timestamp, details_for_old
        )
        self._add_event_to_history(
            new_info, "RENAME", success, timestamp, details_for_new
        )

        # Finalize update for the *new* path
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        # Update the pid_fd_map: change path for any FDs pointing to old_path
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
                # Use helper to update map, ensuring PID/FD exists
                self._update_pid_fd_map(update_pid, update_fd, new_path)

        # Remove the old path state from the monitor
        log.debug(f"Removing old path state after successful rename: {old_path}")
        del self.files[old_path]

    @changes
    def process_exit(self, pid: int, timestamp: float):
        """Handles cleanup when a process exits (e.g., receives exit_group)."""
        log.info(f"Processing exit for PID: {pid}")
        if pid not in self.pid_fd_map:
            log.debug(
                f"PID {pid} not found in fd map, no FD cleanup needed via process_exit."
            )
            return

        # Get list of FDs associated with the exiting PID *before* closing them
        fds_to_close = list(self.pid_fd_map.get(pid, {}).keys())
        log.debug(f"PID {pid} exited, closing its associated FDs: {fds_to_close}")
        for fd in fds_to_close:
            # Call the close handler for each FD
            self.close(
                pid,
                fd,
                success=True,
                timestamp=timestamp,
                details={"process_exited": True},
            )

        # Verify the PID entry is gone from pid_fd_map after closing all FDs
        if pid in self.pid_fd_map:
            log.warning(
                f"PID {pid} still present in pid_fd_map after process_exit close loop. Forcing removal."
            )
            del self.pid_fd_map[pid]
        else:
            log.debug(
                f"PID {pid} successfully removed from pid_fd_map by close handlers during process_exit."
            )

    # --- Public Query/Access Methods (decorated with @waits for thread safety) ---

    @waits
    def __iter__(self) -> Iterator[FileInfo]:
        """Allows iterating directly over the tracked FileInfo objects."""
        # Return a list copy to avoid issues if dict changes during iteration
        yield from list(self.files.values())

    @waits
    def __getitem__(self, path: str) -> FileInfo:
        """Allows dictionary-style access to FileInfo by path."""
        return self.files[path]  # Raises KeyError if path not found

    @waits
    def __contains__(self, path: str) -> bool:
        """Allows checking `if path in monitor`."""
        if not isinstance(path, str):
            return False
        return path in self.files

    @waits
    def __len__(self) -> int:
        """Returns the number of tracked files."""
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> Optional[str]:
        """
        Retrieves the path associated with a given PID and FD from the internal map.
        Returns standard stream names for FDs 0, 1, 2 if not otherwise mapped.
        Returns None if the PID/FD combination is not found.
        """
        path = self.pid_fd_map.get(pid, {}).get(fd)
        if path is not None:
            return path
        # Handle standard streams if not explicitly mapped otherwise
        if fd == 0:
            return STDIN_PATH
        if fd == 1:
            return STDOUT_PATH
        if fd == 2:
            return STDERR_PATH
        # FD not found for this PID
        return None

    # --- Helper for common state updates (internal, not versioned directly) ---
    def _finalize_update(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: Dict[str, Any],
    ):
        """
        Helper to apply common updates to FileInfo state after an event.
        Called internally by the public handler methods.
        """
        info.last_activity_ts = timestamp
        info.last_event_type = event_type

        # Update ENOENT flag specifically for relevant syscall types
        if event_type in ["OPEN", "STAT", "DELETE", "RENAME", "ACCESS", "CHDIR"]:
            info.last_error_enoent = (
                not success and details.get("error_name") == "ENOENT"
            )
        # Clear ENOENT flag on *any* subsequent success (except delete)
        elif success and event_type != "DELETE":
            info.last_error_enoent = False

        # Merge new details into existing details, tracking last error
        current_details = info.details
        current_details.update(details)
        if not success and "error_name" in details:
            current_details["last_error_name"] = details["error_name"]
            current_details["last_error_msg"] = details.get("error_msg")
        elif success and "last_error_name" in current_details:
            # Clear last error on success
            current_details.pop("last_error_name", None)
            current_details.pop("last_error_msg", None)
        info.details = current_details  # Assign updated details back

        # Add event to history (uses the potentially updated info.details)
        self._add_event_to_history(info, event_type, success, timestamp, info.details)
