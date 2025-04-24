# Filename: src/lsoph/monitor/_monitor.py
"""
Contains the Monitor class responsible for managing file access state.
"""

import logging
import os
import time
from collections.abc import Iterator
from typing import Any

from lsoph.util.versioned import Versioned, changes, waits

# Import FileInfo from the sibling module
from ._fileinfo import FileInfo

# --- Setup Logging ---
log = logging.getLogger("lsoph.monitor")  # Use the same logger name

# --- Constants ---
# Constants related to standard streams, used by Monitor logic
STDIN_PATH = "<STDIN>"
STDOUT_PATH = "<STDOUT>"
STDERR_PATH = "<STDERR>"
STD_PATHS: set[str] = {STDIN_PATH, STDOUT_PATH, STDERR_PATH}


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
        self.ignored_paths: set[str] = set()
        # Maps PID -> {FD -> Path}
        self.pid_fd_map: dict[int, dict[int, str]] = {}
        # Maps Path -> FileInfo
        self.files: dict[str, FileInfo] = {}
        self.backend_pid: int | None = None
        log.info(f"Initialized Monitor for identifier: '{identifier}'")

    # --- Internal Helper Methods ---

    def _get_or_create_fileinfo(self, path: str, timestamp: float) -> FileInfo | None:
        """Gets existing FileInfo or creates one. Returns None if ignored/invalid."""
        if not path or not isinstance(path, str):
            log.debug(f"Ignoring event for invalid path: {path!r}")
            return None
        # Check against standard streams and ignored paths
        if path in self.ignored_paths or path in STD_PATHS:
            log.debug(f"Ignoring event for standard or ignored path: {path}")
            return None
        # Get or create FileInfo entry
        if path not in self.files:
            log.debug(f"Creating new FileInfo for path: {path}")
            # Use the imported FileInfo class
            self.files[path] = FileInfo(
                path=path, last_activity_ts=timestamp, status="accessed"
            )
        # Update last activity timestamp regardless
        self.files[path].last_activity_ts = timestamp
        return self.files[path]

    def _add_event_to_history(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: dict[str, Any],
    ):
        """Adds a simplified event representation to the file's history deque."""
        # Create a simplified version of details, excluding potentially large data
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
        # Add to recent event types only if successful and different from last
        if success:
            if not info.recent_event_types or info.recent_event_types[-1] != event_type:
                info.recent_event_types.append(event_type)

    def _update_pid_fd_map(self, pid: int, fd: int, path: str | None):
        """Safely updates or removes entries in the pid_fd_map."""
        pid_map = self.pid_fd_map.get(pid)
        current_path = pid_map.get(fd) if pid_map else None

        if path:  # Add or update mapping
            if pid not in self.pid_fd_map:
                self.pid_fd_map[pid] = {}
            # Only log if the path actually changes or is new
            if current_path != path:
                log.debug(f"Mapping PID {pid} FD {fd} -> '{path}'")
                self.pid_fd_map[pid][fd] = path
        else:  # Remove mapping (path is None)
            if pid_map and fd in pid_map:
                removed_path = self.pid_fd_map[pid].pop(fd)
                log.debug(
                    f"Removed mapping for PID {pid} FD {fd} (was path: '{removed_path}')"
                )
                # Clean up PID entry if it becomes empty
                if not self.pid_fd_map[pid]:
                    del self.pid_fd_map[pid]
                    log.debug(f"Removed empty FD map for PID {pid}")

    @changes  # Modifies state (FileInfo status, open_by_pids)
    def _remove_fd(self, pid: int, fd: int) -> FileInfo | None:
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
            # If set is empty after removal, remove PID entry entirely
            if not info.open_by_pids[pid]:
                del info.open_by_pids[pid]
                log.debug(
                    f"_remove_fd: Removed PID {pid} from open_by_pids for '{path}'."
                )

        # 5. Update FileInfo.status based on whether *any* process still holds it open
        if not info.is_open and info.status != "deleted":
            info.status = "closed"
            log.debug(f"_remove_fd: Path '{path}' marked as closed.")
        elif info.is_open and info.status != "deleted":
            # If still open by other PIDs/FDs, keep status as 'open' or 'active'
            # Let subsequent events like read/write change it to 'active'
            if info.status not in ["open", "active"]:
                info.status = "open"

        return info  # Return the modified FileInfo

    def _finalize_update(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: dict[str, Any],
    ):
        """Helper to apply common updates (history, details, errors) to FileInfo state."""
        info.last_activity_ts = timestamp
        info.last_event_type = event_type

        # Update last_error_enoent flag based on specific event types
        if event_type in ["OPEN", "STAT", "DELETE", "RENAME", "ACCESS", "CHDIR"]:
            info.last_error_enoent = (
                not success and details.get("error_name") == "ENOENT"
            )
        elif success and event_type != "DELETE":
            # Clear ENOENT flag on successful non-delete operations
            info.last_error_enoent = False
        # Note: READ/WRITE/CLOSE failures don't set last_error_enoent

        # Update details, storing last error if applicable
        current_details = info.details
        current_details.update(details)  # Merge new details
        if not success and "error_name" in details:
            current_details["last_error_name"] = details["error_name"]
            current_details["last_error_msg"] = details.get("error_msg")
        elif success and "last_error_name" in current_details:
            # Clear last error on success
            current_details.pop("last_error_name", None)
            current_details.pop("last_error_msg", None)
        info.details = current_details

        # Add event to history
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
            return  # Ignore invalid, standard, or already ignored paths
        log.info(f"Adding path to ignore list for '{self.identifier}': {path}")
        self.ignored_paths.add(path)

        # Remove existing state if present
        if path in self.files:
            log.debug(f"Removing ignored path from active state: {path}")
            # Clean up FDs associated with this path across all PIDs
            pids_fds_to_remove: list[tuple[int, int]] = []
            for pid, fd_map in self.pid_fd_map.items():
                for fd, p in fd_map.items():
                    if p == path:
                        pids_fds_to_remove.append((pid, fd))
            # Use the _remove_fd helper for proper cleanup
            for pid, fd in pids_fds_to_remove:
                self._remove_fd(
                    pid, fd
                )  # This handles pid_fd_map and FileInfo.open_by_pids

            # Remove from files map (check again as _remove_fd might affect it)
            if path in self.files:
                del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list."""
        log.info(f"Ignoring all currently tracked files for '{self.identifier}'")
        # Create list of paths to ignore *before* modifying the dict
        paths_to_ignore = [p for p in self.files.keys() if p not in STD_PATHS]
        count = 0
        for path in paths_to_ignore:
            if path not in self.ignored_paths:
                self.ignore(path)  # Call the ignore method for proper cleanup
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

        event_details = details.copy()
        event_details["fd"] = fd  # Ensure FD is in details for history
        self._finalize_update(info, "OPEN", success, timestamp, event_details)

        if success and fd >= 0:
            # Update status only if not already deleted
            if info.status != "deleted":
                info.status = "open"
            # Add mapping and update open set
            self._update_pid_fd_map(pid, fd, path)
            info.open_by_pids.setdefault(pid, set()).add(fd)
            log.debug(
                f"FileInfo updated for open: PID {pid} FD {fd}. Open PIDs: {list(info.open_by_pids.keys())}"
            )
        elif not success:
            # Mark as error if open failed (and not already deleted)
            if info.status != "deleted":
                info.status = "error"
        elif success and fd < 0:
            # Log warning for successful open with invalid FD
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

        # Use the helper to remove the FD mapping and update FileInfo state
        info = self._remove_fd(pid, fd)  # This handles map removal and status update

        if info:  # If FileInfo was found and updated by _remove_fd
            event_details = details.copy()
            event_details["fd"] = fd  # Ensure FD is in details for history
            # Finalize adds history entry and handles error details
            self._finalize_update(info, "CLOSE", success, timestamp, event_details)
            # Update status again if close failed *after* helper potentially set it to 'closed'
            if not success and info.status not in ["deleted", "open"]:
                info.status = "error"
        else:
            # Log if close event didn't match tracked state (e.g., closing untracked FD)
            log.debug(
                f"Close event for PID {pid} FD {fd} did not correspond to a tracked file state."
            )

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
        """Handles a 'read' (or similar) event."""
        log.debug(
            f"Monitor.read: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        # Try to resolve path from FD if not provided
        if path is None:
            path = self.get_path(pid, fd)
        # Get or create FileInfo, returns None if ignored/invalid/standard
        info = self._get_or_create_fileinfo(path, timestamp) if path else None
        if not info:
            return

        # Update byte count if successful
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
            info.bytes_read += byte_count

        event_details = details.copy()
        event_details["fd"] = fd  # Ensure FD is in details for history
        self._finalize_update(info, "READ", success, timestamp, event_details)

        # Update status based on success
        if success and info.status != "deleted":
            info.status = "active"  # Mark as active on successful read
        elif not success and info.status not in ["deleted", "open"]:
            # Mark as error on failure, unless it's already deleted or still open
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
        """Handles a 'write' (or similar) event."""
        log.debug(
            f"Monitor.write: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        # Try to resolve path from FD if not provided
        if path is None:
            path = self.get_path(pid, fd)
        # Get or create FileInfo, returns None if ignored/invalid/standard
        info = self._get_or_create_fileinfo(path, timestamp) if path else None
        if not info:
            return

        # Update byte count if successful and bytes > 0
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count > 0:
            info.bytes_written += byte_count

        event_details = details.copy()
        event_details["fd"] = fd  # Ensure FD is in details for history
        self._finalize_update(info, "WRITE", success, timestamp, event_details)

        # Update status based on success
        if success and info.status != "deleted":
            info.status = "active"  # Mark as active on successful write
        elif not success and info.status not in ["deleted", "open"]:
            # Mark as error on failure, unless it's already deleted or still open
            info.status = "error"

    @changes
    def stat(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles a 'stat', 'access', 'lstat' etc. event."""
        log.debug(
            f"Monitor.stat: pid={pid}, path={path}, success={success}, details={details}"
        )
        info = self._get_or_create_fileinfo(path, timestamp)
        if not info:
            return  # Path was ignored or invalid

        event_details = details.copy()
        self._finalize_update(info, "STAT", success, timestamp, event_details)

        # Update status: if successful and file wasn't open/active, mark as 'accessed'
        if success:
            if info.status in ["unknown", "closed", "accessed"]:
                info.status = "accessed"
        # If failed, mark as 'error' unless already deleted
        elif info.status != "deleted":
            info.status = "error"

    @changes
    def delete(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles an 'unlink', 'rmdir' event."""
        log.debug(
            f"Monitor.delete: pid={pid}, path={path}, success={success}, details={details}"
        )
        info = self.files.get(path)  # Check if path exists in our state
        if not info:
            # Log if delete event is for an untracked path
            log.debug(f"Delete event for untracked path: {path}")
            # Optionally create a temporary FileInfo to record the failed delete attempt?
            # For now, just return if not tracked.
            return

        event_details = details.copy()
        self._finalize_update(info, "DELETE", success, timestamp, event_details)

        if not success:
            # If delete failed, mark as error unless already deleted/open
            if info.status not in ["deleted", "open"]:
                info.status = "error"
            return

        # --- Successful Delete ---
        info.status = "deleted"
        log.info(f"Path '{path}' marked as deleted.")

        # Clean up associated state using the helper for each open FD
        pids_fds_to_remove: list[tuple[int, int]] = []
        # Iterate over copies as _remove_fd modifies the structure
        for open_pid, open_fds in list(info.open_by_pids.items()):
            for open_fd in list(open_fds):
                pids_fds_to_remove.append((open_pid, open_fd))

        log.debug(
            f"Cleaning up {len(pids_fds_to_remove)} FD mappings for deleted path '{path}'."
        )
        for remove_pid, remove_fd in pids_fds_to_remove:
            self._remove_fd(remove_pid, remove_fd)  # Use helper

        # Ensure open_by_pids is empty after cleanup (should be handled by _remove_fd)
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
            # If successful rename *to* ignored, treat old path as deleted
            if success and not old_is_ignored and old_path in self.files:
                self.delete(
                    pid, old_path, True, timestamp, {"renamed_to_ignored": new_path}
                )
            # If failed rename *to* ignored, just record failure on old path
            elif not success and not old_is_ignored and old_path in self.files:
                info_old = self.files[old_path]
                event_details = details.copy()
                event_details["target_path"] = new_path
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, event_details
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            return  # Stop processing rename if target is ignored

        if old_is_ignored:
            log.warning(
                f"Rename source path '{old_path}' is ignored (event on PID {pid})."
            )
            # If successful rename *from* ignored, treat as stat/access on new path
            if success:
                self.stat(
                    pid, new_path, True, timestamp, {"renamed_from_ignored": old_path}
                )
            return  # Stop processing rename if source is ignored

        # --- Handle rename failure (neither path ignored) ---
        if not success:
            # Record failure on both old and potentially new path state
            info_old = self.files.get(old_path)
            if info_old:
                event_details = details.copy()
                event_details["target_path"] = new_path
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, event_details
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            # Also record failure on target path (might create it)
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
            # Source path wasn't tracked, just treat as access on new path
            log.debug(
                f"Rename source path '{old_path}' not tracked. Treating as access to target '{new_path}'."
            )
            self.stat(
                pid, new_path, True, timestamp, {"renamed_from_unknown": old_path}
            )
            return

        # Get or create state for the new path
        new_info = self._get_or_create_fileinfo(new_path, timestamp)
        if not new_info:
            # Should not happen if new_path isn't ignored, but handle defensively
            log.error(
                f"Could not get/create FileInfo for rename target '{new_path}'. State may be inconsistent."
            )
            # Treat old path as deleted since rename succeeded but target state failed
            self.delete(
                pid,
                old_path,
                True,
                timestamp,
                {"error": "Rename target state creation failed"},
            )
            return

        # --- Transfer state from old_info to new_info ---
        new_info.status = (
            old_info.status if old_info.status != "deleted" else "accessed"
        )
        new_info.open_by_pids = old_info.open_by_pids  # Transfer open FDs map
        new_info.bytes_read = old_info.bytes_read
        new_info.bytes_written = old_info.bytes_written
        new_info.last_event_type = old_info.last_event_type  # Keep last event type
        new_info.last_error_enoent = old_info.last_error_enoent
        new_info.details = old_info.details  # Transfer details
        # Decide whether to transfer history or keep separate
        # Transferring keeps full context, but might be long. Let's transfer.
        new_info.event_history = old_info.event_history
        new_info.recent_event_types = old_info.recent_event_types
        # --- End State Transfer ---

        # Add RENAME event to history of *both* (before deleting old)
        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        self._add_event_to_history(
            old_info, "RENAME", success, timestamp, details_for_old
        )
        self._add_event_to_history(
            new_info, "RENAME", success, timestamp, details_for_new
        )
        # Finalize update for the new path
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        # Update pid_fd_map for all FDs that pointed to old_path
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
                self._update_pid_fd_map(update_pid, update_fd, new_path)

        # Remove old path state from the main files dictionary
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

        # Get list of FDs to close *before* iterating and calling close
        fds_to_close = list(self.pid_fd_map.get(pid, {}).keys())
        log.debug(f"PID {pid} exited, closing its associated FDs: {fds_to_close}")

        # Call the close handler for each FD associated with the exiting PID
        for fd in fds_to_close:
            self.close(
                pid,
                fd,
                success=True,  # Assume successful close on process exit
                timestamp=timestamp,
                details={"process_exited": True},
            )

        # Verify the PID entry is gone from pid_fd_map after closing all FDs
        if pid in self.pid_fd_map:
            # This indicates an issue in _remove_fd or close logic if it happens
            log.warning(
                f"PID {pid} still present in pid_fd_map after process_exit close loop. Forcing removal."
            )
            del self.pid_fd_map[pid]
        else:
            log.debug(
                f"PID {pid} successfully removed from pid_fd_map by close handlers during process_exit."
            )

    # --- Public Query/Access Methods ---

    @waits  # Decorator ensures thread safety (acquires lock)
    def __iter__(self) -> Iterator[FileInfo]:
        # Return a list copy for safe iteration if needed elsewhere,
        # though direct iteration might be fine with RLock if caller doesn't modify.
        # Let's return a list copy for safety.
        yield from list(self.files.values())

    @waits
    def __getitem__(self, path: str) -> FileInfo:
        # Accessing item, protected by lock via @waits
        return self.files[path]

    @waits
    def __contains__(self, path: str) -> bool:
        # Checking containment, protected by lock
        return isinstance(path, str) and path in self.files

    @waits
    def __len__(self) -> int:
        # Getting length, protected by lock
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> str | None:
        """Retrieves the path for a PID/FD, handling standard streams."""
        path = self.pid_fd_map.get(pid, {}).get(fd)
        if path is not None:
            return path
        # Handle standard streams if no mapping found
        if fd == 0:
            return STDIN_PATH
        if fd == 1:
            return STDOUT_PATH
        if fd == 2:
            return STDERR_PATH
        # Return None if FD is not standard and not mapped
        return None
