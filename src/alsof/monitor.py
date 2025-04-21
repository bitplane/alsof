import logging
import os
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field

from alsof.util.versioned import Versioned, changes, waits

# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("alsof.monitor")  # Use package-aware logger name

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
    status: str = (
        "unknown"  # "open", "closed", "deleted", "accessed", "error", "active"
    )
    last_activity_ts: float = field(default_factory=time.time)
    open_by_pids: dict[int, set[int]] = field(
        default_factory=dict
    )  # Key: pid, Value: set[fd]
    last_event_type: str = ""
    last_error_enoent: bool = False  # True if last file-not-found error occurred
    recent_event_types: deque[str] = field(default_factory=lambda: deque(maxlen=5))
    event_history: deque[dict] = field(default_factory=lambda: deque(maxlen=100))
    bytes_read: int = 0
    bytes_written: int = 0
    details: dict[str, any] = field(default_factory=dict)  # Use lowercase any

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
        super().__init__()
        self.identifier = identifier
        self.ignored_paths: set[str] = set()  # In-memory only

        # PID -> FD -> Path mapping
        self.pid_fd_map: dict[int, dict[int, str]] = {}
        # Path -> FileInfo mapping (the primary state)
        self.files: dict[str, FileInfo] = {}

        log.info(f"Initialized Monitor for identifier: '{identifier}'")

    def _cache_info(self, path: str, timestamp: float) -> FileInfo | None:
        """Gets existing FileInfo or creates a new one, checking ignore list."""
        if path in self.ignored_paths or path in STD_PATHS:
            log.debug(f"Ignoring event for path: {path}")
            return None
        if path not in self.files:
            log.debug(f"Creating new FileInfo for path: {path}")
            # Initial status is 'accessed' upon first encounter
            self.files[path] = FileInfo(
                path=path, last_activity_ts=timestamp, status="accessed"
            )
        # Always update timestamp on access/creation
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
        # Avoid storing large data chunks in history
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
        # Update recent event types only on success
        if success:
            # Add only if different from the last added type
            if not info.recent_event_types or info.recent_event_types[-1] != event_type:
                info.recent_event_types.append(event_type)

    # --- Public Handler Methods (Called by Backends/Adapters) ---

    @changes
    def ignore(self, path: str):
        """Adds a path to the ignore list (in-memory only)."""
        if not isinstance(path, str) or not path:
            return
        if path in STD_PATHS:
            return
        if path in self.ignored_paths:
            return

        log.info(f"Adding path to ignore list for '{self.identifier}': {path}")
        self.ignored_paths.add(path)

        # If the path was being tracked, remove its state
        if path not in self.files:
            return

        log.debug(f"Removing ignored path from active state: {path}")
        pids_with_path = []
        # Iterate over a copy of items for safe modification
        for pid, fd_map in list(self.pid_fd_map.items()):
            fds_to_remove = {fd for fd, p in fd_map.items() if p == path}
            if fds_to_remove:
                pids_with_path.append(pid)
                for fd in fds_to_remove:
                    log.debug(
                        f"Removing FD mapping for ignored path: PID {pid}, FD {fd}"
                    )
                    del fd_map[fd]  # Modify original map
        # Clean up empty PID entries in pid_fd_map
        for pid in pids_with_path:
            if pid in self.pid_fd_map and not self.pid_fd_map[pid]:
                del self.pid_fd_map[pid]
        # Finally, remove from the main files dictionary
        del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list (in-memory only)."""
        log.info(f"Ignoring all currently tracked files for '{self.identifier}'")
        # Create a list first to avoid modifying dict while iterating
        ignores = [p for p in self.files.keys() if p not in STD_PATHS]
        count = 0
        for path in ignores:
            # ignore() method handles checks and state removal
            if path not in self.ignored_paths:
                self.ignore(path)
                count += 1  # Count how many were actually newly ignored
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
        # Important: Call finalize *before* potentially changing status based on success
        self._finalize_update(info, "OPEN", success, timestamp, details_for_finalize)

        if success and fd >= 0:
            # Only set to open if not already deleted
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
        elif success and fd < 0:  # Successful open but invalid FD reported
            log.warning(
                f"Successful open reported for path '{path}' but FD is invalid ({fd})"
            )
            if info.status != "deleted":
                info.status = "error"

    @changes
    def close(self, pid: int, fd: int, success: bool, timestamp: float, **details):
        log.debug(f"close: pid={pid}, fd={fd}, success={success}")
        # Get path *before* potentially modifying map
        path = self.get_path(pid, fd)

        # --- Clean up pid_fd_map regardless of path validity if close succeeded ---
        # This handles cases where the mapping might be stale but the OS closed the FD.
        if success and pid in self.pid_fd_map and fd in self.pid_fd_map.get(pid, {}):
            mapped_path = self.pid_fd_map[pid][fd]
            # Only remove the mapping if the path matches what we expected,
            # unless the expected path was None (meaning we didn't know the FD).
            if path is None or mapped_path == path:
                del self.pid_fd_map[pid][fd]
                log.debug(
                    f"Removed mapping for PID {pid} FD {fd} (path: {mapped_path})"
                )
                if not self.pid_fd_map[pid]:
                    del self.pid_fd_map[pid]
            else:
                log.warning(
                    f"Close success for PID {pid} FD {fd}, "
                    f"but map pointed to '{mapped_path}' "
                    f"instead of expected '{path}'. Map not removed."
                )

        # --- Now update FileInfo state if path is valid and tracked ---
        if not path:
            log.debug(f"Close event for unknown PID {pid} FD {fd}, no FileInfo update.")
            return
        if path in STD_PATHS:
            log.debug(f"Ignoring close event state update for standard stream: {path}")
            return

        info = self.files.get(path)
        if not info:
            log.warning(
                f"Close event for PID {pid} FD {fd} refers to path '{path}' not in state. No FileInfo update."
            )
            return

        # --- Update FileInfo ---
        details_for_finalize = details.copy()
        self._finalize_update(info, "CLOSE", success, timestamp, details_for_finalize)

        if not success:
            # Don't change status on failed close, unless it was deleted
            if info.status == "deleted":
                pass  # Keep deleted status
            elif info.is_open:
                info.status = "open"  # Still considered open if close failed
            else:  # If wasn't open but close failed, might indicate error
                info.status = "error"
            return

        # --- Success Case for FileInfo ---
        # Remove the specific PID/FD from the file's open set
        if pid in info.open_by_pids:
            if fd in info.open_by_pids[pid]:
                info.open_by_pids[pid].remove(fd)
                log.debug(f"Removed FD {fd} from open set for PID {pid} ('{path}')")
            if not info.open_by_pids[pid]:  # If no more FDs for this PID
                del info.open_by_pids[pid]

        # Set status to closed *only if* no other process/fd holds it open
        if not info.is_open and info.status != "deleted":
            info.status = "closed"
            log.debug(f"Path '{path}' marked as closed.")
        elif info.is_open and info.status != "deleted":
            # If still open by others, ensure status reflects that
            info.status = "open"

    @changes
    def read(
        self,
        pid: int,
        fd: int,
        path: str | None,  # Path might be None if looked up via FD
        success: bool,
        timestamp: float,
        **details,
    ):
        log.debug(
            f"read: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        # Resolve path using fd if not provided
        if path is None:
            path = self.get_path(pid, fd)

        if not path:
            log.debug(f"Read event for PID {pid} FD {fd} could not resolve path.")
            return
        if path in STD_PATHS:
            log.debug(f"Ignoring read event details for standard stream: {path}")
            return

        info = self._cache_info(path, timestamp)
        if not info:
            return

        # Update byte count if successful read
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
            info.bytes_read += byte_count

        details_for_finalize = details.copy()
        self._finalize_update(info, "READ", success, timestamp, details_for_finalize)

        # Update status only if the operation was successful and file isn't deleted
        if success and info.status != "deleted":
            info.status = "active"  # Indicate recent activity
        elif not success and info.status not in [
            "deleted",
            "open",
        ]:  # Set error only if not open/deleted
            info.status = "error"

    @changes
    def write(
        self,
        pid: int,
        fd: int,
        path: str | None,  # Path might be None
        success: bool,
        timestamp: float,
        **details,
    ):
        log.debug(
            f"write: pid={pid}, fd={fd}, path={path}, success={success}, details={details}"
        )
        if path is None:
            path = self.get_path(pid, fd)

        if not path:
            log.debug(f"Write event for PID {pid} FD {fd} could not resolve path.")
            return
        if path in STD_PATHS:
            log.debug(f"Ignoring write event details for standard stream: {path}")
            return

        info = self._cache_info(path, timestamp)
        if not info:
            return

        # Update byte count if successful write
        byte_count = details.get("bytes")
        if (
            success and isinstance(byte_count, int) and byte_count > 0
        ):  # Write counts > 0
            info.bytes_written += byte_count

        details_for_finalize = details.copy()
        self._finalize_update(info, "WRITE", success, timestamp, details_for_finalize)

        # Update status only if the operation was successful and file isn't deleted
        if success and info.status != "deleted":
            info.status = "active"  # Indicate recent activity
        elif not success and info.status not in [
            "deleted",
            "open",
        ]:  # Set error only if not open/deleted
            info.status = "error"

    @changes
    def stat(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles a stat/access event."""
        log.debug(f"stat: pid={pid}, path={path}, success={success}")
        info = self._cache_info(path, timestamp)
        if not info:
            return

        details_for_finalize = details.copy()
        self._finalize_update(info, "STAT", success, timestamp, details_for_finalize)

        # Update status based on success, but only if not already open or deleted
        if success:
            # Don't override more specific statuses like open/active/deleted/error
            if info.status not in ["open", "deleted", "active", "error"]:
                info.status = "accessed"
        else:  # Not successful stat
            if info.status != "deleted":
                info.status = "error"

    @changes
    def delete(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles unlink, rmdir events."""
        log.debug(f"delete: pid={pid}, path={path}, success={success}")
        info = self.files.get(path)  # Use get() as file might not be tracked

        if not info:
            # If file doesn't exist in cache, a successful delete means nothing to track
            # A failed delete also means nothing to track *now*
            log.debug(f"Delete event for untracked path: {path}")
            # Even if untracked, add a history event if needed for debugging? Optional.
            # self._add_event_to_history(FileInfo(path=path), "DELETE", success, timestamp, details) # Example
            return

        # --- Update FileInfo ---
        details_for_finalize = details.copy()
        self._finalize_update(info, "DELETE", success, timestamp, details_for_finalize)

        if not success:
            if info.status not in [
                "deleted",
                "open",
            ]:  # Avoid changing open file status on failed delete
                info.status = "error"
            return

        # --- Success Case ---
        info.status = "deleted"
        # Clear open FDs as the underlying file is gone
        pids_holding_open = list(info.open_by_pids.keys())
        for check_pid in pids_holding_open:
            fds_to_remove = set(info.open_by_pids.get(check_pid, set()))
            for fd in fds_to_remove:
                log.debug(
                    f"Removing FD mapping due to delete: PID {check_pid}, FD {fd}"
                )
                # Remove from the global pid->fd map
                if (
                    check_pid in self.pid_fd_map
                    and fd in self.pid_fd_map.get(check_pid, {})
                    and self.pid_fd_map[check_pid][fd]
                    == path  # Ensure it's the correct path
                ):
                    del self.pid_fd_map[check_pid][fd]
                    if not self.pid_fd_map[check_pid]:  # Clean up empty PID entry
                        del self.pid_fd_map[check_pid]

            # Remove from the FileInfo's local record
            if check_pid in info.open_by_pids:
                del info.open_by_pids[check_pid]

        # As a safety measure, ensure open_by_pids is empty after delete
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
        """Handles a rename event by updating internal state."""
        log.debug(
            f"rename: pid={pid}, old={old_path}, new={new_path}, success={success}"
        )

        # --- Handle ignored paths ---
        old_is_ignored = old_path in self.ignored_paths
        new_is_ignored = new_path in self.ignored_paths

        if new_is_ignored:
            log.info(f"Rename target path '{new_path}' is ignored.")
            # If successful rename to ignored, treat old path as deleted (if tracked)
            if success and not old_is_ignored and old_path in self.files:
                self.delete(
                    pid, old_path, True, timestamp, {"renamed_to_ignored": new_path}
                )
            # If failed rename to ignored, potentially log error on old path (if tracked)
            elif not success and not old_is_ignored and old_path in self.files:
                info_old = self.files[old_path]
                details_for_finalize = details.copy()
                self._finalize_update(
                    info_old, "RENAME", success, timestamp, details_for_finalize
                )
                if info_old.status != "deleted":
                    info_old.status = "error"
            return  # Stop processing if target is ignored

        if old_is_ignored:
            # Renaming *from* an ignored path
            log.warning(
                f"Rename source path '{old_path}' is ignored (event on PID {pid})."
            )
            if success:
                # Treat as a stat/access on the new path (since it's not ignored)
                self.stat(
                    pid, new_path, True, timestamp, {"renamed_from_ignored": old_path}
                )
            # If fails, nothing happens to tracked state
            return  # Stop processing if source is ignored

        # --- Handle failed rename attempt (neither path ignored) ---
        if not success:
            info = self.files.get(old_path)
            if not info:
                return  # Failed rename of untracked file

            details_for_finalize = details.copy()
            self._finalize_update(
                info, "RENAME", success, timestamp, details_for_finalize
            )
            if info.status != "deleted":
                info.status = "error"
            return

        # --- Successful Rename (neither path ignored) ---
        old_info = self.files.get(old_path)
        if not old_info:
            # Successful rename of an untracked file -> treat as access/creation of new path
            log.debug(
                f"Rename source path '{old_path}' not tracked. Treating as access to target '{new_path}'."
            )
            self.stat(
                pid, new_path, True, timestamp, {"renamed_from_unknown": old_path}
            )
            return

        log.info(f"Processing successful rename: '{old_path}' -> '{new_path}'")

        # Get or create FileInfo for the new path
        new_info = self._cache_info(new_path, timestamp)
        if not new_info:  # Should not happen if new_path isn't ignored
            log.error(
                f"Could not get/create FileInfo for rename target '{new_path}'. State may be inconsistent."
            )
            # Treat old path as deleted since it's gone
            self.delete(
                pid,
                old_path,
                True,
                timestamp,
                {"error": "Rename target state creation failed"},
            )
            return

        # --- Transfer state from old_info to new_info ---
        # If new_info existed (overwrite), keep its history/bytes? Or replace?
        # Current approach: Replace state entirely with old_info's state.
        new_info.status = (
            old_info.status if old_info.status != "deleted" else "accessed"
        )
        new_info.open_by_pids = old_info.open_by_pids  # Transfer open FDs map
        new_info.bytes_read = old_info.bytes_read  # Transfer R/W counts
        new_info.bytes_written = old_info.bytes_written
        # Merge history? Or just take old? Taking old's history for simplicity.
        # new_info.event_history = old_info.event_history # This might lose new_info's prior history
        # new_info.recent_event_types = old_info.recent_event_types # Transfer recent events
        new_info.last_event_type = (
            old_info.last_event_type
        )  # Carry over last event type
        new_info.last_error_enoent = (
            old_info.last_error_enoent
        )  # Carry over error state
        new_info.details = old_info.details  # Transfer details

        # Add rename event to both histories (old will be deleted, new persists)
        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        # Add history to old_info *before* deleting it
        self._add_event_to_history(
            old_info, "RENAME", success, timestamp, details_for_old
        )
        # Add history to new_info
        self._add_event_to_history(
            new_info, "RENAME", success, timestamp, details_for_new
        )
        # Update timestamp/event type on new_info via finalize
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        # --- Update the global PID->FD map ---
        # Find all PIDs/FDs currently mapped to old_path
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
                    self.pid_fd_map[update_pid][
                        update_fd
                    ] = new_path  # Update path in map

        # --- Remove the old path state ---
        log.debug(f"Removing old path state after successful rename: {old_path}")
        del self.files[old_path]

    # --- Public Query/Access Methods ---

    @waits
    def __iter__(self) -> Iterator[FileInfo]:  # Iterator is from collections.abc
        """Iterates over tracked FileInfo objects (values of self.files)."""
        # Return a copy of values to prevent modification during iteration issues
        yield from list(self.files.values())

    @waits
    def __getitem__(self, path: str) -> FileInfo:
        """Gets FileInfo for a specific path using dictionary-style access."""
        return self.files[path]  # Raises KeyError if not found

    @waits
    def __contains__(self, path: str) -> bool:
        """Checks if a path is currently being tracked (key in self.files)."""
        if not isinstance(path, str):
            return False
        return path in self.files

    @waits
    def __len__(self) -> int:
        """Returns the number of tracked files (excluding ignored)."""
        # This counts keys in self.files, which already excludes ignored paths
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> str | None:
        """
        Gets the path associated with a PID/FD combination from cache,
        returning placeholders for std streams if not found.
        """
        path = self.pid_fd_map.get(pid, {}).get(fd)
        if path is not None:
            return path
        # Handle std streams only if not found in map
        if fd == 0:
            return STDIN_PATH
        if fd == 1:
            return STDOUT_PATH
        if fd == 2:
            return STDERR_PATH
        return None  # Unknown FD

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
        info.last_activity_ts = timestamp  # Always update timestamp
        info.last_event_type = event_type

        # Update last_error_enoent status based on specific syscall types
        # ENOENT means "No such file or directory"
        if event_type in [
            "OPEN",
            "STAT",
            "DELETE",
            "RENAME",
            "ACCESS",
            "CHDIR",
        ]:  # Added CHDIR, ACCESS
            info.last_error_enoent = (
                not success and details.get("error_name") == "ENOENT"
            )
        # Clear ENOENT error flag if a subsequent successful operation occurs on the file
        # (except for delete, which might succeed on an already gone file)
        elif success and event_type != "DELETE":
            info.last_error_enoent = False
        # Don't clear ENOENT on failed non-file-checking ops like read/write/close

        # Merge details, prioritizing current event's info
        current_details = info.details
        current_details.update(details)
        # Update or clear last_error_name based on success
        if not success and "error_name" in details:
            current_details["last_error_name"] = details[
                "error_name"
            ]  # Store last error name
        elif success and "last_error_name" in current_details:
            # Clear previous error only if current event was successful
            del current_details["last_error_name"]
        info.details = current_details  # Assign back the updated details

        # Add event to history *after* updating other state like last_error_enoent
        self._add_event_to_history(info, event_type, success, timestamp, info.details)

    @changes
    def process_exit(self, pid: int, timestamp: float):
        """Handles cleanup when a process exits (e.g., receives exit_group)."""
        log.info(f"Processing exit for PID: {pid}")
        if pid not in self.pid_fd_map:
            log.debug(f"PID {pid} not found in fd map, no FD cleanup needed.")
            return

        # Get FDs associated with the exiting PID *before* modifying the map
        fds_to_close = list(self.pid_fd_map.get(pid, {}).keys())
        log.debug(f"PID {pid} exited, closing associated FDs: {fds_to_close}")

        # Use the close handler for each FD to update state consistently
        for fd in fds_to_close:
            # Treat as a successful close from the monitor's perspective
            self.close(
                pid,
                fd,
                success=True,
                timestamp=timestamp,
                details={"process_exited": True},
            )

        # Ensure the PID is removed from the map *after* closing FDs
        # The close calls should have handled this, but double-check
        if pid in self.pid_fd_map:
            # If close didn't remove it (e.g., path mismatch warning), remove it now.
            log.warning(
                f"Removing PID {pid} from pid_fd_map post-exit (may indicate prior inconsistency)."
            )
            del self.pid_fd_map[pid]
        else:
            log.debug(f"PID {pid} already removed from pid_fd_map by close handlers.")
