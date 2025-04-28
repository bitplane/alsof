# Filename: src/lsoph/monitor/_monitor.py
"""
Contains the Monitor class responsible for managing file access state.
Stores paths as bytes.
"""

import logging
import os
from collections.abc import Iterator
from typing import Any

from upd8 import Versioned, changes, waits

from ..util.pid import get_fd_path
from ._fileinfo import FileInfo

# Setup Logging
log = logging.getLogger("lsoph.monitor")

# Constants for standard streams
STDIN_PATH = b"<STDIN>"
STDOUT_PATH = b"<STDOUT>"
STDERR_PATH = b"<STDERR>"
STD_PATHS = {0: STDIN_PATH, 1: STDOUT_PATH, 2: STDERR_PATH}


class Monitor(Versioned):
    """
    Manages the state of files accessed by a monitored target (process group).
    Inherits from Versioned for change tracking and thread safety via decorators.
    Provides methods for backends to report file events.
    Stores paths as bytes internally.
    """

    def __init__(self, identifier: str):
        super().__init__()
        self.identifier = identifier
        self.ignored_paths = set()
        self.pid_fd_map = {}
        self.files = {}
        self.backend_pid = None
        log.info(f"Initialized Monitor for identifier: '{identifier}'")

    def _get_or_create_fileinfo(self, path: bytes, timestamp: float) -> FileInfo:
        """Gets existing FileInfo or creates one. Raises if ignored/invalid."""
        if path in self.ignored_paths:
            raise ValueError(
                f"Path {os.fsdecode(path)!r} is ignored or a standard stream"
            )

        if path not in self.files:
            log.debug(f"Creating new FileInfo for path: {os.fsdecode(path)!r}")
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
        details: dict[str, Any],
    ):
        """Adds event to the file's history."""
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

        if success and (
            not info.recent_event_types or info.recent_event_types[-1] != event_type
        ):
            info.recent_event_types.append(event_type)

    @changes
    def _update_pid_fd_map(self, pid: int, fd: int, path: bytes | None):
        """Updates or removes entries in the pid_fd_map."""
        if path:
            if pid not in self.pid_fd_map:
                self.pid_fd_map[pid] = {}

            self.pid_fd_map[pid][fd] = path
            log.debug(f"Mapping PID {pid} FD {fd} -> {os.fsdecode(path)!r}")
        else:
            if pid in self.pid_fd_map and fd in self.pid_fd_map[pid]:
                self.pid_fd_map[pid].pop(fd)
                log.debug(f"Removed mapping for PID {pid} FD {fd}")

                if not self.pid_fd_map[pid]:
                    del self.pid_fd_map[pid]

    @changes
    def _remove_fd(self, pid: int, fd: int) -> FileInfo | None:
        """Removes an FD mapping and updates FileInfo state."""
        self._update_pid_fd_map(pid, fd, None)

        try:
            path = self.get_path(pid, fd)
        except KeyError:
            return None

        info = self.files.get(path)
        if not info:
            return None

        # Remove from FileInfo.open_by_pids
        if pid in info.open_by_pids:
            if fd in info.open_by_pids[pid]:
                info.open_by_pids[pid].remove(fd)

            if not info.open_by_pids[pid]:
                del info.open_by_pids[pid]

        # Update status
        if not info.is_open and info.status != "deleted":
            info.status = "closed"
        elif info.is_open and info.status != "deleted":
            if info.status not in ["open", "active"]:
                info.status = "open"

        return info

    def _finalize_update(
        self,
        info: FileInfo,
        event_type: str,
        success: bool,
        timestamp: float,
        details: dict[str, Any],
    ):
        """Updates common state in FileInfo."""
        info.last_activity_ts = timestamp
        info.last_event_type = event_type

        # Update error flags
        if event_type in ["OPEN", "STAT", "DELETE", "RENAME", "ACCESS", "CHDIR"]:
            info.last_error_enoent = (
                not success and details.get("error_name") == "ENOENT"
            )
        elif success and event_type != "DELETE":
            info.last_error_enoent = False

        # Update details
        current_details = info.details
        current_details.update(details)

        if not success and "error_name" in details:
            current_details["last_error_name"] = details["error_name"]
            current_details["last_error_msg"] = details.get("error_msg")
        elif success and "last_error_name" in current_details:
            current_details.pop("last_error_name", None)
            current_details.pop("last_error_msg", None)

        info.details = current_details

        # Add event to history
        self._add_event_to_history(info, event_type, success, timestamp, info.details)

    @changes
    def ignore(self, path: bytes):
        """Adds a path to the ignore list and removes existing state for it."""
        if not path or path in STD_PATHS.values() or path in self.ignored_paths:
            return

        log.info(f"Adding path to ignore list: {os.fsdecode(path)!r}")
        self.ignored_paths.add(path)

        # Remove existing state if present
        if path in self.files:
            # Clean up FDs
            pids_fds_to_remove = []
            for pid, fd_map in self.pid_fd_map.items():
                for fd, mapped_path in fd_map.items():
                    if mapped_path == path:
                        pids_fds_to_remove.append((pid, fd))

            for pid, fd in pids_fds_to_remove:
                self._remove_fd(pid, fd)

            # Remove from files map
            if path in self.files:
                del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list."""
        paths_to_ignore = [p for p in self.files.keys() if p not in STD_PATHS.values()]
        for path in paths_to_ignore:
            if path not in self.ignored_paths:
                self.ignore(path)

    @changes
    def open(
        self, pid: int, path: bytes, fd: int, success: bool, timestamp: float, **details
    ):
        """Handles an 'open' or 'creat' event."""
        try:
            info = self._get_or_create_fileinfo(path, timestamp)
        except ValueError:
            return

        event_details = details.copy()
        event_details["fd"] = fd
        self._finalize_update(info, "OPEN", success, timestamp, event_details)

        if success and fd >= 0:
            if info.status != "deleted":
                info.status = "open"

            # Update mappings
            self._update_pid_fd_map(pid, fd, path)
            info.open_by_pids.setdefault(pid, set()).add(fd)
        elif not success and info.status != "deleted":
            info.status = "error"

    @changes
    def close(self, pid: int, fd: int, success: bool, timestamp: float, **details):
        """Handles a 'close' event."""
        info = self._remove_fd(pid, fd)

        if info:
            event_details = details.copy()
            event_details["fd"] = fd
            self._finalize_update(info, "CLOSE", success, timestamp, event_details)

            if not success and info.status not in ["deleted", "open"]:
                info.status = "error"

    @changes
    def read(
        self,
        pid: int,
        fd: int,
        path: bytes | None,
        success: bool,
        timestamp: float,
        **details,
    ):
        """Handles a 'read' event."""
        if path is None:
            path = self.get_path(pid, fd)

        try:
            info = self._get_or_create_fileinfo(path, timestamp) if path else None
        except ValueError:
            return

        # Update byte count
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
            info.bytes_read += byte_count

        event_details = details.copy()
        event_details["fd"] = fd
        self._finalize_update(info, "READ", success, timestamp, event_details)

        # Update status
        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in ["deleted", "open"]:
            info.status = "error"

    @changes
    def write(
        self,
        pid: int,
        fd: int,
        path: bytes | None,
        success: bool,
        timestamp: float,
        **details,
    ):
        """Handles a 'write' event."""
        if path is None:
            path = self.get_path(pid, fd)

        try:
            info = self._get_or_create_fileinfo(path, timestamp) if path else None
        except ValueError:
            return

        # Update byte count
        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count > 0:
            info.bytes_written += byte_count

        event_details = details.copy()
        event_details["fd"] = fd
        self._finalize_update(info, "WRITE", success, timestamp, event_details)

        # Update status
        if success and info.status != "deleted":
            info.status = "active"
        elif not success and info.status not in ["deleted", "open"]:
            info.status = "error"

    @changes
    def stat(self, pid: int, path: bytes, success: bool, timestamp: float, **details):
        """Handles a 'stat' event."""
        try:
            info = self._get_or_create_fileinfo(path, timestamp)
        except ValueError:
            return

        self._finalize_update(info, "STAT", success, timestamp, details)

        # Update status
        if success:
            if info.status in ["unknown", "closed", "accessed"]:
                info.status = "accessed"
        elif info.status != "deleted":
            info.status = "error"

    @changes
    def delete(self, pid: int, path: bytes, success: bool, timestamp: float, **details):
        """Handles a deletion event."""
        info = self.files.get(path)
        if not info:
            return

        self._finalize_update(info, "DELETE", success, timestamp, details)

        if not success:
            if info.status not in ["deleted", "open"]:
                info.status = "error"
            return

        # For successful delete
        info.status = "deleted"
        log.info(f"Path '{os.fsdecode(path)!r}' marked as deleted.")

        # Clean up associated state
        pids_fds_to_remove = []
        for open_pid, open_fds in list(info.open_by_pids.items()):
            for open_fd in list(open_fds):
                pids_fds_to_remove.append((open_pid, open_fd))

        for remove_pid, remove_fd in pids_fds_to_remove:
            self._remove_fd(remove_pid, remove_fd)

        # Ensure open_by_pids is empty
        info.open_by_pids.clear()

    @changes
    def rename(
        self,
        pid: int,
        old_path: bytes,
        new_path: bytes,
        success: bool,
        timestamp: float,
        **details,
    ):
        """Handles a 'rename' event."""
        old_is_ignored = (
            old_path in self.ignored_paths or old_path in STD_PATHS.values()
        )
        new_is_ignored = (
            new_path in self.ignored_paths or new_path in STD_PATHS.values()
        )

        # Handle cases with ignored paths
        if new_is_ignored:
            if success and not old_is_ignored and old_path in self.files:
                self.delete(
                    pid, old_path, True, timestamp, {"renamed_to_ignored": new_path}
                )
            return

        if old_is_ignored:
            if success:
                self.stat(
                    pid, new_path, True, timestamp, {"renamed_from_ignored": old_path}
                )
            return

        # Handle rename failure
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

            try:
                info_new = self._get_or_create_fileinfo(new_path, timestamp)
                event_details = details.copy()
                event_details["source_path"] = old_path
                self._finalize_update(
                    info_new, "RENAME_TARGET", success, timestamp, event_details
                )
                if info_new.status != "deleted":
                    info_new.status = "error"
            except ValueError:
                pass
            return

        # Handle successful rename
        old_info = self.files.get(old_path)
        if not old_info:
            self.stat(
                pid, new_path, True, timestamp, {"renamed_from_unknown": old_path}
            )
            return

        try:
            new_info = self._get_or_create_fileinfo(new_path, timestamp)
        except ValueError:
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
        new_info.event_history = old_info.event_history
        new_info.recent_event_types = old_info.recent_event_types

        # Add events
        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        self._add_event_to_history(
            old_info, "RENAME", success, timestamp, details_for_old
        )
        self._add_event_to_history(
            new_info, "RENAME", success, timestamp, details_for_new
        )
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        # Update FD mappings
        pids_fds_to_update = []
        for map_pid, fd_map in self.pid_fd_map.items():
            for map_fd, map_path in fd_map.items():
                if map_path == old_path:
                    pids_fds_to_update.append((map_pid, map_fd))

        for update_pid, update_fd in pids_fds_to_update:
            self._update_pid_fd_map(update_pid, update_fd, new_path)

        # Remove old path state
        del self.files[old_path]

    @changes
    def process_exit(self, pid: int, timestamp: float):
        """Handles cleanup when a process exits."""
        if pid not in self.pid_fd_map:
            return

        fds_to_close = list(self.pid_fd_map.get(pid, {}).keys())
        for fd in fds_to_close:
            self.close(pid, fd, True, timestamp, {"process_exited": True})

        # Ensure PID is removed
        if pid in self.pid_fd_map:
            del self.pid_fd_map[pid]

    # Public Query Methods

    @waits
    def __iter__(self) -> Iterator[FileInfo]:
        yield from list(self.files.values())

    @waits
    def __getitem__(self, path: bytes) -> FileInfo:
        return self.files[path]

    @waits
    def __contains__(self, path: bytes) -> bool:
        return isinstance(path, bytes) and path in self.files

    @waits
    def __len__(self) -> int:
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> bytes:
        """Retrieves the path for a PID/FD."""
        path = STD_PATHS.get(fd) or self.pid_fd_map.get(pid, {}).get(fd)

        if path is not None:
            return path

        path = get_fd_path(pid, fd)
        if path:
            self._update_pid_fd_map(pid, fd, path)
            return path

        raise KeyError(f"pid={pid} does not have fd={fd}")
