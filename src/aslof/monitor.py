#!/usr/bin/env python3

# Filename: monitor.py
# Assumes versioned.py exists in the same package/PYTHONPATH

import os
import logging
import sys
import time
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Any, Union, Deque, Iterator
from collections import deque

# Assumes versioned.py contains Versioned, changes, waits
from versioned import Versioned, changes, waits

# --- Setup Logging ---
logging.basicConfig(level=os.environ.get("LOGLEVEL", "WARNING").upper(),
                    format='%(levelname)s:%(name)s:%(message)s')
log = logging.getLogger(__name__)


# --- File State Information ---

@dataclass
class FileInfo:
    """Holds state information about a single tracked file."""
    path: str
    status: str = "unknown" # "open", "closed", "deleted", "accessed", "error"
    last_activity_ts: float = field(default_factory=time.time)
    open_by_pids: Dict[int, Set[int]] = field(default_factory=dict) # Key: pid, Value: Set[fd]
    last_event_type: str = ""
    last_error_enoent: bool = False
    recent_event_types: Deque[str] = field(default_factory=lambda: deque(maxlen=5))
    event_history: Deque[Dict] = field(default_factory=lambda: deque(maxlen=100))
    bytes_read: int = 0
    bytes_written: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
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
        self.ignored_paths: Set[str] = set() # In-memory only

        self.pid_fd_map: Dict[int, Dict[int, str]] = {} # PID -> FD -> Path
        self.files: Dict[str, FileInfo] = {} # Path -> FileInfo

        log.info(f"Initialized Monitor for identifier: '{identifier}'")


    def _cache_info(self, path: str, timestamp: float) -> Optional[FileInfo]:
        """Gets existing FileInfo or creates a new one, checking ignore list."""
        if path in self.ignored_paths:
            log.debug(f"Ignoring event for path: {path}")
            return None
        if path not in self.files:
            log.debug(f"Creating new FileInfo for path: {path}")
            self.files[path] = FileInfo(path=path, last_activity_ts=timestamp, status="accessed")
        self.files[path].last_activity_ts = timestamp
        return self.files[path]

    def _add_event_to_history(self, info: FileInfo, event_type: str, success: bool, timestamp: float, details: Dict):
        """Adds a simplified event representation to the file's history."""
        simple_details = {k: v for k, v in details.items() if k not in ['read_data', 'write_data']}
        info.event_history.append({
            'ts': timestamp, 'type': event_type, 'success': success, 'details': simple_details
        })
        if success and event_type != info.last_event_type:
             if not info.recent_event_types or info.recent_event_types[-1] != event_type:
                  info.recent_event_types.append(event_type)


    # --- Public Handler Methods (Called by Backends/Adapters) ---
    # NOTE: tid parameter removed from all handlers

    @changes
    def ignore(self, path: str):
        """Adds a path to the ignore list (in-memory only)."""
        if not isinstance(path, str) or not path: return
        if path in self.ignored_paths: return

        log.info(f"Adding path to ignore list for '{self.identifier}': {path}")
        self.ignored_paths.add(path)

        if path not in self.files: return

        log.debug(f"Removing ignored path from active state: {path}")
        pids_with_path = []
        for pid, fd_map in list(self.pid_fd_map.items()):
            fds_to_remove = {fd for fd, p in fd_map.items() if p == path}
            if fds_to_remove:
                 pids_with_path.append(pid)
                 for fd in fds_to_remove:
                     log.debug(f"Removing FD mapping for ignored path: PID {pid}, FD {fd}")
                     del fd_map[fd]
        for pid in pids_with_path:
             if not self.pid_fd_map[pid]: del self.pid_fd_map[pid]
        del self.files[path]

    @changes
    def ignore_all(self):
        """Adds all currently tracked file paths to the ignore list (in-memory only)."""
        log.info(f"Ignoring all currently tracked files for '{self.identifier}'")
        ignores = list(self.files.keys())
        count = 0
        for path in ignores:
             if path not in self.ignored_paths:
                 self.ignore(path)
                 count += 1
        log.info(f"Added {count} paths to ignore list via ignore_all.")

    @changes
    def open(self, pid: int, path: str, fd: int, success: bool, timestamp: float, **details):
        log.debug(f"open: pid={pid}, path={path}, fd={fd}, success={success}")
        info = self._cache_info(path, timestamp)
        if not info: return

        details_for_finalize = details.copy()
        self._finalize_update(info, "OPEN", success, timestamp, details_for_finalize)

        if success and fd >= 0:
            info.status = "open"
            if pid not in self.pid_fd_map: self.pid_fd_map[pid] = {}
            self.pid_fd_map[pid][fd] = path
            if pid not in info.open_by_pids: info.open_by_pids[pid] = set()
            info.open_by_pids[pid].add(fd)
            log.debug(f"Mapped PID {pid} FD {fd} -> '{path}', PIDs with open FDs: {list(info.open_by_pids.keys())}")
        elif not success:
            if info.status != "deleted": info.status = "error"
        elif success and fd < 0:
            log.warning(f"Successful open reported for path '{path}' but FD is invalid ({fd})")
            if info.status != "deleted": info.status = "error"


    @changes
    def close(self, pid: int, fd: int, success: bool, timestamp: float, **details):
        log.debug(f"close: pid={pid}, fd={fd}, success={success}")
        path = self.pid_fd_map.get(pid, {}).get(fd)

        if not path:
             log.warning(f"Close event for unknown PID {pid} FD {fd}")
             return

        info = self.files.get(path)
        if not info:
            log.warning(f"Close event for PID {pid} FD {fd} refers to path '{path}' not in state.")
            if success and pid in self.pid_fd_map and fd in self.pid_fd_map[pid]:
                 del self.pid_fd_map[pid][fd]
                 if not self.pid_fd_map[pid]: del self.pid_fd_map[pid]
            return

        details_for_finalize = details.copy()
        self._finalize_update(info, "CLOSE", success, timestamp, details_for_finalize)

        if not success:
             if info.is_open and info.status != "deleted": info.status = "open"
             elif info.status != "deleted": info.status = "error"
             return

        # Success Case
        if pid in self.pid_fd_map and fd in self.pid_fd_map[pid]:
            del self.pid_fd_map[pid][fd]
            log.debug(f"Removed mapping for PID {pid} FD {fd}")
            if not self.pid_fd_map[pid]: del self.pid_fd_map[pid]

        if pid in info.open_by_pids:
            if fd in info.open_by_pids[pid]:
                 info.open_by_pids[pid].remove(fd)
                 log.debug(f"Removed FD {fd} from open set for PID {pid} ('{path}')")
            if not info.open_by_pids[pid]:
                 del info.open_by_pids[pid]

        if not info.is_open and info.status != "deleted":
             info.status = "closed"
             log.debug(f"Path '{path}' marked as closed.")


    @changes
    def read(self, pid: int, fd: int, path: Optional[str], success: bool, timestamp: float, **details):
        log.debug(f"read: pid={pid}, fd={fd}, path={path}, success={success}, details={details}")
        if path is None: path = self.get_path(pid, fd)

        if not path:
            log.warning(f"Read event for PID {pid} FD {fd} could not resolve path.")
            return

        info = self._cache_info(path, timestamp)
        if not info: return

        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count >= 0:
             info.bytes_read += byte_count

        details_for_finalize = details.copy()
        self._finalize_update(info, "READ", success, timestamp, details_for_finalize)

        if info.status != "deleted": info.status = "active"


    @changes
    def write(self, pid: int, fd: int, path: Optional[str], success: bool, timestamp: float, **details):
        log.debug(f"write: pid={pid}, fd={fd}, path={path}, success={success}, details={details}")
        if path is None: path = self.get_path(pid, fd)

        if not path:
             log.warning(f"Write event for PID {pid} FD {fd} could not resolve path.")
             return

        info = self._cache_info(path, timestamp)
        if not info: return

        byte_count = details.get("bytes")
        if success and isinstance(byte_count, int) and byte_count > 0:
             info.bytes_written += byte_count

        details_for_finalize = details.copy()
        self._finalize_update(info, "WRITE", success, timestamp, details_for_finalize)

        if info.status != "deleted": info.status = "active"


    @changes
    def stat(self, pid: int, path: str, success: bool, timestamp: float, **details):
        """Handles a stat/access event."""
        log.debug(f"stat: pid={pid}, path={path}, success={success}")
        info = self._cache_info(path, timestamp)
        if not info: return

        details_for_finalize = details.copy()
        self._finalize_update(info, "STAT", success, timestamp, details_for_finalize)

        if info.status not in ["open", "deleted"]:
             info.status = "accessed" if success else "error"


    @changes
    def delete(self, pid: int, path: str, success: bool, timestamp: float, **details):
        log.debug(f"delete: pid={pid}, path={path}, success={success}")
        info = self._cache_info(path, timestamp)
        if not info: return

        details_for_finalize = details.copy()
        self._finalize_update(info, "DELETE", success, timestamp, details_for_finalize)

        if not success:
            if info.status not in ["open", "deleted"]: info.status = "error"
            return

        # Success Case
        info.status = "deleted"
        # Clean up FD maps and FileInfo.open_by_pids
        pids_to_check = list(self.pid_fd_map.keys())
        for check_pid in pids_to_check:
             if check_pid in info.open_by_pids:
                 fds_to_remove = set(info.open_by_pids[check_pid])
                 for fd in fds_to_remove:
                     log.debug(f"Removing FD mapping due to delete: PID {check_pid}, FD {fd}")
                     if check_pid in self.pid_fd_map and fd in self.pid_fd_map[check_pid]:
                         if self.pid_fd_map[check_pid][fd] == path:
                             del self.pid_fd_map[check_pid][fd]
                     if check_pid in info.open_by_pids and fd in info.open_by_pids[check_pid]:
                          info.open_by_pids[check_pid].remove(fd)
                 if check_pid in info.open_by_pids and not info.open_by_pids[check_pid]:
                      del info.open_by_pids[check_pid]

             if check_pid in self.pid_fd_map:
                  fds_to_remove_extra = {fd for fd, p in self.pid_fd_map[check_pid].items() if p == path}
                  for fd in fds_to_remove_extra: del self.pid_fd_map[check_pid][fd]
                  if not self.pid_fd_map[check_pid]: del self.pid_fd_map[check_pid]
        info.open_by_pids.clear()


    @changes
    def rename(self, pid: int, old_path: str, new_path: str, success: bool, timestamp: float, **details):
        """Handles a rename event by updating internal state."""
        log.debug(f"rename: pid={pid}, old={old_path}, new={new_path}, success={success}")

        # --- Handle ignored paths (early outs) ---
        if new_path in self.ignored_paths:
            log.info(f"Rename target path '{new_path}' is ignored.")
            if success and old_path not in self.ignored_paths:
                 # Pass pid, path, success, timestamp, details
                 self.delete(pid, old_path, True, timestamp, {"renamed_to_ignored": new_path})
            return
        if old_path in self.ignored_paths:
             log.warning(f"Rename source path '{old_path}' is ignored.")
             if success: # Pass pid, path, success, timestamp, details
                  self.stat(pid, new_path, True, timestamp, {"renamed_from_ignored": old_path})
             return

        # --- Handle rename failure (early out) ---
        if not success:
             info = self._cache_info(old_path, timestamp)
             if not info: return
             details_for_finalize = details.copy()
             self._finalize_update(info, "RENAME", success, timestamp, details_for_finalize)
             if info.status != "deleted": info.status = "error"
             return

        # --- Handle rename success ---
        old_info = self.files.get(old_path)
        if not old_info:
            log.debug(f"Rename source path '{old_path}' not tracked. Treating as access to target.")
            # Pass pid, path, success, timestamp, details
            self.stat(pid, new_path, True, timestamp, {"renamed_from_unknown": old_path})
            return

        # Source *is* tracked
        log.info(f"Processing successful rename: '{old_path}' -> '{new_path}'")
        old_info.last_activity_ts = timestamp

        new_info = self._cache_info(new_path, timestamp)
        if not new_info:
             log.error(f"Could not get/create FileInfo for rename target '{new_path}'")
             # Pass pid, path, success, timestamp, details
             self.delete(pid, old_path, True, timestamp, {"error": "Rename target creation failed"})
             return

        # Transfer state from old to new
        new_info.status = old_info.status if old_info.status != "deleted" else "accessed"
        new_info.open_by_pids = old_info.open_by_pids
        new_info.bytes_read = old_info.bytes_read
        new_info.bytes_written = old_info.bytes_written
        # Finalize update for both
        details_for_old = {"renamed_to": new_path}
        details_for_new = {"renamed_from": old_path}
        self._finalize_update(old_info, "RENAME", success, timestamp, details_for_old)
        self._finalize_update(new_info, "RENAME", success, timestamp, details_for_new)

        # Update main FD map
        pids_to_update = list(self.pid_fd_map.keys())
        for update_pid in pids_to_update:
             fds_to_update = []
             for fd, path_in_map in self.pid_fd_map[update_pid].items():
                 if path_in_map == old_path:
                     fds_to_update.append(fd)
             if fds_to_update:
                 log.info(f"Rename: Updating FD map for PID {update_pid}, FDs {fds_to_update}: '{old_path}' -> '{new_path}'")
                 for fd in fds_to_update:
                     self.pid_fd_map[update_pid][fd] = new_path

        # Remove old path state from tracking
        log.debug(f"Removing old path state after successful rename: {old_path}")
        del self.files[old_path]


    # --- Public Query/Access Methods ---

    @waits
    def __iter__(self) -> Iterator[FileInfo]:
        """Iterates over tracked FileInfo objects (values of self.files)."""
        yield from self.files.values()

    @waits
    def __getitem__(self, path: str) -> FileInfo:
        """Gets FileInfo for a specific path using dictionary-style access."""
        return self.files[path] # Raises KeyError if not found

    @waits
    def __contains__(self, path: str) -> bool:
        """Checks if a path is currently being tracked (key in self.files)."""
        if not isinstance(path, str): return False
        return path in self.files

    @waits
    def __len__(self) -> int:
        """Returns the number of tracked files."""
        return len(self.files)

    @waits
    def get_path(self, pid: int, fd: int) -> Optional[str]:
        """Gets the path associated with a PID/FD combination from cache."""
        return self.pid_fd_map.get(pid, {}).get(fd)

    # --- Helper for common state updates ---
    # Note: This is called *within* the lock acquired by @changes handlers
    def _finalize_update(self, info: FileInfo, event_type: str, success: bool, timestamp: float, details: Dict):
        """Helper to apply common updates to FileInfo state."""
        info.last_event_type = event_type
        if event_type in ["OPEN", "STAT", "DELETE", "RENAME"]:
             info.last_error_enoent = (not success and details.get("error_name") == "ENOENT")
        else:
             info.last_error_enoent = False
        info.details.update(details)
        self._add_event_to_history(info, event_type, success, timestamp, info.details)

    # TODO: Add method to handle process exit (clear FDs for that PID)

