# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend implementation using refactored components."""

import argparse
import asyncio
import logging
import os
import shlex
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import psutil

from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

# Import base class (assuming it's now one level up)
from ..base import Backend

# Import from refactored strace modules
from .parse import (  # Import constants from parse
    EXIT_SYSCALLS,
    PROCESS_SYSCALLS,
    Syscall,
    parse_strace_stream,
)

# Import the terminate helper
from .terminate import terminate_strace_process

# Import specific helper functions if needed, or keep them internal to backend.py
# from .helpers import _clean_path_arg, _parse_dirfd, _resolve_path, ...


log = logging.getLogger(__name__)  # Use module-specific logger

# Define default syscalls here or import from a shared constants module if preferred
# For now, defining locally based on previous usage
FILE_STRUCT_SYSCALLS = [
    "open",
    "openat",
    "creat",
    "access",
    "stat",
    "lstat",
    "newfstatat",
    "close",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "chdir",
    "fchdir",
]
IO_SYSCALLS = ["read", "pread64", "readv", "write", "pwrite64", "writev"]
DEFAULT_SYSCALLS = sorted(
    list(
        set(
            PROCESS_SYSCALLS
            + FILE_STRUCT_SYSCALLS
            + IO_SYSCALLS
            + EXIT_SYSCALLS
            + ["chdir", "fchdir"]  # Explicitly include CWD syscalls
        )
    )
)


# Type alias for handler functions
SyscallHandler = Callable[[Syscall, Monitor, Dict[int, str]], None]


# --- Internal Helper Functions (Consider moving to helpers.py) ---
# These are kept here for now as they are tightly coupled with the handlers below.
def _parse_result_int(result_str: str) -> Optional[int]:
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)
    except ValueError:
        log.warning(f"Could not parse result: '{result_str}'")
        return None


def _clean_path_arg(path_arg: Any) -> Optional[str]:
    if not isinstance(path_arg, str) or not path_arg:
        return None
    path = path_arg
    if path.startswith('"') and path.endswith('"') and "\\x" in path:
        path = path[1:-1]
        try:
            decoded_bytes = (
                path.encode("latin-1", "backslashreplace")
                .decode("unicode_escape")
                .encode("latin-1", "surrogateescape")
            )
            try:
                path = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                path = decoded_bytes.decode("latin-1")
        except Exception as e:
            log.warning(f"Failed hex decode '{path_arg}': {e}")
    elif path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
        try:
            path = path.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception as e:
            log.warning(f"Failed escape decode '{path_arg}': {e}")
    return path


def _parse_dirfd(dirfd_arg: Optional[str]) -> Optional[Union[int, str]]:
    if dirfd_arg is None:
        return None
    if isinstance(dirfd_arg, str) and dirfd_arg.strip().upper() == "AT_FDCWD":
        return "AT_FDCWD"
    try:
        return int(str(dirfd_arg), 0)
    except (ValueError, TypeError):
        log.warning(f"Could not parse dirfd: '{dirfd_arg}'")
        return None


def _resolve_path(
    pid: int,
    path: Optional[str],
    cwd_map: Dict[int, str],
    monitor: Monitor,
    dirfd: Optional[Union[int, str]] = None,
) -> Optional[str]:
    if path is None:
        return None
    if (path.startswith("<") and path.endswith(">")) or path.startswith("@"):
        return path
    base_dir: Optional[str] = None
    if dirfd is not None:
        if dirfd == "AT_FDCWD":
            base_dir = cwd_map.get(pid)
        elif isinstance(dirfd, int) and dirfd >= 0:
            base_dir = monitor.get_path(pid, dirfd)
            if not base_dir:
                log.warning(f"dirfd={dirfd} PID {pid} not found")
                return path
        else:
            log.warning(f"Unhandled dirfd: {dirfd!r}")
            return path
    if os.path.isabs(path):
        return os.path.normpath(path)
    else:
        if base_dir is None:
            base_dir = cwd_map.get(pid)
        if base_dir:
            try:
                return os.path.normpath(os.path.join(base_dir, path))
            except Exception as e:
                log.warning(f"Error joining '{path}' with '{base_dir}': {e}")
                return path
        else:
            log.warning(f"No base dir for PID {pid} relative path '{path}'")
            return path


# --- End Internal Helpers ---


# --- Syscall Handlers (remain synchronous) ---
# These handlers now use the helper functions defined above.
def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    if event.syscall in ["open", "creat"]:
        path = _resolve_path(
            pid,
            _clean_path_arg(event.args[0] if event.args else None),
            cwd_map,
            monitor,
        )
    elif event.syscall == "openat":
        dirfd_arg = event.args[0] if event.args else None
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(
            pid,
            _clean_path_arg(event.args[1] if len(event.args) > 1 else None),
            cwd_map,
            monitor,
            dirfd=dirfd,
        )
        details["dirfd"] = dirfd_arg
    if path is not None:
        fd = _parse_result_int(event.result_str) if success else -1
        fd = fd if fd is not None else -1
        # Ensure fd is not passed in details dict
        monitor.open(
            pid, path, fd, success, timestamp, **details
        )  # Pass fd positionally


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
    if fd_arg is not None:
        # Ensure fd is not passed in details dict
        monitor.close(
            pid, fd_arg, success, timestamp, **details
        )  # Pass fd positionally


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
    if fd_arg is None:
        log.warning(f"No FD for {event.syscall}: {event!r}")
        return
    # Ensure fd is not passed in details dict
    path = monitor.get_path(pid, fd_arg)
    byte_count = _parse_result_int(event.result_str) if success else 0
    byte_count = byte_count if byte_count is not None else 0
    details["bytes"] = byte_count
    if event.syscall.startswith("read"):
        monitor.read(
            pid, fd_arg, path, success, timestamp, **details
        )  # Pass fd positionally
    elif event.syscall.startswith("write"):
        monitor.write(
            pid, fd_arg, path, success, timestamp, **details
        )  # Pass fd positionally


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    if event.syscall in ["access", "stat", "lstat"]:
        path = _resolve_path(
            pid,
            _clean_path_arg(event.args[0] if event.args else None),
            cwd_map,
            monitor,
        )
    elif event.syscall == "newfstatat":
        dirfd_arg = event.args[0] if event.args else None
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(
            pid,
            _clean_path_arg(event.args[1] if len(event.args) > 1 else None),
            cwd_map,
            monitor,
            dirfd=dirfd,
        )
        details["dirfd"] = dirfd_arg
    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    if event.syscall in ["unlink", "rmdir"]:
        path = _resolve_path(
            pid,
            _clean_path_arg(event.args[0] if event.args else None),
            cwd_map,
            monitor,
        )
    elif event.syscall == "unlinkat":
        dirfd_arg = event.args[0] if event.args else None
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(
            pid,
            _clean_path_arg(event.args[1] if len(event.args) > 1 else None),
            cwd_map,
            monitor,
            dirfd=dirfd,
        )
        details["dirfd"] = dirfd_arg
    if path is not None:
        monitor.delete(pid, path, success, timestamp, **details)


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    if event.syscall == "rename":
        old_path = _resolve_path(
            pid,
            _clean_path_arg(event.args[0] if event.args else None),
            cwd_map,
            monitor,
        )
        new_path = _resolve_path(
            pid,
            _clean_path_arg(event.args[1] if len(event.args) > 1 else None),
            cwd_map,
            monitor,
        )
    elif event.syscall in ["renameat", "renameat2"]:
        old_dirfd_arg = event.args[0] if event.args else None
        old_dirfd = _parse_dirfd(old_dirfd_arg)
        old_path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        new_dirfd_arg = event.args[2] if len(event.args) > 2 else None
        new_dirfd = _parse_dirfd(new_dirfd_arg)
        new_path_arg = _clean_path_arg(event.args[3] if len(event.args) > 3 else None)
        old_path = _resolve_path(pid, old_path_arg, cwd_map, monitor, dirfd=old_dirfd)
        new_path = _resolve_path(pid, new_path_arg, cwd_map, monitor, dirfd=new_dirfd)
        details["old_dirfd"] = old_dirfd_arg
        details["new_dirfd"] = new_dirfd_arg
    if old_path and new_path:
        monitor.rename(pid, old_path, new_path, success, timestamp, **details)


# --- End Syscall Handlers ---


# --- Syscall Dispatcher ---
SYSCALL_HANDLERS: Dict[str, SyscallHandler] = {
    "open": _handle_open_creat,
    "openat": _handle_open_creat,
    "creat": _handle_open_creat,
    "close": _handle_close,
    "read": _handle_read_write,
    "pread64": _handle_read_write,
    "readv": _handle_read_write,
    "write": _handle_read_write,
    "pwrite64": _handle_read_write,
    "writev": _handle_read_write,
    "access": _handle_stat,
    "stat": _handle_stat,
    "lstat": _handle_stat,
    "newfstatat": _handle_stat,
    "unlink": _handle_delete,
    "unlinkat": _handle_delete,
    "rmdir": _handle_delete,
    "rename": _handle_rename,
    "renameat": _handle_rename,
    "renameat2": _handle_rename,
}
# --- End Syscall Dispatcher ---


# --- CWD Update Logic ---
def _update_cwd(pid: int, cwd_map: Dict[int, str], monitor: Monitor, event: Syscall):
    """Updates the CWD map based on chdir or fchdir syscalls."""
    success, timestamp = event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    if not success:  # Log failed attempt
        path_arg = (
            _clean_path_arg(event.args[0] if event.args else None)
            if event.syscall == "chdir"
            else None
        )
        fd_arg = (
            _parse_result_int(str(event.args[0]))
            if event.syscall == "fchdir" and event.args
            else None
        )
        path = (
            _resolve_path(pid, path_arg, cwd_map, monitor)
            if path_arg
            else (monitor.get_path(pid, fd_arg) if fd_arg is not None else None)
        )
        if path:
            monitor.stat(pid, path, success, timestamp, **details)
        return
    new_cwd: Optional[str] = None  # Determine new CWD
    if event.syscall == "chdir":
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        resolved_path = _resolve_path(pid, path_arg, cwd_map, monitor)
        if resolved_path:
            new_cwd = resolved_path
            details["path"] = resolved_path
        else:
            log.warning(f"Could not resolve chdir path '{path_arg}' PID {pid}")
    elif event.syscall == "fchdir":
        fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
        if fd_arg is not None:
            target_path = monitor.get_path(pid, fd_arg)
            if target_path:
                new_cwd = target_path
                details["fd"] = fd_arg  # Keep fd in details for stat
            else:
                log.warning(f"fchdir(fd={fd_arg}) target path unknown PID {pid}.")
        else:
            log.warning(f"fchdir PID {pid} invalid fd: {event.args}")
    if new_cwd:  # Update map and log successful stat
        cwd_map[pid] = new_cwd
        monitor.stat(pid, new_cwd, success, timestamp, **details)
        log.info(f"PID {pid} changed CWD via {event.syscall} to: {new_cwd}")


# --- End CWD Update Logic ---


# --- Backend Class ---
class StraceBackend(Backend):
    """Async backend implementation using strace (refactored)."""

    def __init__(self, monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS):
        super().__init__(monitor)
        # Ensure essential syscalls are always included
        self.syscalls = sorted(
            list(
                set(syscalls)
                | set(PROCESS_SYSCALLS)
                | set(EXIT_SYSCALLS)
                | {"chdir", "fchdir"}
            )
        )
        # Add attribute to store the strace process handle
        self._strace_process: asyncio.subprocess.Process | None = None

    async def attach(self, pids: list[int]):
        """Implementation of the attach method using refactored components."""
        if not pids:
            log.warning("StraceBackend.attach called with no PIDs.")
            return
        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        pid_cwd_map: Dict[int, str] = {p: cwd for p in pids if (cwd := pid_get_cwd(p))}
        log.info(f"Initial CWDs: {pid_cwd_map}")

        try:
            # Use keyword arguments for clarity and correctness
            event_stream = parse_strace_stream(
                backend=self,
                monitor=self.monitor,
                should_stop=self._should_stop,
                target_command=None,  # Explicitly None for attach mode
                attach_ids=pids,
                syscalls=self.syscalls,
            )
            log.info("Starting event processing loop in StraceBackend.attach...")
            processed_count = 0
            async for event in event_stream:
                if self.should_stop:
                    log.info("Stop signal detected.")
                    break
                processed_count += 1
                pid = event.pid
                syscall_name = event.syscall
                if pid not in pid_cwd_map:  # Ensure CWD known
                    cwd = pid_get_cwd(pid)
                    if cwd:
                        pid_cwd_map[pid] = cwd
                        log.info(f"Fetched CWD for new PID {pid}: {cwd}")
                    else:
                        log.warning(f"Could not determine CWD for PID {pid}.")
                log.debug(f"Processing event: {event!r}")
                # Handle specific syscalls
                if syscall_name in ["chdir", "fchdir"]:
                    _update_cwd(pid, pid_cwd_map, self.monitor, event)
                    continue
                if syscall_name in EXIT_SYSCALLS:
                    self.monitor.process_exit(pid, event.timestamp)
                    if pid in pid_cwd_map:
                        del pid_cwd_map[pid]
                        log.debug(f"Removed PID {pid} CWD map on exit.")
                    continue
                # Dispatch to generic handlers
                handler = SYSCALL_HANDLERS.get(syscall_name)
                if handler:
                    try:
                        handler(event, self.monitor, pid_cwd_map)
                    except Exception as e:
                        log.exception(f"Handler error {syscall_name}: {e}")
            log.info(
                f"Finished event loop in attach. Processed {processed_count} events."
            )
        except asyncio.CancelledError:
            log.info("Strace attach task cancelled.")
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            log.error(f"Strace attach error: {e}")
        except Exception as e:
            log.exception(f"Unexpected error in strace attach: {e}")
        finally:
            log.info("Strace attach finished.")

    async def run_command(self, command: list[str]):
        """Implementation of the run_command method using refactored components."""
        if not command:
            log.error("StraceBackend.run_command called empty.")
            return
        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        pid_cwd_map: Dict[int, str] = {}  # CWD map populated dynamically

        try:
            # Use keyword arguments for clarity and correctness
            event_stream = parse_strace_stream(
                backend=self,
                monitor=self.monitor,
                should_stop=self._should_stop,
                target_command=command,
                attach_ids=None,  # Explicitly None for run mode
                syscalls=self.syscalls,
            )
            log.info("Starting event processing loop in StraceBackend.run_command...")
            processed_count = 0
            async for event in event_stream:
                if self.should_stop:
                    log.info("Stop signal detected.")
                    break
                processed_count += 1
                pid = event.pid
                syscall_name = event.syscall
                if pid not in pid_cwd_map:  # Ensure CWD known
                    cwd = pid_get_cwd(pid)
                    if cwd:
                        pid_cwd_map[pid] = cwd
                        log.info(f"Fetched CWD for new PID {pid}: {cwd}")
                    else:
                        log.warning(f"Could not determine CWD for PID {pid}.")
                log.debug(f"Processing event: {event!r}")
                # Handle specific syscalls
                if syscall_name in ["chdir", "fchdir"]:
                    _update_cwd(pid, pid_cwd_map, self.monitor, event)
                    continue
                if syscall_name in EXIT_SYSCALLS:
                    self.monitor.process_exit(pid, event.timestamp)
                    if pid in pid_cwd_map:
                        del pid_cwd_map[pid]
                        log.debug(f"Removed PID {pid} CWD map on exit.")
                    continue
                # Dispatch to generic handlers
                handler = SYSCALL_HANDLERS.get(syscall_name)
                if handler:
                    try:
                        handler(event, self.monitor, pid_cwd_map)
                    except Exception as e:
                        log.exception(f"Handler error {syscall_name}: {e}")
            log.info(
                f"Finished event loop in run_command. Processed {processed_count} events."
            )
        except asyncio.CancelledError:
            log.info("Strace run task cancelled.")
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            log.error(f"Strace run error: {e}")
        except Exception as e:
            log.exception(f"Unexpected error in strace run: {e}")
        finally:
            log.info("Strace run finished.")

    # Override the stop method from the base class
    async def stop(self):
        """Signals the backend's running task to stop and terminates the managed strace process."""
        if not self._should_stop.is_set():
            log.info(f"Signalling backend {self.__class__.__name__} to stop.")
            self._should_stop.set()  # Signal the event stream loop to stop

            # Terminate the specific strace process using its stored handle
            process_to_term = self._strace_process
            pid_to_term = process_to_term.pid if process_to_term else -1
            log.info(
                f"Attempting termination of stored strace process (PID: {pid_to_term})..."
            )
            await terminate_strace_process(process_to_term, pid_to_term)
            # No need to call self._terminate_process() from base class
        else:
            log.debug(f"Backend {self.__class__.__name__} stop already signalled.")


# --- End Backend Class ---
