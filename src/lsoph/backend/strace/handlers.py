# Filename: src/lsoph/backend/strace/handlers.py
"""Syscall handlers and CWD update logic for the strace backend."""

import logging
import os
from collections.abc import Callable
from typing import Any

from lsoph.backend.strace.parse import Syscall
from lsoph.monitor import Monitor

# Import helpers from the new module
from . import helpers

log = logging.getLogger(__name__)

# Type alias for handler functions
SyscallHandler = Callable[[Syscall, Monitor, dict[int, str]], None]

# --- Syscall Handlers ---


def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: dict[int, str]):
    """Handles open, openat, creat syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: str | None = None

    if event.syscall in ["open", "creat"]:
        path_arg = helpers.clean_path_arg(event.args[0] if event.args else None)
        path = helpers.resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "openat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        dirfd = helpers.parse_dirfd(dirfd_arg)
        path = helpers.resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Keep original for logging

    if path is not None:
        fd_val = helpers.parse_result_int(event.result_str) if success else -1
        fd = fd_val if fd_val is not None else -1  # Ensure fd is int
        monitor.open(pid, path, fd, success, timestamp, **details)
    else:
        log.warning(f"Could not determine path for {event.syscall} event: {event!r}")


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: dict[int, str]):
    """Handles close syscall."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    # Ensure arg is string before parsing
    fd_arg_str = str(event.args[0]) if event.args else None
    fd_arg = helpers.parse_result_int(fd_arg_str) if fd_arg_str else None

    if fd_arg is not None:
        monitor.close(pid, fd_arg, success, timestamp, **details)
    else:
        log.warning(f"Could not parse FD for close event: {event!r}")


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: dict[int, str]):
    """Handles read, write, pread64, pwrite64, readv, writev syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    # Ensure arg is string before parsing
    fd_arg_str = str(event.args[0]) if event.args else None
    fd_arg = helpers.parse_result_int(fd_arg_str) if fd_arg_str else None

    if fd_arg is None:
        log.warning(f"No valid FD found for {event.syscall} event: {event!r}")
        return

    # Get path from monitor state based on FD
    path = monitor.get_path(pid, fd_arg)
    # If path is None here, it means the FD wasn't tracked (e.g., socket, pipe)
    # Proceed only if path is known.
    if path is None:
        log.debug(
            f"Path for {event.syscall} on PID {pid} FD {fd_arg} is unknown, skipping monitor update."
        )
        return

    byte_count_val = helpers.parse_result_int(event.result_str) if success else 0
    byte_count = byte_count_val if byte_count_val is not None else 0  # Ensure int
    details["bytes"] = byte_count

    if event.syscall.startswith("read"):
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    elif event.syscall.startswith("write"):
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: dict[int, str]):
    """Handles access, stat, lstat, newfstatat syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: str | None = None

    if event.syscall in ["access", "stat", "lstat"]:
        path_arg = helpers.clean_path_arg(event.args[0] if event.args else None)
        path = helpers.resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "newfstatat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        dirfd = helpers.parse_dirfd(dirfd_arg)
        path = helpers.resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Keep original for logging

    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)
    else:
        log.warning(f"Could not determine path for {event.syscall} event: {event!r}")


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: dict[int, str]):
    """Handles unlink, unlinkat, rmdir syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: str | None = None

    if event.syscall in ["unlink", "rmdir"]:
        path_arg = helpers.clean_path_arg(event.args[0] if event.args else None)
        path = helpers.resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "unlinkat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        dirfd = helpers.parse_dirfd(dirfd_arg)
        path = helpers.resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Keep original for logging

    if path is not None:
        monitor.delete(pid, path, success, timestamp, **details)
    else:
        log.warning(f"Could not determine path for {event.syscall} event: {event!r}")


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: dict[int, str]):
    """Handles rename, renameat, renameat2 syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    old_path: str | None = None
    new_path: str | None = None

    if event.syscall == "rename":
        old_path_arg = helpers.clean_path_arg(event.args[0] if event.args else None)
        new_path_arg = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        old_path = helpers.resolve_path(pid, old_path_arg, cwd_map, monitor)
        new_path = helpers.resolve_path(pid, new_path_arg, cwd_map, monitor)
    elif event.syscall in ["renameat", "renameat2"]:
        # Indices: 0=olddirfd, 1=oldpath, 2=newdirfd, 3=newpath [, 4=flags for renameat2]
        old_dirfd_arg = event.args[0] if event.args else None
        old_path_arg = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        new_dirfd_arg = event.args[2] if len(event.args) > 2 else None
        new_path_arg = helpers.clean_path_arg(
            event.args[3] if len(event.args) > 3 else None
        )

        old_dirfd = helpers.parse_dirfd(old_dirfd_arg)
        new_dirfd = helpers.parse_dirfd(new_dirfd_arg)

        old_path = helpers.resolve_path(
            pid, old_path_arg, cwd_map, monitor, dirfd=old_dirfd
        )
        new_path = helpers.resolve_path(
            pid, new_path_arg, cwd_map, monitor, dirfd=new_dirfd
        )

        details["old_dirfd"] = old_dirfd_arg  # Keep original for logging
        details["new_dirfd"] = new_dirfd_arg  # Keep original for logging

    if old_path and new_path:
        monitor.rename(pid, old_path, new_path, success, timestamp, **details)
    else:
        log.warning(
            f"Could not determine old or new path for {event.syscall} event: {event!r}"
        )


# --- Syscall Dispatcher ---
SYSCALL_HANDLERS: dict[str, SyscallHandler] = {
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
    # Note: chdir/fchdir are handled separately in _process_single_event
    # Note: PROCESS_SYSCALLS (fork etc.) and EXIT_SYSCALLS handled in _process_single_event
}


# --- CWD Update Logic ---
def update_cwd(pid: int, cwd_map: dict[int, str], monitor: Monitor, event: Syscall):
    """Updates the CWD map based on chdir or fchdir syscalls."""
    success, timestamp = event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    new_cwd: str | None = None

    if event.syscall == "chdir":
        path_arg = helpers.clean_path_arg(event.args[0] if event.args else None)
        if path_arg:
            resolved_path = helpers.resolve_path(pid, path_arg, cwd_map, monitor)
            if resolved_path:
                if success:
                    new_cwd = resolved_path
                details["path"] = resolved_path  # Record attempted path even on failure
            else:
                log.warning(f"Could not resolve chdir path '{path_arg}' for PID {pid}")
                details["path"] = path_arg  # Record original arg if resolve failed
        else:
            log.warning(f"chdir syscall for PID {pid} missing path argument: {event!r}")

    elif event.syscall == "fchdir":
        # Ensure arg is string before parsing
        fd_arg_str = str(event.args[0]) if event.args else None
        fd_arg = helpers.parse_result_int(fd_arg_str) if fd_arg_str else None
        if fd_arg is not None:
            details["fd"] = fd_arg
            target_path = monitor.get_path(pid, fd_arg)
            if target_path:
                if success:
                    new_cwd = target_path
                details["target_path"] = target_path  # Record target path
            else:
                log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}.")
        else:
            log.warning(
                f"fchdir syscall for PID {pid} has invalid FD argument: {event.args}"
            )

    # Update CWD map and call monitor.stat
    if success and new_cwd:
        cwd_map[pid] = new_cwd
        monitor.stat(pid, new_cwd, success, timestamp, **details)
        log.info(f"PID {pid} changed CWD via {event.syscall} to: {new_cwd}")
    elif not success and ("path" in details or "target_path" in details):
        # If failed, still call stat on the *attempted* target path if known
        path_for_stat = details.get("path") or details.get("target_path")
        if path_for_stat:
            monitor.stat(pid, path_for_stat, success, timestamp, **details)
    elif not success:
        # Failed, but target path wasn't determined
        log.warning(
            f"{event.syscall} failed for PID {pid}, but target path unknown: {event!r}"
        )
