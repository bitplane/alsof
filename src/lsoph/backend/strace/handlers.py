# Filename: src/lsoph/backend/strace/handlers.py
"""
Syscall handlers and CWD update logic for the strace backend.
Works with bytes paths internally and interacts with the Monitor using bytes.
"""

import logging
import os
from collections.abc import Callable
from typing import Any

# Syscall object now has args as list[bytes]
from lsoph.backend.strace.parse import Syscall
from lsoph.monitor import Monitor

# Import helpers from the new module
# clean_path_arg now accepts bytes
from . import helpers

log = logging.getLogger(__name__)

# Type alias for handler functions (cwd_map now holds bytes)
SyscallHandler = Callable[[Syscall, Monitor, dict[int, bytes]], None]

# --- Syscall Handlers ---


def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles open, openat, creat syscalls. Works with bytes paths."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: bytes | None = None  # Path is bytes

    if event.syscall in ["open", "creat"]:
        # Get first arg as bytes, clean it (decodes octal escapes)
        path_arg_bytes = helpers.clean_path_arg(event.args[0] if event.args else None)
        # resolve_path accepts and returns bytes
        path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor)
    elif event.syscall == "openat":
        # dirfd arg is still string from original parse before args became bytes
        # We need to decode the first arg (dirfd) to pass to parse_dirfd
        dirfd_arg_str: str | None = None
        if event.args:
            try:
                dirfd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
            except Exception:
                log.warning(f"Could not decode dirfd argument bytes: {event.args[0]!r}")
        # Get second arg (path) as bytes, clean it
        path_arg_bytes = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        dirfd = helpers.parse_dirfd(dirfd_arg_str)  # parse_dirfd accepts str
        # resolve_path accepts bytes path_arg, int dirfd, returns bytes path
        path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg_str  # Keep decoded string for logging

    if path is not None:
        fd_val = helpers.parse_result_int(event.result_str) if success else -1
        fd = fd_val if fd_val is not None else -1
        monitor.open(pid, path, fd, success, timestamp, **details)


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles close syscall."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    # Decode FD arg bytes to string for parsing
    fd_arg_str: str | None = None
    if event.args:
        try:
            fd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
        except Exception:
            log.warning(f"Could not decode close FD argument bytes: {event.args[0]!r}")
    fd_arg = helpers.parse_result_int(fd_arg_str) if fd_arg_str else None

    if fd_arg is not None:
        monitor.close(pid, fd_arg, success, timestamp, **details)


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles read, write, pread64, pwrite64, readv, writev syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    # Decode FD arg bytes to string for parsing
    fd_arg_str: str | None = None
    if event.args:
        try:
            fd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
        except Exception:
            log.warning(
                f"Could not decode read/write FD argument bytes: {event.args[0]!r}"
            )
    fd_arg = helpers.parse_result_int(fd_arg_str) if fd_arg_str else None

    if fd_arg is None:
        return

    # Get path (bytes) from monitor state based on FD
    path: bytes | None = monitor.get_path(pid, fd_arg)
    if path is None:
        return

    byte_count_val = helpers.parse_result_int(event.result_str) if success else 0
    byte_count = byte_count_val if byte_count_val is not None else 0
    details["bytes"] = byte_count

    if event.syscall.startswith("read"):
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    elif event.syscall.startswith("write"):
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles access, stat, lstat, newfstatat syscalls. Works with bytes paths."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: bytes | None = None  # Path is bytes

    if event.syscall in ["access", "stat", "lstat"]:
        # Get first arg as bytes, clean it
        path_arg_bytes = helpers.clean_path_arg(event.args[0] if event.args else None)
        path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor)
    elif event.syscall == "newfstatat":
        # Decode dirfd arg bytes
        dirfd_arg_str: str | None = None
        if event.args:
            try:
                dirfd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
            except Exception:
                log.warning(
                    f"Could not decode newfstatat dirfd argument bytes: {event.args[0]!r}"
                )
        # Get path arg as bytes, clean it
        path_arg_bytes = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        dirfd = helpers.parse_dirfd(dirfd_arg_str)  # accepts str
        path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg_str  # Keep decoded string for logging

    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles unlink, unlinkat, rmdir syscalls. Works with bytes paths."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: bytes | None = None  # Path is bytes

    if event.syscall in ["unlink", "rmdir"]:
        # Get first arg as bytes, clean it
        path_arg_bytes = helpers.clean_path_arg(event.args[0] if event.args else None)
        path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor)
    elif event.syscall == "unlinkat":
        # Decode dirfd arg bytes
        dirfd_arg_str: str | None = None
        if event.args:
            try:
                dirfd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
            except Exception:
                log.warning(
                    f"Could not decode unlinkat dirfd argument bytes: {event.args[0]!r}"
                )
        # Get path arg as bytes, clean it
        path_arg_bytes = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        dirfd = helpers.parse_dirfd(dirfd_arg_str)  # accepts str
        path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg_str  # Keep decoded string for logging

    if path is not None:
        monitor.delete(pid, path, success, timestamp, **details)


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles rename, renameat, renameat2 syscalls. Works with bytes paths."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    old_path: bytes | None = None  # Path is bytes
    new_path: bytes | None = None  # Path is bytes

    if event.syscall == "rename":
        # Get args as bytes, clean them
        old_path_arg_bytes = helpers.clean_path_arg(
            event.args[0] if event.args else None
        )
        new_path_arg_bytes = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        old_path = helpers.resolve_path(pid, old_path_arg_bytes, cwd_map, monitor)
        new_path = helpers.resolve_path(pid, new_path_arg_bytes, cwd_map, monitor)
    elif event.syscall in ["renameat", "renameat2"]:
        # Decode dirfd args bytes
        old_dirfd_arg_str: str | None = None
        new_dirfd_arg_str: str | None = None
        if event.args:
            try:
                old_dirfd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
            except Exception:
                log.warning(
                    f"Could not decode renameat olddirfd argument bytes: {event.args[0]!r}"
                )
        if len(event.args) > 2:
            try:
                new_dirfd_arg_str = event.args[2].decode("utf-8", "surrogateescape")
            except Exception:
                log.warning(
                    f"Could not decode renameat newdirfd argument bytes: {event.args[2]!r}"
                )

        # Get path args as bytes, clean them
        old_path_arg_bytes = helpers.clean_path_arg(
            event.args[1] if len(event.args) > 1 else None
        )
        new_path_arg_bytes = helpers.clean_path_arg(
            event.args[3] if len(event.args) > 3 else None
        )

        old_dirfd = helpers.parse_dirfd(old_dirfd_arg_str)  # accepts str
        new_dirfd = helpers.parse_dirfd(new_dirfd_arg_str)  # accepts str

        old_path = helpers.resolve_path(
            pid, old_path_arg_bytes, cwd_map, monitor, dirfd=old_dirfd
        )
        new_path = helpers.resolve_path(
            pid, new_path_arg_bytes, cwd_map, monitor, dirfd=new_dirfd
        )

        details["old_dirfd"] = old_dirfd_arg_str  # Keep decoded string for logging
        details["new_dirfd"] = new_dirfd_arg_str  # Keep decoded string for logging

    if old_path and new_path:
        monitor.rename(pid, old_path, new_path, success, timestamp, **details)


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
def update_cwd(pid: int, cwd_map: dict[int, bytes], monitor: Monitor, event: Syscall):
    """
    Updates the CWD map (bytes) based on chdir or fchdir syscalls.
    Calls monitor.stat with bytes path.
    """
    success, timestamp = event.error_name is None, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    new_cwd: bytes | None = None  # CWD is bytes
    path_for_stat_call: bytes | None = None  # Path is bytes

    if event.syscall == "chdir":
        # Get first arg as bytes, clean it
        path_arg_bytes = helpers.clean_path_arg(event.args[0] if event.args else None)
        if path_arg_bytes:
            # resolve_path accepts and returns bytes
            resolved_path = helpers.resolve_path(pid, path_arg_bytes, cwd_map, monitor)
            if resolved_path:
                path_for_stat_call = resolved_path
                if success:
                    new_cwd = resolved_path
            else:
                path_for_stat_call = path_arg_bytes
        else:
            log.warning(f"chdir syscall for PID {pid} missing path argument: {event!r}")

    elif event.syscall == "fchdir":
        # Decode FD arg bytes
        fd_arg_str: str | None = None
        if event.args:
            try:
                fd_arg_str = event.args[0].decode("utf-8", "surrogateescape")
            except Exception:
                log.warning(
                    f"Could not decode fchdir FD argument bytes: {event.args[0]!r}"
                )
        fd_arg = helpers.parse_result_int(fd_arg_str) if fd_arg_str else None

        if fd_arg is not None:
            details["fd"] = fd_arg
            # monitor.get_path returns bytes
            target_path: bytes | None = monitor.get_path(pid, fd_arg)
            if target_path:
                path_for_stat_call = target_path
                if success:
                    new_cwd = target_path
            else:
                log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}.")
        else:
            log.warning(
                f"fchdir syscall for PID {pid} has invalid FD argument: {event.args}"
            )

    # Update CWD map (bytes) if successful
    if success and new_cwd:
        cwd_map[pid] = new_cwd
        log.info(
            f"PID {pid} changed CWD via {event.syscall} to: {os.fsdecode(new_cwd)!r}"
        )

    # Always call monitor.stat with the bytes path determined above
    details.pop("path", None)
    details.pop("target_path", None)
    if path_for_stat_call:
        monitor.stat(pid, path_for_stat_call, success, timestamp, **details)
    elif not success:
        log.warning(
            f"{event.syscall} failed for PID {pid}, but target path unknown: {event!r}"
        )
