# Filename: src/lsoph/backend/strace/handlers.py
"""
Syscall handlers and CWD update logic for the strace backend.
Receives Syscall object with parsed args (bytes/str/int) based on parser_defs.
Path arguments are expected to be bytes.
Ensures flags are stored as strings in details.
"""

import logging
import os
from collections.abc import Callable
from typing import Any, List, Optional, Union

# ----------------------
from lsoph.monitor import Monitor

# Import helpers from the module
# resolve_path now accepts Optional[bytes] path_arg and bytes cwd_map
from . import helpers

# Syscall object now has args as list[Any] (bytes/str/int)
from .syscall import Syscall

log = logging.getLogger(__name__)

# Type alias for handler functions (cwd_map still holds bytes)
SyscallHandler = Callable[[Syscall, Monitor, dict[int, bytes]], None]


# --- Helper to get specific argument type ---
def _get_arg(
    args: List[Any], index: int, expected_type: type | tuple[type, ...]
) -> Any | None:
    """Gets argument at index, checking its type."""
    if index < len(args):
        arg_val = args[index]
        if isinstance(arg_val, expected_type):
            return arg_val
        else:
            expected_names = (
                expected_type.__name__
                if isinstance(expected_type, type)
                else tuple(t.__name__ for t in expected_type)
            )
            log.warning(
                f"Expected {expected_names} argument at index {index}, but got {type(arg_val)}: {arg_val!r}"
            )
            return None
    log.debug(f"Argument index {index} out of bounds for args: {args}")
    return None


# --- Syscall Handlers ---


def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles open, openat, creat syscalls."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: bytes | None = None
    dirfd: Optional[int] = None
    dirfd_arg: Any = None
    path_arg_parsed: Optional[bytes] = None  # Path must be bytes

    if event.syscall == "openat":
        dirfd_arg = _get_arg(event.args, 0, (int, str))  # dirfd: int or str
        path_arg_parsed = _get_arg(event.args, 1, bytes)  # path: bytes
        dirfd = helpers.parse_dirfd(dirfd_arg)
        details["dirfd"] = dirfd_arg
    elif event.syscall in ["open", "creat"]:
        path_arg_parsed = _get_arg(event.args, 0, bytes)  # path: bytes

    log.debug(
        f"[{event.syscall}] PID {pid}: Pre-resolve path arg type: {type(path_arg_parsed)}, value: {path_arg_parsed!r}"
    )
    path = helpers.resolve_path(pid, path_arg_parsed, cwd_map, monitor, dirfd=dirfd)
    if path is not None and not isinstance(path, bytes):
        log.error(
            f"[{event.syscall}] PID {pid}: resolve_path returned non-bytes/None type {type(path)} for value {path!r}. Args: {event.args}"
        )
        return
    log.debug(
        f"[{event.syscall}] PID {pid}: Post-resolve path type: {type(path)}, value: {path!r}"
    )

    if path is not None:
        flags_arg = _get_arg(
            event.args, 2 if event.syscall == "openat" else 1, str
        )  # flags: str
        if flags_arg:
            details["flags"] = flags_arg
        mode_arg = _get_arg(
            event.args, 3 if event.syscall == "openat" else 2, int
        )  # mode: int
        if mode_arg is not None:
            details["mode"] = mode_arg

        fd = event.result_int if success and isinstance(event.result_int, int) else -1
        monitor.open(pid, path, fd, success, timestamp, **details)
    else:
        log.debug(
            f"[{event.syscall}] PID {pid}: Path resolution failed or path argument was invalid/None. Args: {event.args}"
        )


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles close syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    fd_arg = _get_arg(event.args, 0, int)  # fd: int

    if fd_arg is not None:
        monitor.close(pid, fd_arg, success, timestamp, **details)
    else:
        log.warning(f"[close] PID {pid}: Could not parse FD from args: {event.args}")


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles read, write, pread64, pwrite64, readv, writev syscalls."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    fd_arg = _get_arg(event.args, 0, int)  # fd: int

    if fd_arg is None:
        log.warning(
            f"[{event.syscall}] PID {pid}: Could not parse FD from args: {event.args}"
        )
        return

    path: bytes | None = monitor.get_path(pid, fd_arg)  # path: bytes
    if path is None:
        log.debug(f"[{event.syscall}] PID {pid}: Path for FD {fd_arg} is unknown.")
        return

    buffer_arg = _get_arg(event.args, 1, bytes)  # buffer: bytes
    count_arg = _get_arg(event.args, 2, int)  # count: int
    offset_arg = (
        _get_arg(event.args, 3, int) if "p" in event.syscall else None
    )  # offset: int

    byte_count = (
        event.result_int if success and isinstance(event.result_int, int) else 0
    )
    details["bytes"] = byte_count
    if count_arg is not None:
        details["requested_bytes"] = count_arg
    if offset_arg is not None:
        details["offset"] = offset_arg

    if event.syscall.startswith("read"):
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    elif event.syscall.startswith("write"):
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles access, stat, lstat, newfstatat, fstat syscalls."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: bytes | None = None
    dirfd: Optional[int] = None
    dirfd_arg: Any = None
    path_arg_parsed: Optional[bytes] = None  # Path must be bytes
    struct_arg: Optional[bytes] = None

    if event.syscall in ["access", "stat", "lstat"]:
        path_arg_parsed = _get_arg(event.args, 0, bytes)  # path: bytes
        struct_idx = 1
        if event.syscall == "access":
            mode_arg = _get_arg(event.args, 1, str)  # mode: str
            if mode_arg:
                details["mode"] = mode_arg
            struct_idx = -1
    elif event.syscall == "newfstatat":
        dirfd_arg = _get_arg(event.args, 0, (int, str))  # dirfd: int or str
        path_arg_parsed = _get_arg(event.args, 1, bytes)  # path: bytes
        struct_idx = 2
        flags_arg = _get_arg(event.args, 3, (int, str))  # flags: int or str
        if flags_arg is not None:
            details["flags"] = str(flags_arg)  # Store as str
        dirfd = helpers.parse_dirfd(dirfd_arg)
        details["dirfd"] = dirfd_arg
    elif event.syscall == "fstat":
        fd_arg = _get_arg(event.args, 0, int)  # fd: int
        struct_idx = 1
        if fd_arg is not None:
            path = monitor.get_path(pid, fd_arg)  # path: bytes
            details["fd"] = fd_arg
        else:
            log.warning(
                f"[fstat] PID {pid}: Could not parse FD from args: {event.args}"
            )
            path = None

    # Get struct buffer if applicable
    if struct_idx != -1:
        struct_arg = _get_arg(event.args, struct_idx, bytes)  # struct: bytes
        if struct_arg is not None:
            details["struct_buffer"] = struct_arg[:64]
        else:
            actual_type = (
                type(event.args[struct_idx]).__name__
                if struct_idx < len(event.args)
                else "OutOfBounds"
            )
            log.warning(
                f"Struct argument for {event.syscall} at index {struct_idx} was not bytes: {actual_type}"
            )

    # Resolve path if not fstat
    if event.syscall != "fstat":
        log.debug(
            f"[{event.syscall}] PID {pid}: Pre-resolve path arg type: {type(path_arg_parsed)}, value: {path_arg_parsed!r}"
        )
        path = helpers.resolve_path(pid, path_arg_parsed, cwd_map, monitor, dirfd=dirfd)
        if path is not None and not isinstance(path, bytes):
            log.error(
                f"[{event.syscall}] PID {pid}: resolve_path returned non-bytes/None type {type(path)} for value {path!r}. Args: {event.args}"
            )
            return
        log.debug(
            f"[{event.syscall}] PID {pid}: Post-resolve path type: {type(path)}, value: {path!r}"
        )

    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)
    else:
        log.debug(
            f"[{event.syscall}] PID {pid}: Path resolution/retrieval failed. Args: {event.args}"
        )


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles unlink, unlinkat, rmdir syscalls."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    path: bytes | None = None
    dirfd: Optional[int] = None
    dirfd_arg: Any = None
    path_arg_parsed: Optional[bytes] = None  # Path must be bytes

    if event.syscall in ["unlink", "rmdir"]:
        path_arg_parsed = _get_arg(event.args, 0, bytes)
    elif event.syscall == "unlinkat":
        dirfd_arg = _get_arg(event.args, 0, (int, str))  # dirfd: int or str
        path_arg_parsed = _get_arg(event.args, 1, bytes)  # path: bytes
        flags_arg = _get_arg(event.args, 2, (int, str))  # flags: int or str
        if flags_arg is not None:
            details["flags"] = str(flags_arg)  # Store as str
        dirfd = helpers.parse_dirfd(dirfd_arg)
        details["dirfd"] = dirfd_arg

    log.debug(
        f"[{event.syscall}] PID {pid}: Pre-resolve path arg type: {type(path_arg_parsed)}, value: {path_arg_parsed!r}"
    )
    path = helpers.resolve_path(pid, path_arg_parsed, cwd_map, monitor, dirfd=dirfd)
    if path is not None and not isinstance(path, bytes):
        log.error(
            f"[{event.syscall}] PID {pid}: resolve_path returned non-bytes/None type {type(path)} for value {path!r}. Args: {event.args}"
        )
        return
    log.debug(
        f"[{event.syscall}] PID {pid}: Post-resolve path type: {type(path)}, value: {path!r}"
    )

    if path is not None:
        monitor.delete(pid, path, success, timestamp, **details)
    else:
        log.debug(
            f"[{event.syscall}] PID {pid}: Path resolution failed or path argument was invalid/None. Args: {event.args}"
        )


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles rename, renameat, renameat2 syscalls."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    old_path: bytes | None = None
    new_path: bytes | None = None
    old_dirfd: Optional[int] = None
    new_dirfd: Optional[int] = None
    old_dirfd_arg: Any = None
    new_dirfd_arg: Any = None
    old_path_arg_parsed: Optional[bytes] = None  # Path must be bytes
    new_path_arg_parsed: Optional[bytes] = None  # Path must be bytes

    if event.syscall == "rename":
        old_path_arg_parsed = _get_arg(event.args, 0, bytes)
        new_path_arg_parsed = _get_arg(event.args, 1, bytes)
    elif event.syscall in ["renameat", "renameat2"]:
        old_dirfd_arg = _get_arg(event.args, 0, (int, str))  # dirfd: int or str
        old_path_arg_parsed = _get_arg(event.args, 1, bytes)  # path: bytes
        new_dirfd_arg = _get_arg(event.args, 2, (int, str))  # dirfd: int or str
        new_path_arg_parsed = _get_arg(event.args, 3, bytes)  # path: bytes

        old_dirfd = helpers.parse_dirfd(old_dirfd_arg)
        new_dirfd = helpers.parse_dirfd(new_dirfd_arg)
        details["old_dirfd"] = old_dirfd_arg
        details["new_dirfd"] = new_dirfd_arg
        if event.syscall == "renameat2":
            flags_arg = _get_arg(event.args, 4, (int, str))  # flags: int or str
            if flags_arg is not None:
                details["flags"] = str(flags_arg)  # Store as str

    log.debug(
        f"[{event.syscall}] PID {pid}: Pre-resolve OLD path arg type: {type(old_path_arg_parsed)}, value: {old_path_arg_parsed!r}"
    )
    old_path = helpers.resolve_path(
        pid, old_path_arg_parsed, cwd_map, monitor, dirfd=old_dirfd
    )
    if old_path is not None and not isinstance(old_path, bytes):
        log.error(
            f"[{event.syscall}] PID {pid}: resolve_path (OLD) returned non-bytes/None type {type(old_path)} for value {old_path!r}. Args: {event.args}"
        )
        old_path = None
    log.debug(
        f"[{event.syscall}] PID {pid}: Post-resolve OLD path type: {type(old_path)}, value: {old_path!r}"
    )

    log.debug(
        f"[{event.syscall}] PID {pid}: Pre-resolve NEW path arg type: {type(new_path_arg_parsed)}, value: {new_path_arg_parsed!r}"
    )
    new_path = helpers.resolve_path(
        pid, new_path_arg_parsed, cwd_map, monitor, dirfd=new_dirfd
    )
    if new_path is not None and not isinstance(new_path, bytes):
        log.error(
            f"[{event.syscall}] PID {pid}: resolve_path (NEW) returned non-bytes/None type {type(new_path)} for value {new_path!r}. Args: {event.args}"
        )
        new_path = None
    log.debug(
        f"[{event.syscall}] PID {pid}: Post-resolve NEW path type: {type(new_path)}, value: {new_path!r}"
    )

    if old_path and new_path:
        monitor.rename(pid, old_path, new_path, success, timestamp, **details)
    else:
        log.debug(
            f"[{event.syscall}] PID {pid}: Path resolution failed or path arguments were invalid/None. Args: {event.args}"
        )


# --- CWD Update Logic ---
def update_cwd(pid: int, cwd_map: dict[int, bytes], monitor: Monitor, event: Syscall):
    """
    Updates the CWD map (bytes) based on chdir or fchdir syscalls.
    """
    success, timestamp = event.success, event.timestamp
    details: dict[str, Any] = {"syscall": event.syscall}
    new_cwd: bytes | None = None
    path_for_stat_call: bytes | None = None

    if event.syscall == "chdir":
        path_arg_parsed = _get_arg(event.args, 0, bytes)  # path: bytes
        log.debug(
            f"[{event.syscall}] PID {pid}: Pre-resolve path arg type: {type(path_arg_parsed)}, value: {path_arg_parsed!r}"
        )
        resolved_path = helpers.resolve_path(pid, path_arg_parsed, cwd_map, monitor)
        if resolved_path is not None and not isinstance(resolved_path, bytes):
            log.error(
                f"[{event.syscall}] PID {pid}: resolve_path returned non-bytes/None type {type(resolved_path)} for value {resolved_path!r}. Args: {event.args}"
            )
            resolved_path = None
        log.debug(
            f"[{event.syscall}] PID {pid}: Post-resolve path type: {type(resolved_path)}, value: {resolved_path!r}"
        )
        path_for_stat_call = resolved_path
        if resolved_path and success:
            new_cwd = resolved_path
        elif (
            path_arg_parsed and not resolved_path
        ):  # If resolve failed, use original bytes for stat
            path_for_stat_call = path_arg_parsed

    elif event.syscall == "fchdir":
        fd_arg = _get_arg(event.args, 0, int)  # fd: int
        if fd_arg is not None:
            details["fd"] = fd_arg
            target_path: bytes | None = monitor.get_path(pid, fd_arg)  # path: bytes
            path_for_stat_call = target_path
            if target_path and success:
                new_cwd = target_path
            elif not target_path:
                log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}.")
        else:
            log.warning(
                f"fchdir syscall for PID {pid} missing or invalid FD argument: {event.args}"
            )

    if success and new_cwd:
        cwd_map[pid] = new_cwd
        log.info(
            f"PID {pid} changed CWD via {event.syscall} to: {os.fsdecode(new_cwd)!r}"
        )

    if path_for_stat_call:
        monitor.stat(pid, path_for_stat_call, success, timestamp, **details)
    elif not success:
        log.warning(
            f"{event.syscall} failed for PID {pid}, target path unknown/unresolved: {event!r}"
        )


# --- SYSCALL_HANDLERS dict remains the same ---
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
    "fstat": _handle_stat,
    "unlink": _handle_delete,
    "unlinkat": _handle_delete,
    "rmdir": _handle_delete,
    "rename": _handle_rename,
    "renameat": _handle_rename,
    "renameat2": _handle_rename,
}
