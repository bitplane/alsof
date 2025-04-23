# Filename: src/lsoph/backend/strace.py

import argparse
import asyncio  # Ensure asyncio is imported
import logging
import os
import shlex
import sys

# Use Python 3.10+ style hints
from collections.abc import AsyncIterator, Callable
from typing import Any, Dict, List, Optional, Tuple, Union

import psutil

# Import async components from strace_cmd
from lsoph.backend.strace_cmd import parse_strace_stream  # Now an async generator
from lsoph.backend.strace_cmd import (
    DEFAULT_SYSCALLS,
    EXIT_SYSCALLS,
    PROCESS_SYSCALLS,
    Syscall,
)
from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

# Import base class
from .base import Backend

log = logging.getLogger("lsoph.backend.strace")

# Type alias for handler functions (remains sync)
SyscallHandler = Callable[[Syscall, Monitor, Dict[int, str]], None]


# --- Helper Functions (remain synchronous) ---
# _parse_result_int, _clean_path_arg, _parse_dirfd, _resolve_path
# remain the same.
def _parse_result_int(result_str: str) -> Optional[int]:
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)
    except ValueError:
        log.warning(f"Could not parse result string as integer: '{result_str}'")
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
            log.warning(
                f"Failed to decode hex path '{path_arg}': {e}. Using raw value after quote removal."
            )
    elif path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
        try:
            path = path.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception as e:
            log.warning(
                f"Error decoding standard escapes in path '{path_arg}': {e}. Using raw value after quote removal."
            )
    return path


def _parse_dirfd(dirfd_arg: Optional[str]) -> Optional[Union[int, str]]:
    if dirfd_arg is None:
        return None
    if isinstance(dirfd_arg, str) and dirfd_arg.strip().upper() == "AT_FDCWD":
        return "AT_FDCWD"
    try:
        return int(str(dirfd_arg), 0)
    except (ValueError, TypeError):
        log.warning(f"Could not parse dirfd argument: '{dirfd_arg}'")
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
                log.warning(
                    f"Numeric dirfd={dirfd} for PID {pid} not found in monitor state."
                )
                return path
        else:
            log.warning(f"Unhandled dirfd type/value: {dirfd!r}.")
            return path
    if os.path.isabs(path):
        return path
    else:
        if base_dir is None:
            base_dir = cwd_map.get(pid)
        if base_dir:
            try:
                return os.path.normpath(os.path.join(base_dir, path))
            except Exception as e:
                log.warning(
                    f"Error joining path '{path}' with base_dir '{base_dir}': {e}"
                )
        else:
            log.warning(
                f"Could not determine base directory for PID {pid} to resolve relative path '{path}'."
            )
    return path


# --- Syscall Handlers (remain synchronous) ---
# _handle_open_creat, _handle_close, _handle_read_write, _handle_stat, _handle_delete, _handle_rename
# remain the same internally.
def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    dirfd: Optional[Union[int, str]] = None
    if event.syscall in ["open", "creat"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "openat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg
    if path is not None:
        fd = _parse_result_int(event.result_str) if success else -1
        fd = fd if fd is not None else -1
        details["fd"] = fd
        monitor.open(pid, path, fd, success, timestamp, **details)


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
    if fd_arg is not None:
        details["fd"] = fd_arg
        monitor.close(pid, fd_arg, success, timestamp, **details)


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
    if fd_arg is None:
        return
    details["fd"] = fd_arg
    path = monitor.get_path(pid, fd_arg)
    byte_count = _parse_result_int(event.result_str) if success else 0
    byte_count = byte_count if byte_count is not None else 0
    details["bytes"] = byte_count
    if event.syscall.startswith("read"):
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    elif event.syscall.startswith("write"):
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    dirfd: Optional[Union[int, str]] = None
    if event.syscall in ["access", "stat", "lstat"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "newfstatat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg
    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    dirfd: Optional[Union[int, str]] = None
    if event.syscall in ["unlink", "rmdir"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "unlinkat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg
    if path is not None:
        monitor.delete(pid, path, success, timestamp, **details)


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    old_dirfd: Optional[Union[int, str]] = None
    new_dirfd: Optional[Union[int, str]] = None
    if event.syscall == "rename":
        old_path_arg = _clean_path_arg(event.args[0] if event.args else None)
        new_path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        old_path = _resolve_path(pid, old_path_arg, cwd_map, monitor)
        new_path = _resolve_path(pid, new_path_arg, cwd_map, monitor)
    elif event.syscall in ["renameat", "renameat2"]:
        old_dirfd_arg = event.args[0] if event.args else None
        old_path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        new_dirfd_arg = event.args[2] if len(event.args) > 2 else None
        new_path_arg = _clean_path_arg(event.args[3] if len(event.args) > 3 else None)
        old_dirfd = _parse_dirfd(old_dirfd_arg)
        new_dirfd = _parse_dirfd(new_dirfd_arg)
        old_path = _resolve_path(pid, old_path_arg, cwd_map, monitor, dirfd=old_dirfd)
        new_path = _resolve_path(pid, new_path_arg, cwd_map, monitor, dirfd=new_dirfd)
        details["old_dirfd"] = old_dirfd_arg
        details["new_dirfd"] = new_dirfd_arg
    if old_path and new_path:
        monitor.rename(pid, old_path, new_path, success, timestamp, **details)


# --- Syscall Dispatcher (synchronous) ---
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


# --- Core Event Processing Logic ---
def _update_cwd(pid: int, cwd_map: Dict[int, str], monitor: Monitor, event: Syscall):
    """Updates the CWD map based on chdir or fchdir syscalls."""
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    if not success:
        if event.syscall == "chdir":
            path_arg = _clean_path_arg(event.args[0] if event.args else None)
            path = _resolve_path(pid, path_arg, cwd_map, monitor)
            if path:
                monitor.stat(pid, path, success, timestamp, **details)
        elif event.syscall == "fchdir":
            fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
            if fd_arg is not None:
                path = monitor.get_path(pid, fd_arg)
                if path:
                    monitor.stat(pid, path, success, timestamp, fd=fd_arg, **details)
        return
    new_cwd: Optional[str] = None
    if event.syscall == "chdir":
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        resolved_path = _resolve_path(pid, path_arg, cwd_map, monitor)
        if resolved_path:
            new_cwd = resolved_path
            details["path"] = resolved_path
            monitor.stat(pid, new_cwd, success, timestamp, **details)
        else:
            log.warning(
                f"Could not resolve successful chdir path '{path_arg}' for PID {pid}"
            )
    elif event.syscall == "fchdir":
        fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
        if fd_arg is not None:
            target_path = monitor.get_path(pid, fd_arg)
            if target_path:
                new_cwd = target_path
                details["fd"] = fd_arg
                monitor.stat(pid, new_cwd, success, timestamp, **details)
            else:
                log.warning(
                    f"Successful fchdir(fd={fd_arg}) target path unknown for PID {pid}."
                )
        else:
            log.warning(
                f"Successful fchdir for PID {pid} had invalid fd argument: {event.args}"
            )
    if new_cwd:
        cwd_map[pid] = new_cwd
        log.info(f"PID {pid} changed CWD via {event.syscall} to: {new_cwd}")


async def _process_event_stream(
    event_stream: AsyncIterator[Syscall],
    monitor: Monitor,
    should_stop: asyncio.Event,
    initial_pids: Optional[List[int]] = None,
):
    """
    Asynchronously processes the stream of Syscall events using timeout-based yielding.
    """
    pid_cwd_map: Dict[int, str] = {}
    if initial_pids:
        for pid in initial_pids:
            cwd = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd
                log.info(f"Fetched initial CWD for PID {pid}: {cwd}")
            else:
                log.warning(f"Could not fetch initial CWD for PID {pid}")

    log.info("Starting async strace event processing loop (v3 - timeout)...")
    processed_count_total = 0
    GET_NEXT_TIMEOUT = 0.05  # Timeout (seconds) for getting the next event

    try:
        while not should_stop.is_set():
            event: Optional[Syscall] = None
            try:
                # Try to get the next event with a timeout
                # Note: anext() is built-in in Python 3.10+
                event = await asyncio.wait_for(
                    anext(event_stream), timeout=GET_NEXT_TIMEOUT
                )
            except StopAsyncIteration:
                log.info("Event stream ended.")
                break  # Exit the main loop
            except asyncio.TimeoutError:
                # No event received within timeout.
                # This is expected during idle periods. We don't need to log it.
                # We must explicitly yield control here.
                await asyncio.sleep(0.01)  # Yield control briefly
                continue  # Go back to check should_stop and wait for next event
            except asyncio.CancelledError:
                log.info("Event stream get cancelled.")
                break
            except Exception as e:
                log.exception(f"Error getting next event from stream: {e}")
                break  # Stop processing on unexpected error fetching events

            # --- Process the received event (if any) ---
            if event:
                processed_count_total += 1
                pid = event.pid
                syscall_name = event.syscall
                success = event.error_name is None
                timestamp = event.timestamp

                # Ensure CWD is known (sync ok)
                if pid not in pid_cwd_map:
                    cwd = pid_get_cwd(pid)
                    if cwd:
                        pid_cwd_map[pid] = cwd
                        log.info(f"Fetched CWD for newly seen PID {pid}: {cwd}")
                    else:
                        log.warning(f"Could not determine CWD for PID {pid}.")

                # Handle specific syscalls
                if syscall_name in ["chdir", "fchdir"]:
                    _update_cwd(pid, pid_cwd_map, monitor, event)
                    continue
                if syscall_name in EXIT_SYSCALLS:
                    monitor.process_exit(pid, timestamp)
                    if pid in pid_cwd_map:
                        del pid_cwd_map[pid]
                        log.debug(f"Removed PID {pid} from CWD map on exit.")
                    continue

                # Handle dispatched syscalls
                handler = SYSCALL_HANDLERS.get(syscall_name)
                if handler:
                    try:
                        details = {"syscall": syscall_name}
                        if not success and event.error_name:
                            details["error_name"] = event.error_name
                            details["error_msg"] = event.error_msg
                        handler(event, monitor, pid_cwd_map)
                    except Exception as e:
                        log.exception(
                            f"Error in handler for syscall {syscall_name} (event: {event!r}): {e}"
                        )

                # Optional: Yield control explicitly after processing *each* event if still unresponsive
                # This might be needed if handlers become complex or monitor updates are slow.
                # await asyncio.sleep(0)

            # Check stop event again after processing (or timeout)
            if should_stop.is_set():
                log.info("Stop event set after processing/timeout, breaking loop.")
                break

    except asyncio.CancelledError:
        log.info("Strace event processing task cancelled.")
    finally:
        log.info(
            f"Finished processing strace event stream. Total events: {processed_count_total}"
        )


# --- Async Backend Class ---


class StraceBackend(Backend):
    """Async backend implementation using strace."""

    def __init__(self, monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS):
        super().__init__(monitor)
        self.syscalls = syscalls
        self.syscalls = sorted(
            list(
                set(self.syscalls)
                | set(PROCESS_SYSCALLS)
                | set(EXIT_SYSCALLS)
                | {"chdir", "fchdir"}
            )
        )

    async def attach(self, pids: list[int]):
        """Implementation of the attach method."""
        if not pids:
            log.warning("StraceBackend.attach called with no PIDs.")
            return
        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        try:
            event_stream = parse_strace_stream(
                monitor=self.monitor,
                should_stop=self._should_stop,
                attach_ids=pids,
                syscalls=self.syscalls,
            )
            await _process_event_stream(
                event_stream, self.monitor, self._should_stop, initial_pids=pids
            )
        except asyncio.CancelledError:
            log.info("Strace attach task cancelled.")
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            log.error(f"Failed to start or run strace for attach: {e}")
        except Exception as e:
            log.exception(f"Unexpected error during strace attach processing: {e}")
        finally:
            log.info("Strace attach finished.")

    async def run_command(self, command: list[str]):
        """Overrides base run_command to invoke strace directly."""
        if not command:
            log.error("StraceBackend.run_command called with empty command.")
            return
        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        try:
            event_stream = parse_strace_stream(
                monitor=self.monitor,
                should_stop=self._should_stop,
                target_command=command,
                syscalls=self.syscalls,
            )
            await _process_event_stream(event_stream, self.monitor, self._should_stop)
        except asyncio.CancelledError:
            log.info("Strace run task cancelled.")
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            log.error(f"Failed to start or run strace for run: {e}")
        except Exception as e:
            log.exception(f"Unexpected error during strace run processing: {e}")
        finally:
            log.info("Strace run finished.")
