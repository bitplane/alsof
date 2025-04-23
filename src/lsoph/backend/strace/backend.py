# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend implementation using refactored components."""

import argparse
import asyncio
import logging
import os
import shlex
import sys
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple, Union

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
    """Safely parses an integer result string from strace."""
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)  # Handles hex (0x...) and decimal
    except ValueError:
        log.warning(f"Could not parse result: '{result_str}'")
        return None


def _clean_path_arg(path_arg: Any) -> Optional[str]:
    """Cleans and decodes path arguments from strace, handling quotes and escapes."""
    if not isinstance(path_arg, str) or not path_arg:
        return None

    path = path_arg
    # Handle hex-encoded strings first (common for non-ASCII)
    if path.startswith('"') and path.endswith('"') and "\\x" in path:
        path = path[1:-1]  # Remove quotes
        try:
            # Decode using unicode_escape, then handle potential surrogates
            decoded_bytes = (
                path.encode("latin-1", "backslashreplace")  # Preserve backslashes
                .decode("unicode_escape")  # Decode \xNN sequences
                .encode("latin-1", "surrogateescape")  # Allow lone surrogates
            )
            try:
                # Try decoding as UTF-8 first (most common)
                path = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # Fallback to latin-1 if UTF-8 fails
                path = decoded_bytes.decode("latin-1")
        except Exception as e:
            log.warning(f"Failed hex/escape decode '{path_arg}': {e}")
            # Return the original quoted string if decoding fails badly
            return path_arg
    # Handle simple quoted strings with standard escapes
    elif path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
        try:
            # Use standard string escape decoding
            path = path.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception as e:
            log.warning(f"Failed simple escape decode '{path_arg}': {e}")
            return path_arg  # Return original quoted string on error

    # If it wasn't quoted or decoding failed, return the original (or partially decoded) path
    return path


def _parse_dirfd(dirfd_arg: Optional[str]) -> Optional[Union[int, str]]:
    """Parses the dirfd argument, handling AT_FDCWD."""
    if dirfd_arg is None:
        return None
    if isinstance(dirfd_arg, str) and dirfd_arg.strip().upper() == "AT_FDCWD":
        return "AT_FDCWD"
    try:
        # Handle potential base prefixes like 0x
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
    """Resolves a path argument relative to CWD or dirfd if necessary."""
    if path is None:
        return None

    # Don't resolve special paths like sockets "<...>" or abstract namespaces "@..."
    if (path.startswith("<") and path.endswith(">")) or path.startswith("@"):
        return path

    base_dir: Optional[str] = None

    # Determine base directory based on dirfd
    if dirfd is not None:
        if dirfd == "AT_FDCWD":
            base_dir = cwd_map.get(pid)
            if base_dir is None:
                log.warning(f"AT_FDCWD used, but CWD for PID {pid} is unknown.")
                # Fallback to treating path as relative to potentially unknown CWD
                # or absolute if it starts with '/'
        elif isinstance(dirfd, int) and dirfd >= 0:
            # Get the path associated with the directory file descriptor
            base_dir = monitor.get_path(pid, dirfd)
            if not base_dir:
                log.warning(
                    f"dirfd={dirfd} used, but path for this FD in PID {pid} is unknown."
                )
                # Cannot resolve relative path reliably, return original path
                return path
        else:
            # Unhandled dirfd type (should not happen with _parse_dirfd)
            log.warning(f"Unhandled dirfd value: {dirfd!r} for PID {pid}")
            return path  # Cannot resolve

    # Resolve the path
    if os.path.isabs(path):
        # Path is absolute, normalize it
        return os.path.normpath(path)
    else:
        # Path is relative
        if base_dir is None:
            # If dirfd wasn't specified or was AT_FDCWD with unknown CWD, use PID's CWD
            base_dir = cwd_map.get(pid)

        if base_dir:
            try:
                # Join relative path with the determined base directory
                return os.path.normpath(os.path.join(base_dir, path))
            except Exception as e:
                # Handle potential errors during path joining (e.g., invalid chars)
                log.warning(
                    f"Error joining path '{path}' with base '{base_dir}' for PID {pid}: {e}"
                )
                return path  # Return original relative path on error
        else:
            # Cannot resolve relative path if base_dir is unknown
            log.warning(
                f"Cannot resolve relative path '{path}' for PID {pid}: CWD unknown."
            )
            return path  # Return original relative path


# --- End Internal Helpers ---


# --- Syscall Handlers (remain synchronous) ---
# These handlers now use the helper functions defined above.
def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles open, openat, creat syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None

    if event.syscall in ["open", "creat"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "openat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Keep original for logging

    if path is not None:
        fd = _parse_result_int(event.result_str) if success else -1
        fd = fd if fd is not None else -1
        # Ensure fd is not passed in details dict, pass positionally
        monitor.open(pid, path, fd, success, timestamp, **details)
    else:
        log.warning(f"Could not determine path for {event.syscall} event: {event!r}")


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles close syscall."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    # The argument to close() is the FD being closed
    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None

    if fd_arg is not None:
        # Ensure fd is not passed in details dict, pass positionally
        monitor.close(pid, fd_arg, success, timestamp, **details)
    else:
        log.warning(f"Could not parse FD for close event: {event!r}")


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles read, write, pread64, pwrite64, readv, writev syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    # First argument is always the file descriptor
    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None

    if fd_arg is None:
        log.warning(f"No valid FD found for {event.syscall} event: {event!r}")
        return

    # Get the path associated with the FD *before* potentially closing it on error
    path = monitor.get_path(pid, fd_arg)

    # Result is byte count (or error)
    byte_count = _parse_result_int(event.result_str) if success else 0
    byte_count = byte_count if byte_count is not None else 0
    details["bytes"] = byte_count

    # Ensure fd is not passed in details dict, pass positionally
    if event.syscall.startswith("read"):
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    elif event.syscall.startswith("write"):
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles access, stat, lstat, newfstatat syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None

    if event.syscall in ["access", "stat", "lstat"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "newfstatat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Keep original for logging

    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)
    else:
        log.warning(f"Could not determine path for {event.syscall} event: {event!r}")


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles unlink, unlinkat, rmdir syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None

    if event.syscall in ["unlink", "rmdir"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)
    elif event.syscall == "unlinkat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Keep original for logging

    if path is not None:
        monitor.delete(pid, path, success, timestamp, **details)
    else:
        log.warning(f"Could not determine path for {event.syscall} event: {event!r}")


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles rename, renameat, renameat2 syscalls."""
    pid, success, timestamp = event.pid, event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    old_path: Optional[str] = None
    new_path: Optional[str] = None

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

        details["old_dirfd"] = old_dirfd_arg  # Keep original for logging
        details["new_dirfd"] = new_dirfd_arg  # Keep original for logging

    if old_path and new_path:
        monitor.rename(pid, old_path, new_path, success, timestamp, **details)
    else:
        log.warning(
            f"Could not determine old or new path for {event.syscall} event: {event!r}"
        )


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
    # Note: chdir/fchdir/exit are handled directly in the processing loop
}
# --- End Syscall Dispatcher ---


# --- CWD Update Logic ---
def _update_cwd(pid: int, cwd_map: Dict[int, str], monitor: Monitor, event: Syscall):
    """Updates the CWD map based on chdir or fchdir syscalls."""
    success, timestamp = event.error_name is None, event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}

    new_cwd: Optional[str] = None  # Store the determined new CWD

    if event.syscall == "chdir":
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        if path_arg:
            resolved_path = _resolve_path(pid, path_arg, cwd_map, monitor)
            if resolved_path:
                if success:
                    new_cwd = resolved_path
                details["path"] = resolved_path  # Log attempted path even on failure
            else:
                log.warning(f"Could not resolve chdir path '{path_arg}' for PID {pid}")
                details["path"] = path_arg  # Log original arg if resolution failed
        else:
            log.warning(f"chdir syscall for PID {pid} missing path argument: {event!r}")

    elif event.syscall == "fchdir":
        fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
        if fd_arg is not None:
            details["fd"] = fd_arg  # Log the FD used
            target_path = monitor.get_path(pid, fd_arg)
            if target_path:
                if success:
                    new_cwd = target_path
                details["target_path"] = target_path  # Log path associated with FD
            else:
                log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}.")
        else:
            log.warning(
                f"fchdir syscall for PID {pid} has invalid FD argument: {event.args}"
            )

    # If the syscall was successful and we determined a new CWD, update the map
    if success and new_cwd:
        cwd_map[pid] = new_cwd
        monitor.stat(
            pid, new_cwd, success, timestamp, **details
        )  # Log successful stat of new CWD
        log.info(f"PID {pid} changed CWD via {event.syscall} to: {new_cwd}")
    # If the syscall failed, but we identified the target path/fd, log a failed stat
    elif not success and ("path" in details or "target_path" in details):
        path_for_stat = details.get("path") or details.get("target_path")
        if path_for_stat:
            monitor.stat(pid, path_for_stat, success, timestamp, **details)
    elif not success:
        # Log generic failure if path couldn't be determined
        log.warning(
            f"{event.syscall} failed for PID {pid}, but target path unknown: {event!r}"
        )


# --- End CWD Update Logic ---


# --- Event Processing Helper ---
async def _process_single_event(
    event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]
):
    """Processes a single Syscall event, updating state and CWD map."""
    pid = event.pid
    syscall_name = event.syscall

    # Ensure CWD is known for the PID before processing path-dependent syscalls
    if (
        pid not in cwd_map and syscall_name not in EXIT_SYSCALLS
    ):  # Exit doesn't need CWD
        cwd = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
            log.info(f"Fetched CWD for new PID {pid}: {cwd}")
        else:
            # If CWD cannot be fetched, we might proceed but relative paths will fail
            log.warning(
                f"Could not determine CWD for PID {pid}. Relative paths may be incorrect."
            )

    log.debug(f"Processing event: {event!r}")

    # Handle specific syscalls that modify state or need special handling first
    if syscall_name in ["chdir", "fchdir"]:
        _update_cwd(pid, cwd_map, monitor, event)
        return  # CWD update handled, skip generic handler

    if syscall_name in EXIT_SYSCALLS:
        monitor.process_exit(pid, event.timestamp)
        if pid in cwd_map:
            del cwd_map[pid]
            log.debug(f"Removed PID {pid} CWD map on exit.")
        return  # Process exit handled, skip generic handler

    # Dispatch to generic handlers for file operations
    handler = SYSCALL_HANDLERS.get(syscall_name)
    if handler:
        try:
            handler(event, monitor, cwd_map)
        except Exception as e:
            # Log the specific event that caused the handler error
            log.exception(f"Handler error for {syscall_name} (event: {event!r}): {e}")
    # else: # Optional: Log unhandled syscalls if needed for debugging
    #    log.debug(f"No specific handler for syscall: {syscall_name}")


# --- End Event Processing Helper ---


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
                | {"chdir", "fchdir"}  # Ensure CWD tracking syscalls are present
            )
        )
        # Add attribute to store the strace process handle
        self._strace_process: asyncio.subprocess.Process | None = None

    async def _process_event_stream(
        self, event_stream: AsyncIterator[Syscall], pid_cwd_map: Dict[int, str]
    ):
        """
        Internal helper method to process the stream of Syscall events.
        This method contains the logic previously duplicated in attach and run_command.
        """
        log.info("Starting internal event processing loop...")
        processed_count = 0
        try:
            async for event in event_stream:
                if self.should_stop:
                    log.info("Stop signal detected during event processing.")
                    break
                processed_count += 1
                await _process_single_event(event, self.monitor, pid_cwd_map)

            log.info(
                f"Finished internal event loop. Processed {processed_count} events."
            )

        except asyncio.CancelledError:
            log.info("Event processing stream task cancelled.")
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            # Errors likely originating from parse_strace_stream or stream_strace_output
            log.error(f"Error during event stream processing: {e}")
            # Signal stop to ensure cleanup if the stream fails critically
            await self.stop()
        except Exception as e:
            log.exception(f"Unexpected error processing event stream: {e}")
            # Signal stop on unexpected errors too
            await self.stop()
        finally:
            log.info("Exiting internal event processing loop.")

    async def attach(self, pids: list[int]):
        """Implementation of the attach method using refactored components."""
        if not pids:
            log.warning("StraceBackend.attach called with no PIDs.")
            return

        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        # Pre-populate CWD map for initially attached PIDs
        pid_cwd_map: Dict[int, str] = {}
        for pid in pids:
            # Use pid_get_cwd which handles errors internally
            cwd = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd
            else:
                log.warning(f"Could not get initial CWD for attached PID {pid}.")
        log.info(f"Initial CWDs for attach: {pid_cwd_map}")

        try:
            # Get the event stream from the parser
            event_stream = parse_strace_stream(
                backend=self,  # Pass self
                monitor=self.monitor,
                should_stop=self._should_stop,
                target_command=None,  # Explicitly None for attach mode
                attach_ids=pids,
                syscalls=self.syscalls,
            )

            # Process the stream using the helper method
            await self._process_event_stream(event_stream, pid_cwd_map)

        except asyncio.CancelledError:
            log.info("Strace attach task cancelled externally.")
        except Exception as e:
            # Catch errors during setup (e.g., parse_strace_stream init)
            log.exception(f"Error setting up or running strace attach: {e}")
        finally:
            log.info("Strace attach finished.")
            # Ensure stop is called if the loop finishes unexpectedly
            if not self.should_stop:
                await self.stop()

    async def run_command(self, command: list[str]):
        """Implementation of the run_command method using refactored components."""
        if not command:
            log.error("StraceBackend.run_command called empty.")
            return

        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        # CWD map starts empty and is populated dynamically by _process_single_event
        pid_cwd_map: Dict[int, str] = {}

        try:
            # Get the event stream from the parser
            event_stream = parse_strace_stream(
                backend=self,  # Pass self
                monitor=self.monitor,
                should_stop=self._should_stop,
                target_command=command,
                attach_ids=None,  # Explicitly None for run mode
                syscalls=self.syscalls,
            )

            # Process the stream using the helper method
            await self._process_event_stream(event_stream, pid_cwd_map)

        except asyncio.CancelledError:
            log.info("Strace run task cancelled externally.")
        except Exception as e:
            # Catch errors during setup (e.g., parse_strace_stream init)
            log.exception(f"Error setting up or running strace run_command: {e}")
        finally:
            log.info("Strace run_command finished.")
            # Ensure stop is called if the loop finishes unexpectedly
            # (e.g., if the target command exits before stop is called)
            if not self.should_stop:
                await self.stop()

    # Override the stop method from the base class to specifically handle _strace_process
    async def stop(self):
        """Signals the backend's running task to stop and terminates the managed strace process."""
        if not self._should_stop.is_set():
            log.info(f"Signalling backend {self.__class__.__name__} to stop.")
            self._should_stop.set()  # Signal the event stream loop (_process_event_stream) to stop

            # Terminate the specific strace process using its stored handle
            # Use a local variable to avoid race conditions if stop is called multiple times
            process_to_term = self._strace_process
            pid_to_term = process_to_term.pid if process_to_term else -1

            log.info(
                f"Attempting termination of stored strace process (PID: {pid_to_term})..."
            )
            # Call the dedicated termination helper
            await terminate_strace_process(process_to_term, pid_to_term)

            # Clear the stored handle after attempting termination
            self._strace_process = None

            # NOTE: We do NOT call the base class's _terminate_process here,
            # as strace has its own process handle (_strace_process) managed separately.
            # The base class's _process handle is for the *target* command when
            # using the default run_command implementation, which strace overrides.
        else:
            log.debug(f"Backend {self.__class__.__name__} stop already signalled.")


# --- End Backend Class ---
