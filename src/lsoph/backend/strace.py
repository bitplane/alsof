# Filename: src/lsoph/backend/strace.py

import argparse
import logging
import os
import shlex
import sys
from collections.abc import Callable, Iterator
from typing import Any, Dict, List, Optional, Tuple  # Added Optional, Tuple, Dict, Any

import psutil

# Import necessary components from strace_cmd and monitor
from lsoph.backend.strace_cmd import (
    DEFAULT_SYSCALLS,
    EXIT_SYSCALLS,
    PROCESS_SYSCALLS,
    Syscall,
    parse_strace_stream,
)
from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

log = logging.getLogger("lsoph.backend.strace")

# Type alias for handler functions
SyscallHandler = Callable[[Syscall, Monitor, Dict[int, str]], None]


# --- Helper Functions ---


def _parse_result_int(result_str: str) -> Optional[int]:
    """Parses strace result string (dec/hex/?), returns integer or None."""
    if not result_str or result_str == "?":
        return None
    try:
        # Attempt to parse as integer, automatically handling hex (0x...) / octal (0...)
        return int(result_str, 0)
    except ValueError:
        log.warning(f"Could not parse result string as integer: '{result_str}'")
        return None


def _clean_path_arg(path_arg: Any) -> Optional[str]:
    """
    Cleans a potential path argument from strace output.
    Removes surrounding quotes and attempts basic escape sequence decoding.
    Handles hex-encoded strings from strace's -xx option.
    """
    if not isinstance(path_arg, str) or not path_arg:
        return None

    path = path_arg

    # 1. Handle hex-encoded strings (from -xx) like "\x41\x42..."
    if path.startswith('"') and path.endswith('"') and "\\x" in path:
        path = path[1:-1]  # Remove quotes
        try:
            # Decode using raw_unicode_escape which handles \xNN
            decoded_bytes = (
                path.encode("latin-1", "backslashreplace")
                .decode("unicode_escape")
                .encode("latin-1", "surrogateescape")
            )
            # Attempt to decode as UTF-8, falling back to latin-1 if needed
            try:
                path = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                path = decoded_bytes.decode("latin-1")
            log.debug(f"Decoded hex path '{path_arg}' to '{path}'")
        except Exception as e:
            log.warning(
                f"Failed to decode hex path '{path_arg}': {e}. Using raw value after quote removal."
            )
            # Keep path as the quote-removed string

    # 2. Handle regular quoted strings (if not hex-decoded)
    elif path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
        # Attempt standard escape sequence decoding (e.g., \n, \t)
        try:
            # Use string escape for standard sequences
            path = path.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception as e:
            log.warning(
                f"Error decoding standard escapes in path '{path_arg}': {e}. Using raw value after quote removal."
            )
            # Keep path as the quote-removed string

    # 3. Handle non-quoted strings (or strings after quote removal)
    # No further processing needed unless specific escapes need handling here.

    return path


def _parse_dirfd(dirfd_arg: Optional[str]) -> Optional[Union[int, str]]:
    """Parses the dirfd argument string (e.g., "AT_FDCWD", "3") from strace output."""
    if dirfd_arg is None:
        return None
    # Check for the special AT_FDCWD constant
    if isinstance(dirfd_arg, str) and dirfd_arg.strip().upper() == "AT_FDCWD":
        return "AT_FDCWD"
    # Try parsing as an integer (handles dec/hex/octal)
    try:
        return int(str(dirfd_arg), 0)
    except (ValueError, TypeError):
        log.warning(f"Could not parse dirfd argument: '{dirfd_arg}'")
        return None


def _resolve_path(
    pid: int,
    path: Optional[str],
    cwd_map: Dict[int, str],
    monitor: Monitor,  # Pass monitor to look up paths for numeric dirfds
    dirfd: Optional[Union[int, str]] = None,
) -> Optional[str]:
    """
    Converts a potentially relative path from strace to an absolute path.
    Uses the process's tracked CWD, dirfd argument, and monitor state.

    Args:
        pid: The process ID performing the syscall.
        path: The path string from the syscall arguments.
        cwd_map: Dictionary mapping PIDs to their known CWDs.
        monitor: The Monitor instance to look up paths for numeric dirfds.
        dirfd: The parsed dirfd argument (AT_FDCWD, an integer FD, or None).

    Returns:
        The resolved absolute path string, the original path if resolution fails,
        or None if the input path was None.
    """
    log.debug(
        f"_resolve_path called: pid={pid}, path='{path}', cwd_map has pid={pid in cwd_map}, dirfd='{dirfd}'"
    )

    if path is None:
        return None

    # Handle special paths like "<socket:[...]>", "<pipe:[...]>", "@..."
    if (path.startswith("<") and path.endswith(">")) or path.startswith("@"):
        log.debug(f"Path '{path}' is special, returning as is.")
        return path

    base_dir: Optional[str] = None

    # --- Determine Base Directory based on dirfd ---
    if dirfd is not None:
        if dirfd == "AT_FDCWD":
            # Use the process's current working directory
            base_dir = cwd_map.get(pid)
            log.debug(f"dirfd is AT_FDCWD, using base_dir from cwd_map: '{base_dir}'")
        elif isinstance(dirfd, int) and dirfd >= 0:
            # Look up the path associated with the numeric file descriptor
            base_dir = monitor.get_path(pid, dirfd)
            if base_dir:
                # Ensure the base path is actually a directory
                # This requires an OS check, which might be slow or have permission issues.
                # For now, we'll trust the syscall implies it's a directory context.
                # Consider adding os.path.isdir check if strictness is needed.
                log.debug(
                    f"dirfd is {dirfd}, resolved base_dir from monitor: '{base_dir}'"
                )
            else:
                log.warning(
                    f"Numeric dirfd={dirfd} for PID {pid} not found in monitor state. Cannot resolve relative path."
                )
                # Cannot resolve reliably, return original path
                return path
        else:
            log.warning(
                f"Unhandled or invalid dirfd type/value: {dirfd!r}. Cannot resolve relative path."
            )
            return path  # Cannot resolve reliably

    # --- Resolve the Path ---
    # If the path is already absolute, return it directly.
    # Note: os.path.isabs might behave differently on different OSes, but handles basic cases.
    if os.path.isabs(path):
        if dirfd is not None:
            # An absolute path with dirfd usually means dirfd is ignored by the kernel.
            log.debug(
                f"Path '{path}' is absolute, ignoring dirfd='{dirfd}'. Returning absolute path."
            )
        else:
            log.debug(f"Path '{path}' is absolute, returning directly.")
        return path
    else:
        # Path is relative. Resolve it against the determined base directory.
        if base_dir is None:
            # If dirfd wasn't specified, use the process's CWD as the base.
            base_dir = cwd_map.get(pid)
            log.debug(f"No dirfd specified, using base_dir from cwd_map: '{base_dir}'")

        if base_dir:
            try:
                # Join the base directory and the relative path
                abs_path = os.path.normpath(os.path.join(base_dir, path))
                log.debug(
                    f"Resolved relative path '{path}' using base '{base_dir}' -> '{abs_path}'"
                )
                return abs_path
            except Exception as e:
                # Log if joining fails (e.g., invalid characters)
                log.warning(
                    f"Error joining path '{path}' with base_dir '{base_dir}': {e}"
                )
                # Fall through to returning original path
        else:
            # Could not determine base directory (e.g., CWD unknown and no valid dirfd)
            log.warning(
                f"Could not determine base directory for PID {pid} to resolve relative path '{path}'. Returning original."
            )
            return path


# --- Syscall Handlers ---
# These functions take the parsed Syscall, the Monitor, and the current CWD map.


def _handle_open_creat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles open, openat, creat syscalls."""
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}
    path: Optional[str] = None
    dirfd: Optional[Union[int, str]] = None

    if event.syscall in ["open", "creat"]:
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        path = _resolve_path(pid, path_arg, cwd_map, monitor)  # dirfd is implicitly CWD
    elif event.syscall == "openat":
        dirfd_arg = event.args[0] if event.args else None
        path_arg = _clean_path_arg(event.args[1] if len(event.args) > 1 else None)
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg  # Store original dirfd string for info

    if path is not None:
        fd = _parse_result_int(event.result_str) if success else -1
        if fd is None:
            fd = -1  # Treat parse failure as invalid fd
        details["fd"] = fd
        monitor.open(pid, path, fd, success, timestamp, **details)
    else:
        log.warning(
            f"Skipping {event.syscall}, could not resolve path from args: {event.args}"
        )


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles close syscall."""
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}

    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
    if fd_arg is not None:
        details["fd"] = fd_arg
        monitor.close(pid, fd_arg, success, timestamp, **details)
    else:
        log.warning(f"Skipping close, invalid/missing fd argument: {event.args}")


def _handle_read_write(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles read, pread64, readv, write, pwrite64, writev syscalls."""
    pid = event.pid
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}

    fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
    if fd_arg is None:
        log.warning(
            f"Skipping {event.syscall}, invalid/missing fd argument: {event.args}"
        )
        return

    details["fd"] = fd_arg
    path = monitor.get_path(pid, fd_arg)  # Get path from monitor state

    byte_count = _parse_result_int(event.result_str) if success else 0
    if byte_count is None:
        byte_count = 0  # Treat parse failure as 0 bytes
    details["bytes"] = byte_count

    if event.syscall.startswith("read"):
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    elif event.syscall.startswith("write"):
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles access, stat, lstat, newfstatat syscalls."""
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
        # Note: path can be empty string for newfstatat to stat the dirfd itself
        dirfd = _parse_dirfd(dirfd_arg)
        path = _resolve_path(pid, path_arg, cwd_map, monitor, dirfd=dirfd)
        details["dirfd"] = dirfd_arg

    if path is not None:
        monitor.stat(pid, path, success, timestamp, **details)
    else:
        log.warning(
            f"Skipping {event.syscall}, could not resolve path from args: {event.args}"
        )


def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles unlink, unlinkat, rmdir syscalls."""
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
    else:
        log.warning(
            f"Skipping {event.syscall}, could not resolve path from args: {event.args}"
        )


def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: Dict[int, str]):
    """Handles rename, renameat, renameat2 syscalls."""
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
    else:
        log.warning(
            f"Skipping {event.syscall}, could not resolve paths from args: {event.args}"
        )


# --- Syscall Dispatcher ---

# Dictionary mapping syscall names to their handler functions
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
    # chdir/fchdir are handled separately for CWD tracking
    # process/exit syscalls are handled separately
}


# --- Core Event Processing Logic ---


def _update_cwd(pid: int, cwd_map: Dict[int, str], monitor: Monitor, event: Syscall):
    """Updates the CWD map based on chdir or fchdir syscalls."""
    success = event.error_name is None
    timestamp = event.timestamp
    details: Dict[str, Any] = {"syscall": event.syscall}

    if not success:
        # Failed CWD changes don't update the map, but record the attempt
        if event.syscall == "chdir":
            path_arg = _clean_path_arg(event.args[0] if event.args else None)
            # Try resolving path even on failure for logging/history
            path = _resolve_path(pid, path_arg, cwd_map, monitor)
            if path:
                monitor.stat(pid, path, success, timestamp, **details)
        elif event.syscall == "fchdir":
            fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
            if fd_arg is not None:
                path = monitor.get_path(pid, fd_arg)
                if path:
                    monitor.stat(pid, path, success, timestamp, fd=fd_arg, **details)
        return  # Don't update cwd_map on failure

    # Handle successful CWD changes
    new_cwd: Optional[str] = None
    if event.syscall == "chdir":
        path_arg = _clean_path_arg(event.args[0] if event.args else None)
        resolved_path = _resolve_path(pid, path_arg, cwd_map, monitor)
        if resolved_path:
            new_cwd = resolved_path
            details["path"] = resolved_path
            monitor.stat(pid, new_cwd, success, timestamp, **details)  # Record access
        else:
            log.warning(
                f"Could not resolve successful chdir path '{path_arg}' for PID {pid}"
            )
    elif event.syscall == "fchdir":
        fd_arg = _parse_result_int(str(event.args[0])) if event.args else None
        if fd_arg is not None:
            target_path = monitor.get_path(pid, fd_arg)
            if target_path:
                # Assume the target of a successful fchdir is a directory
                new_cwd = target_path
                details["fd"] = fd_arg
                monitor.stat(
                    pid, new_cwd, success, timestamp, **details
                )  # Record access
            else:
                log.warning(
                    f"Successful fchdir(fd={fd_arg}) target path unknown for PID {pid}."
                )
        else:
            log.warning(
                f"Successful fchdir for PID {pid} had invalid fd argument: {event.args}"
            )

    # Update the map if a new CWD was determined
    if new_cwd:
        cwd_map[pid] = new_cwd
        log.info(f"PID {pid} changed CWD via {event.syscall} to: {new_cwd}")


def _process_event_stream(
    event_stream: Iterator[Syscall],
    monitor: Monitor,
    initial_pids: Optional[List[int]] = None,
):
    """
    Processes the stream of Syscall events, updates monitor state and CWD map.
    """
    # CWD map: pid -> path string
    pid_cwd_map: Dict[int, str] = {}

    # Initialize CWD for initially attached PIDs
    if initial_pids:
        for pid in initial_pids:
            cwd = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd
                log.info(f"Fetched initial CWD for PID {pid}: {cwd}")
            else:
                log.warning(f"Could not fetch initial CWD for PID {pid}")

    log.info("Starting strace event processing loop...")
    for event in event_stream:
        pid = event.pid  # PID should be resolved by parse_strace_stream
        syscall_name = event.syscall
        success = event.error_name is None
        timestamp = event.timestamp

        # Ensure CWD is known for the process if possible
        if pid not in pid_cwd_map:
            cwd = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd
                log.info(f"Fetched CWD for newly seen PID {pid}: {cwd}")
            else:
                # Log warning but continue; path resolution might use fallbacks
                log.warning(
                    f"Could not determine CWD for PID {pid}. Relative path resolution may be affected."
                )

        # Handle CWD changes first
        if syscall_name in ["chdir", "fchdir"]:
            _update_cwd(pid, pid_cwd_map, monitor, event)
            continue  # CWD update handled, move to next event

        # Handle process exit
        if syscall_name in EXIT_SYSCALLS:
            monitor.process_exit(pid, timestamp)
            # Clean up CWD map for the exiting process
            if pid in pid_cwd_map:
                del pid_cwd_map[pid]
                log.debug(f"Removed PID {pid} from CWD map on exit.")
            continue  # Exit handled, move to next event

        # Handle other file-related syscalls using the dispatcher
        handler = SYSCALL_HANDLERS.get(syscall_name)
        if handler:
            try:
                # Add common details before calling handler
                details = {"syscall": syscall_name}
                if not success and event.error_name:
                    details["error_name"] = event.error_name
                    details["error_msg"] = event.error_msg
                # Note: Handlers might add more details like 'bytes', 'fd' etc.

                # Call the specific handler
                handler(event, monitor, pid_cwd_map)

            except Exception as e:
                log.exception(
                    f"Error in handler for syscall {syscall_name} (event: {event!r}): {e}"
                )
        else:
            # Log unhandled (but traced) syscalls for debugging if needed
            if (
                syscall_name not in PROCESS_SYSCALLS
            ):  # Already handled internally by parser
                log.debug(f"No specific handler for syscall: {syscall_name}")

    log.info("Finished processing strace event stream.")


# --- Public Interface Functions ---


def attach(pids: List[int], monitor: Monitor, syscalls: List[str] = DEFAULT_SYSCALLS):
    """Attaches strace to existing PIDs/TIDs and processes events."""
    if not pids:
        log.warning("strace.attach called with no PIDs.")
        return
    log.info(f"Attaching strace to PIDs/TIDs: {pids}")

    try:
        # Get the stream of parsed Syscall events
        event_stream = parse_strace_stream(
            monitor=monitor, attach_ids=pids, syscalls=syscalls
        )
        # Process the stream
        _process_event_stream(event_stream, monitor, initial_pids=pids)
    except KeyboardInterrupt:
        log.info("Strace attach interrupted by user.")
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        # Errors during strace startup or FIFO handling
        log.error(f"Failed to start or run strace for attach: {e}")
    except Exception as e:
        log.exception(f"Unexpected error during strace attach processing: {e}")
    finally:
        log.info("Strace attach finished.")


def run(command: List[str], monitor: Monitor, syscalls: List[str] = DEFAULT_SYSCALLS):
    """Launches a command via strace and processes events."""
    if not command:
        log.error("strace.run called with empty command.")
        return
    log.info(f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}")

    try:
        # Get the stream of parsed Syscall events
        event_stream = parse_strace_stream(
            monitor=monitor, target_command=command, syscalls=syscalls
        )
        # Process the stream
        _process_event_stream(
            event_stream, monitor
        )  # Initial PIDs determined by parser
    except KeyboardInterrupt:
        log.info("Strace run interrupted by user.")
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        # Errors during strace startup or FIFO handling
        log.error(f"Failed to start or run strace for run: {e}")
    except Exception as e:
        log.exception(f"Unexpected error during strace run processing: {e}")
    finally:
        log.info("Strace run finished.")


# --- Main Execution Function (for testing) ---
# (Keep the original main for standalone testing if desired, ensuring it uses the new structure)
def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for testing strace adapter."""
    parser = argparse.ArgumentParser(
        description="Strace adapter (Test): runs/attaches strace and updates Monitor state.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  sudo python3 -m lsoph.backend.strace -c find . -maxdepth 1\n  sudo python3 -m lsoph.backend.strace -p 1234",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--command",
        nargs=argparse.REMAINDER,
        help="The target command and its arguments to launch and trace.",
    )
    group.add_argument(
        "-p",
        "--pids",
        nargs="+",
        type=int,
        metavar="PID",
        help="One or more existing process IDs (PIDs) to attach to.",
    )
    parser.add_argument(
        "--log",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )
    args = parser.parse_args(argv)

    # Configure logging ONLY when run as script
    log_level = args.log.upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s:%(name)s:%(message)s"
    )
    # Also configure the cmd module's logger if needed for testing
    logging.getLogger("lsoph.backend.strace_cmd").setLevel(log_level)
    log.info(f"Log level set to {log_level}")

    target_command: Optional[List[str]] = None
    attach_ids: Optional[List[int]] = None
    monitor_id = "adapter_test"

    if args.command:
        if not args.command:
            log.critical("No command provided for -c.")
            parser.print_usage(sys.stderr)
            return 1
        target_command = args.command
        monitor_id = shlex.join(target_command)
    elif args.pids:
        attach_ids = args.pids
        monitor_id = f"pids_{'_'.join(map(str, attach_ids))}"
    else:
        log.critical("Internal error: Must provide either -c or -p.")
        parser.print_usage(sys.stderr)
        return 1

    if os.geteuid() != 0:
        log.warning("Running without root. strace/psutil may fail or lack permissions.")

    monitor = Monitor(identifier=monitor_id)

    try:
        if target_command:
            run(target_command, monitor)
        elif attach_ids:
            attach(attach_ids, monitor)

        log.info("--- Final Monitored State (Adapter Test) ---")
        tracked_files = list(monitor)
        tracked_files.sort(key=lambda fi: fi.last_activity_ts, reverse=True)

        if not tracked_files:
            log.info("No files were tracked.")
        else:
            for i, file_info in enumerate(tracked_files):
                print(f"{i+1}: {repr(file_info)}")
                if i >= 20:
                    print("...")
                    break

        log.info("------------------------------------------")
        return 0
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        log.error(f"Execution failed: {e}")
        return 1
    except KeyboardInterrupt:
        log.info("\nCtrl+C detected in main.")
        return 130
    except Exception as e:
        log.exception(f"An unexpected error occurred in main: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
