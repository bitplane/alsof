# Filename: strace.py

import argparse
import logging
import os  # Needed for path operations
import shlex
import sys
from collections.abc import Callable  # Use collections.abc

import psutil

# Modules from our package
from alsof.monitor import Monitor

# Import the new CWD function
from alsof.pid import get_cwd as pid_get_cwd
from alsof.strace_cmd import EXIT_SYSCALLS  # Import EXIT_SYSCALLS
from alsof.strace_cmd import (
    DEFAULT_SYSCALLS,
    PROCESS_SYSCALLS,
    Syscall,
    parse_strace_stream,
)

# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("alsof.strace")  # Use package-aware logger name

# --- Helper Functions ---


def _parse_result(result_str: str) -> int | None:
    """Parses strace result string (dec/hex/?), returns integer or None."""
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)  # Handles '0x...' hex and decimal
    except ValueError:
        log.warning(f"Could not parse result string: '{result_str}'")
        return None


def _clean_path_arg(path_arg: any) -> str | None:  # Use lowercase any
    """Cleans a potential path argument (removes quotes, handles basic escapes)."""
    if not isinstance(path_arg, str) or not path_arg:
        return None
    path = path_arg
    # Handle surrounding quotes first
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        path = path[1:-1]

    # Basic unescaping for common sequences seen in strace
    try:
        # Use 'unicode_escape' for standard escapes like \n, \t, \xHH
        # Use 'raw_unicode_escape' or manual replacement for octal \ooo if needed
        # Be cautious as this can mangle binary data represented as strings
        path = path.encode("utf-8", "surrogateescape").decode("unicode_escape")
    except UnicodeDecodeError:
        log.debug(f"Failed unicode_escape decoding path: {path_arg}, using raw.")
        # Fallback: maybe just replace common visual escapes?
        # path = path.replace('\\"', '"').replace('\\\\', '\\') # Example
    except Exception as e:
        log.warning(f"Unexpected error decoding path '{path_arg}': {e}, using raw.")

    return path


def _resolve_path(pid: int, path: str | None, cwd_map: dict[int, str]) -> str | None:
    """
    Converts a potentially relative path to absolute, using the process's
    tracked CWD if available. Falls back to os.path.abspath (alsof's CWD).
    """
    if path is None:
        return None
    # Avoid resolving placeholders like <STDIN> or abstract sockets (@...)
    if (path.startswith("<") and path.endswith(">")) or path.startswith("@"):
        return path
    # If path is already absolute, return it directly
    if os.path.isabs(path):
        return path

    # --- Attempt resolution using tracked CWD ---
    proc_cwd = cwd_map.get(pid)
    if proc_cwd:
        try:
            # Join the process's CWD with the relative path
            abs_path = os.path.normpath(os.path.join(proc_cwd, path))
            log.debug(
                f"Resolved relative path '{path}' using PID {pid}'s CWD '{proc_cwd}' -> '{abs_path}'"
            )
            return abs_path
        except Exception as e:
            log.warning(f"Error joining path '{path}' with CWD '{proc_cwd}': {e}")
            # Fall through to abspath fallback

    # --- Fallback: Resolve relative to alsof's CWD ---
    log.debug(
        f"No tracked CWD for PID {pid}, falling back to os.path.abspath for '{path}'"
    )
    try:
        abs_path = os.path.abspath(path)
        log.debug(f"Resolved relative path '{path}' using alsof's CWD -> '{abs_path}'")
        return abs_path
    except OSError as e:
        log.warning(f"Could not resolve path '{path}' using abspath fallback: {e}")
        return path  # Return original path on error


# --- Core Event Processing Logic ---

# Keep track of CWD per process PID
# Needs to be passed around or stored globally/in a class instance
# For simplicity here, pass it into _process_syscall_event
# pid_cwd_map: dict[int, str] = {}


def _process_syscall_event(
    event: Syscall,
    monitor: Monitor,
    tid_to_pid_map: dict[int, int],
    pid_cwd_map: dict[int, str],
):
    """Processes a single Syscall event, updating the monitor state and CWD map."""
    tid = event.tid
    syscall_name = event.syscall
    args = event.args
    result_str = event.result_str
    error_name = event.error_name
    timestamp = event.timestamp

    path: str | None = None
    old_path: str | None = None  # For rename
    new_path: str | None = None  # For rename
    fd: int | None = None
    details: dict[str, any] = {}  # Use lowercase any
    success = error_name is None
    result_code = _parse_result(result_str)

    # --- Resolve PID ---
    pid = tid_to_pid_map.get(tid)
    if pid is None:
        try:
            if psutil.pid_exists(tid):
                proc_info = psutil.Process(tid)
                pid = proc_info.pid
                tid_to_pid_map[tid] = pid
                log.debug(f"Looked up PID {pid} for unmapped TID {tid}")
                # If we just mapped a new PID, try to get its initial CWD
                if pid not in pid_cwd_map:
                    initial_cwd = pid_get_cwd(pid)
                    if initial_cwd:
                        pid_cwd_map[pid] = initial_cwd
                        log.info(
                            f"Fetched initial CWD for new PID {pid}: {initial_cwd}"
                        )
            else:
                pid = tid
                tid_to_pid_map[tid] = pid
                log.warning(f"TID {tid} not found and process gone, assuming PID=TID.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
            pid = tid
            tid_to_pid_map[tid] = pid
            log.warning(f"Error looking up PID for TID {tid} ({e}), assuming PID=TID.")

    # --- Handle Process Lifecycle Syscalls ---
    if syscall_name == "exit_group":
        monitor.process_exit(pid, timestamp)
        # Clean up maps for the exiting process
        if tid == pid and tid in tid_to_pid_map:
            del tid_to_pid_map[tid]
        if pid in pid_cwd_map:
            del pid_cwd_map[pid]
        log.debug(f"Cleaned up maps for exiting PID {pid}")
        return

    if syscall_name in PROCESS_SYSCALLS and success:
        try:
            new_id = result_code  # new_id is the new TID/PID
            if new_id is not None and new_id > 0:
                if new_id not in tid_to_pid_map:
                    # Map new TID/PID to the *parent's* PID (process group)
                    tid_to_pid_map[new_id] = pid
                    log.info(
                        f"Syscall {syscall_name} by PID {pid}: Mapped new TID/PID {new_id} to process group PID {pid}"
                    )
                    # New thread/process inherits CWD from parent
                    parent_cwd = pid_cwd_map.get(pid)
                    if parent_cwd:
                        pid_cwd_map[new_id] = parent_cwd  # Assume new PID inherits CWD
                        log.debug(
                            f"Inherited CWD '{parent_cwd}' for new PID/TID {new_id} from parent {pid}"
                        )
                    else:
                        # Try fetching CWD for the new process directly if parent CWD unknown
                        new_cwd = pid_get_cwd(new_id)
                        if new_cwd:
                            pid_cwd_map[new_id] = new_cwd
                            log.info(
                                f"Fetched initial CWD for new PID/TID {new_id}: {new_cwd}"
                            )

        except Exception as map_e:
            log.error(f"Error updating maps for {syscall_name}: {map_e}")
        return  # No file operation for process creation

    # --- Process CWD Changes ---
    if syscall_name == "chdir" and success:
        new_cwd_path_arg = _clean_path_arg(args[0] if args else None)
        if new_cwd_path_arg:
            # chdir path can be relative, resolve it against *current* known CWD
            resolved_new_cwd = _resolve_path(pid, new_cwd_path_arg, pid_cwd_map)
            if resolved_new_cwd:
                pid_cwd_map[pid] = resolved_new_cwd
                log.info(f"PID {pid} changed CWD via chdir to: {resolved_new_cwd}")
                details["new_cwd"] = (
                    resolved_new_cwd  # Add to details for monitor history
                )
            else:
                log.warning(
                    f"Could not resolve chdir path '{new_cwd_path_arg}' for PID {pid}"
                )
        # Add chdir event to monitor history even if path resolution failed?
        # monitor.stat(pid, new_cwd_path_arg or "?", success, timestamp, **details) # Maybe?

    elif syscall_name == "fchdir" and success:
        fd_arg = _parse_result(str(args[0])) if args else None
        if fd_arg is not None:
            # Get the path associated with the FD
            target_path = monitor.get_path(pid, fd_arg)
            if target_path and os.path.isdir(
                target_path
            ):  # Ensure it's a directory path we know
                pid_cwd_map[pid] = target_path  # Assume target_path is absolute
                log.info(
                    f"PID {pid} changed CWD via fchdir(fd={fd_arg}) to: {target_path}"
                )
                details["new_cwd"] = target_path
            elif target_path:
                log.warning(
                    f"fchdir(fd={fd_arg}) target path '{target_path}' is not a known directory for PID {pid}."
                )
            else:
                log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}.")
        # Add fchdir event to monitor history?
        # monitor.stat(pid, target_path or f"fd={fd_arg}", success, timestamp, **details) # Maybe?

    # --- Process File-Related Syscalls ---
    try:
        # Populate common details
        if not success and error_name:
            details["error_name"] = error_name
        if (
            syscall_name in ["read", "pread64", "readv", "write", "pwrite64", "writev"]
            and success
            and result_code is not None
            and result_code >= 0
        ):
            details["bytes"] = result_code

        # --- Map Syscall to Monitor Method ---
        handler_method: Callable | None = None
        handler_args: tuple = ()

        # Resolve paths using the appropriate CWD now
        if syscall_name in ["open", "creat"]:
            path_arg = _clean_path_arg(args[0] if args else None)
            path = _resolve_path(pid, path_arg, pid_cwd_map)
            if path is not None:
                fd = result_code if success and result_code is not None else -1
                handler_method = monitor.open
                handler_args = (pid, path, fd, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name}, missing path: {event!r}")

        elif syscall_name == "openat":
            path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            # TODO: Handle dirfd properly using CWD map and FD map
            path = _resolve_path(pid, path_arg, pid_cwd_map)
            if path is not None:
                fd = result_code if success and result_code is not None else -1
                handler_method = monitor.open
                handler_args = (pid, path, fd, success, timestamp)
            else:
                log.warning(f"Skipping openat, missing path: {event!r}")

        elif syscall_name in ["read", "pread64", "readv"]:
            fd_arg = _parse_result(str(args[0])) if args else None
            if fd_arg is not None:
                fd = fd_arg
                handler_method = monitor.read
                handler_args = (pid, fd, None, success, timestamp)  # Pass path=None
            else:
                log.warning(f"Skipping {syscall_name}, invalid/missing fd: {event!r}")

        elif syscall_name in ["write", "pwrite64", "writev"]:
            fd_arg = _parse_result(str(args[0])) if args else None
            if fd_arg is not None:
                fd = fd_arg
                handler_method = monitor.write
                handler_args = (pid, fd, None, success, timestamp)  # Pass path=None
            else:
                log.warning(f"Skipping {syscall_name}, invalid/missing fd: {event!r}")

        elif syscall_name == "close":
            fd_arg = _parse_result(str(args[0])) if args else None
            if fd_arg is not None:
                fd = fd_arg
                handler_method = monitor.close
                handler_args = (pid, fd, success, timestamp)
            else:
                log.warning(f"Skipping close, invalid/missing fd: {event!r}")

        elif syscall_name in ["access", "stat", "lstat"]:
            path_arg = _clean_path_arg(args[0] if args else None)
            path = _resolve_path(pid, path_arg, pid_cwd_map)
            if path is not None:
                handler_method = monitor.stat
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name}, missing path: {event!r}")

        elif syscall_name == "newfstatat":
            path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            # TODO: Handle dirfd
            path = _resolve_path(pid, path_arg, pid_cwd_map)
            if path is not None:
                handler_method = monitor.stat
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping newfstatat, missing path: {event!r}")

        elif syscall_name in ["unlink", "rmdir"]:
            path_arg = _clean_path_arg(args[0] if args else None)
            path = _resolve_path(pid, path_arg, pid_cwd_map)
            if path is not None:
                handler_method = monitor.delete
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name}, missing path: {event!r}")

        elif syscall_name == "unlinkat":
            path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            # TODO: Handle dirfd
            path = _resolve_path(pid, path_arg, pid_cwd_map)
            if path is not None:
                handler_method = monitor.delete
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping unlinkat, missing path: {event!r}")

        elif syscall_name in ["rename"]:
            old_path_arg = _clean_path_arg(args[0] if args else None)
            new_path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            old_path = _resolve_path(pid, old_path_arg, pid_cwd_map)
            new_path = _resolve_path(pid, new_path_arg, pid_cwd_map)
            if old_path and new_path:
                handler_method = monitor.rename
                handler_args = (pid, old_path, new_path, success, timestamp)
            else:
                log.warning(f"Skipping rename, missing paths: {event!r}")

        elif syscall_name in ["renameat", "renameat2"]:
            old_path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            new_path_arg = _clean_path_arg(args[3] if len(args) > 3 else None)
            # TODO: Handle dirfds
            old_path = _resolve_path(pid, old_path_arg, pid_cwd_map)
            new_path = _resolve_path(pid, new_path_arg, pid_cwd_map)
            if old_path and new_path:
                handler_method = monitor.rename
                handler_args = (pid, old_path, new_path, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name}, missing paths: {event!r}")

        # --- Call Monitor Handler ---
        if handler_method:
            # Pass CWD details if relevant? Maybe not needed by monitor itself.
            # details["pid_cwd"] = pid_cwd_map.get(pid) # Example if needed
            handler_method(*handler_args, **details)
        else:
            # Log only if it's not a known process/exit/cwd syscall we handled
            if syscall_name not in PROCESS_SYSCALLS + EXIT_SYSCALLS + [
                "chdir",
                "fchdir",
            ]:
                log.debug(
                    f"No specific file handler implemented for syscall: {syscall_name}"
                )

    except Exception as e:
        log.exception(f"Error processing syscall event details: {event!r} - {e}")


# --- Public Interface Functions ---

AttachFuncType = Callable[[list[int], Monitor], None]
RunFuncType = Callable[[list[str], Monitor], None]


def attach(
    pids_or_tids: list[int], monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS
):
    """Attaches strace to existing PIDs/TIDs and processes events."""
    if not pids_or_tids:
        log.warning("attach called with no PIDs/TIDs.")
        return
    log.info(f"Attaching to PIDs/TIDs: {pids_or_tids}")

    # Initialize TID->PID and PID->CWD maps
    tid_to_pid_map: dict[int, int] = {}
    pid_cwd_map: dict[int, str] = {}
    initial_pids: set[int] = set()

    for tid in pids_or_tids:
        try:
            if psutil.pid_exists(tid):
                proc = psutil.Process(tid)
                pid = proc.pid
                tid_to_pid_map[tid] = pid
                initial_pids.add(pid)
                log.debug(f"Mapped initial TID {tid} to PID {pid}")
                # Get initial CWD for this process if not already fetched
                if pid not in pid_cwd_map:
                    cwd = pid_get_cwd(pid)
                    if cwd:
                        pid_cwd_map[pid] = cwd
                        log.info(f"Fetched initial CWD for PID {pid}: {cwd}")
            else:
                log.warning(f"Initial TID {tid} does not exist. Skipping initial map.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
            log.error(
                f"Error getting info for initial TID {tid}: {e}. TID will be mapped later if seen."
            )

    if not tid_to_pid_map:
        log.warning(
            "Could not map any initial TIDs. Attach might still work if PIDs exist."
        )

    # Ensure necessary syscalls are included
    combined_syscalls = sorted(
        list(
            set(syscalls)
            | set(PROCESS_SYSCALLS)
            | set(EXIT_SYSCALLS)
            | {"chdir", "fchdir"}
        )
    )
    log.info(f"Attaching with syscalls: {','.join(combined_syscalls)}")
    log.info(
        f"Starting attach loop (Initial PID mapping: {tid_to_pid_map}, Initial CWDs: {pid_cwd_map})..."
    )

    try:
        for event in parse_strace_stream(
            attach_ids=pids_or_tids, syscalls=combined_syscalls
        ):
            # Pass maps to be updated by the processor
            _process_syscall_event(event, monitor, tid_to_pid_map, pid_cwd_map)
    except KeyboardInterrupt:
        log.info("Attach interrupted by user.")
    except Exception as e:
        log.exception(f"Error during attach processing: {e}")
    finally:
        log.info("Attach finished.")


def run(command: list[str], monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS):
    """Launches a command via strace and processes events."""
    if not command:
        log.error("run called with empty command.")
        return
    log.info(f"Running command: {' '.join(shlex.quote(c) for c in command)}")

    # Initialize maps for run mode
    tid_to_pid_map: dict[int, int] = {}
    pid_cwd_map: dict[int, str] = {}
    # Initial CWD is alsof's CWD before the command starts
    # The first PID seen will likely be the main process, we can try to map its CWD then.
    try:
        initial_alsof_cwd = os.getcwd()
        log.info(f"alsof initial CWD: {initial_alsof_cwd}")
        # We don't know the initial PID yet, will set its CWD when first seen
    except OSError as e:
        log.error(f"Could not get alsof's initial CWD: {e}")
        initial_alsof_cwd = None

    log.info("Starting run loop...")
    try:
        combined_syscalls = sorted(
            list(
                set(syscalls)
                | set(PROCESS_SYSCALLS)
                | set(EXIT_SYSCALLS)
                | {"chdir", "fchdir"}
            )
        )
        log.info(f"Running with syscalls: {','.join(combined_syscalls)}")

        for event in parse_strace_stream(
            target_command=command, syscalls=combined_syscalls
        ):
            # Set initial CWD for the main process when first seen?
            # This assumes the first event's PID is the main one. Risky.
            # Better: Let the processor handle fetching CWD when a PID is first seen.
            # if not pid_cwd_map and event.pid not in pid_cwd_map and initial_alsof_cwd:
            #      pid_cwd_map[event.pid] = initial_alsof_cwd
            #      log.info(f"Set initial CWD for main PID {event.pid} to {initial_alsof_cwd}")

            # Pass maps to be updated by the processor
            _process_syscall_event(event, monitor, tid_to_pid_map, pid_cwd_map)
    except KeyboardInterrupt:
        log.info("Run interrupted by user.")
    except Exception as e:
        log.exception(f"Error during run processing: {e}")
    finally:
        log.info("Run finished.")


# --- Main Execution Function (for testing adapter) ---
def main(argv: list[str] | None = None) -> int:
    log_level = os.environ.get("LOGLEVEL", "INFO").upper()
    if log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        log_level = "INFO"
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s:%(name)s:%(message)s"
    )
    log.info(f"Log level set to {log_level}")

    parser = argparse.ArgumentParser(
        description="Strace adapter (Test): runs/attaches strace and updates Monitor state.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python3 -m alsof.strace -c find . -maxdepth 1\n"
        "  sudo python3 -m alsof.strace -p 1234",
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

    args = parser.parse_args(argv)
    target_command: list[str] | None = None
    attach_ids: list[int] | None = None
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
        for i, file_info in enumerate(tracked_files):
            print(f"{i+1}: {repr(file_info)}")
            if i > 20:  # Limit output for test
                print("...")
                break
        log.info("------------------------------------------")
        return 0

    except (ValueError, FileNotFoundError, RuntimeError) as e:
        log.error(f"Execution failed: {e}")
        return 1
    except KeyboardInterrupt:
        log.info("\nCtrl+C detected in main.")
        return 130  # Standard exit code for Ctrl+C
    except Exception as e:
        log.exception(f"An unexpected error occurred in main: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
