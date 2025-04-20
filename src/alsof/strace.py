# Filename: strace.py

import argparse
import logging
import os
import shlex
import sys
from typing import (  # Added missing imports
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)

import psutil

# Modules from our package
# Assumes monitor.py, strace_cmd.py, versioned.py are importable
from alsof.monitor import Monitor
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


def _parse_result(result_str: str) -> Optional[int]:
    """Parses strace result string (dec/hex) into an integer."""
    if not result_str:
        return None
    try:
        return int(result_str, 0)  # Use base 0 to auto-detect hex/dec/oct
    except ValueError:
        log.warning(f"Could not parse result string: '{result_str}'")
        return None


def _clean_path_arg(path_arg: Any) -> Optional[str]:
    """Cleans a potential path argument (removes quotes, unescapes)."""
    if not isinstance(path_arg, str) or not path_arg:
        return None
    path = path_arg
    # Remove surrounding quotes if present
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        try:
            # Decode common escapes
            path = path[1:-1].encode("utf-8").decode("unicode_escape")
        except Exception:
            path = path[1:-1]  # Use raw content if unescaping fails
    return path


# --- Core Event Processing Logic ---


def _process_syscall_event(
    event: Syscall, monitor: Monitor, tid_to_pid_map: Dict[int, int]
):
    """
    Processes a single Syscall event, updates the tid->pid map,
    resolves paths, and calls the appropriate method on the Monitor object.
    """
    tid = event.tid  # TID from strace line
    syscall_name = event.syscall
    args = event.args  # List[str] of raw args from state machine parser
    result_str = event.result_str
    error_name = event.error_name
    timestamp = event.timestamp

    path: Optional[str] = None
    fd: Optional[int] = None
    details: Dict[str, Any] = {}
    success = error_name is None
    result_code = _parse_result(result_str)

    # --- Determine PID (TGID) ---
    pid = tid_to_pid_map.get(tid)
    if pid is None:
        # If TID not in map, assume it's a main thread (TID=PID)
        # or we missed its creation (attach mode to non-main thread?)
        # Defaulting TID=PID is usually correct for the initial process
        # and clone/fork handling should catch descendants.
        pid = tid
        tid_to_pid_map[tid] = pid
        log.debug(f"TID {tid} not in map, assuming PID=TID.")
        # TODO: Consider optional psutil lookup here if robustness is critical
    # --- End PID Lookup ---

    # --- Update map on clone/fork success ---
    # Needs to happen *before* calling handlers
    if syscall_name in PROCESS_SYSCALLS and success:
        try:
            new_id = result_code
            if new_id is not None and new_id > 0:  # Parent context receiving child ID
                # Map the new child TID/PID to the *current* process's PID (TGID)
                if new_id not in tid_to_pid_map:
                    tid_to_pid_map[new_id] = pid
                    log.info(
                        f"Syscall {syscall_name}: Mapped new TID/PID {new_id} to parent PID {pid}"
                    )
        except Exception as map_e:
            log.error(f"Error updating TID map for {syscall_name}: {map_e}")
    # --- End Map Update ---

    # --- Extract Path/FD and Call Monitor Handler ---
    try:
        # Prepare details dict
        if not success and error_name:
            details["error_name"] = error_name
        if (
            syscall_name in ["read", "pread64", "readv", "write", "pwrite64", "writev"]
            and success
            and result_code is not None
        ):
            if result_code >= 0:
                details["bytes"] = result_code

        # --- Map syscall to Monitor method ---
        handler_method = None
        handler_args: Tuple = ()

        if syscall_name in ["open", "creat"]:
            path = _clean_path_arg(args[0] if len(args) > 0 else None)
            if path is not None and result_code is not None:
                fd = result_code if success else -1
                handler_method = monitor.open
                handler_args = (pid, path, fd, success, timestamp)
            else:
                log.warning(
                    f"Skipping {syscall_name} event, missing path or result: {event!r}"
                )

        elif syscall_name == "openat":
            path = _clean_path_arg(args[1] if len(args) > 1 else None)
            if path is not None and result_code is not None:
                fd = result_code if success else -1
                handler_method = monitor.open
                handler_args = (pid, path, fd, success, timestamp)
            else:
                log.warning(f"Skipping openat event, missing path or result: {event!r}")

        elif syscall_name in ["read", "pread64", "readv"]:
            if len(args) > 0:
                fd = _parse_result(str(args[0]))
            if fd is not None:
                path = monitor.get_path(pid, fd)  # Resolve path using monitor's cache
                handler_method = monitor.read
                handler_args = (pid, fd, path, success, timestamp)
            else:
                log.warning(f"Skipping read event, missing fd: {event!r}")

        elif syscall_name in ["write", "pwrite64", "writev"]:
            if len(args) > 0:
                fd = _parse_result(str(args[0]))
            if fd is not None:
                path = monitor.get_path(pid, fd)  # Resolve path using monitor's cache
                handler_method = monitor.write
                handler_args = (pid, fd, path, success, timestamp)
            else:
                log.warning(f"Skipping write event, missing fd: {event!r}")

        elif syscall_name == "close":
            if len(args) > 0:
                fd = _parse_result(str(args[0]))
            if fd is not None:
                handler_method = monitor.close
                handler_args = (pid, fd, success, timestamp)
            else:
                log.warning(f"Skipping close event, missing fd: {event!r}")

        elif syscall_name in ["access", "stat", "lstat"]:
            path = _clean_path_arg(args[0] if len(args) > 0 else None)
            if path is not None:
                handler_method = monitor.stat
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name} event, missing path: {event!r}")

        elif syscall_name == "newfstatat":
            path = _clean_path_arg(args[1] if len(args) > 1 else None)
            if path is not None:
                handler_method = monitor.stat
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping newfstatat event, missing path: {event!r}")

        elif syscall_name in ["unlink"]:
            path = _clean_path_arg(args[0] if len(args) > 0 else None)
            if path is not None:
                handler_method = monitor.delete
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping unlink event, missing path: {event!r}")

        elif syscall_name == "unlinkat":
            path = _clean_path_arg(args[1] if len(args) > 1 else None)
            if path is not None:
                handler_method = monitor.delete
                handler_args = (pid, path, success, timestamp)
            else:
                log.warning(f"Skipping unlinkat event, missing path: {event!r}")

        elif syscall_name in ["rename"]:
            old_path = _clean_path_arg(args[0] if len(args) > 0 else None)
            new_path = _clean_path_arg(args[1] if len(args) > 1 else None)
            if old_path and new_path:
                handler_method = monitor.rename
                handler_args = (pid, old_path, new_path, success, timestamp)
            else:
                log.warning(f"Skipping rename event, missing paths: {event!r}")

        elif syscall_name in ["renameat"]:
            old_path = _clean_path_arg(args[1] if len(args) > 1 else None)
            new_path = _clean_path_arg(args[3] if len(args) > 3 else None)
            if old_path and new_path:
                handler_method = monitor.rename
                handler_args = (pid, old_path, new_path, success, timestamp)
            else:
                log.warning(f"Skipping renameat event, missing paths: {event!r}")

        # Call the handler if found
        if handler_method:
            handler_method(*handler_args, **details)
        elif syscall_name not in PROCESS_SYSCALLS:
            log.debug(f"No specific file handler for syscall: {syscall_name}")

    except Exception as e:
        log.exception(f"Error processing syscall event: {event!r} - {e}")


# --- Public Interface Functions ---

# Type hint for attach function
AttachFuncType = Callable[[List[int], Monitor], None]
# Type hint for run function
RunFuncType = Callable[[List[str], Monitor], None]


def attach(
    pids_or_tids: List[int], monitor: Monitor, syscalls: List[str] = DEFAULT_SYSCALLS
):
    """
    Attaches strace to existing PIDs/TIDs and processes events, updating the Monitor state.
    """
    if not pids_or_tids:
        log.warning("attach called with no PIDs/TIDs.")
        return

    log.info(f"Attaching to PIDs/TIDs: {pids_or_tids}")
    tid_to_pid_map: Dict[int, int] = {}

    # Pre-populate map using psutil
    log.info(f"Pre-populating TID->PID map for attach IDs: {pids_or_tids}")
    initial_pids = set()
    for initial_tid in pids_or_tids:
        try:
            if not psutil.pid_exists(initial_tid):
                log.warning(f"Initial TID {initial_tid} does not exist. Skipping.")
                continue
            proc_info = psutil.Process(initial_tid)
            pid = proc_info.pid  # Get TGID
            tid_to_pid_map[initial_tid] = pid
            initial_pids.add(pid)
            log.debug(f"Mapped initial TID {initial_tid} to PID {pid}")
        except psutil.NoSuchProcess:
            log.warning(
                f"Process/Thread with TID {initial_tid} disappeared during initial mapping."
            )
        except psutil.AccessDenied:
            log.warning(
                f"Access denied getting PID for initial TID {initial_tid}. Mapping might be incomplete."
            )
        except Exception as e:
            log.error(f"Error getting PID for initial TID {initial_tid}: {e}")

    if not tid_to_pid_map:
        log.error("Could not map any initial TIDs to PIDs. Aborting attach.")
        return

    log.info(
        f"Starting event processing loop for attached PIDs/TIDs (maps to PIDs: {list(initial_pids)})..."
    )
    try:
        # Ensure process syscalls are traced for TID->PID mapping
        combined_syscalls = sorted(list(set(syscalls) | set(PROCESS_SYSCALLS)))
        for syscall_event in parse_strace_stream(
            attach_ids=pids_or_tids, syscalls=combined_syscalls
        ):
            _process_syscall_event(syscall_event, monitor, tid_to_pid_map)
    except KeyboardInterrupt:
        log.info("Attach interrupted by user.")
    except Exception as e:
        log.exception(f"Error during attach event processing: {e}")
    finally:
        log.info("Attach processing finished.")


def run(command: List[str], monitor: Monitor, syscalls: List[str] = DEFAULT_SYSCALLS):
    """
    Launches a command via strace and processes events, updating the Monitor state.
    """
    if not command:
        log.error("run called with empty command.")
        return

    log.info(f"Running command: {' '.join(shlex.quote(c) for c in command)}")
    tid_to_pid_map: Dict[int, int] = {}  # Starts empty, populated by clone/fork

    log.info("Starting event processing loop for launched command...")
    try:
        # Ensure process syscalls are traced for TID->PID mapping
        combined_syscalls = sorted(list(set(syscalls) | set(PROCESS_SYSCALLS)))
        for syscall_event in parse_strace_stream(
            target_command=command, syscalls=combined_syscalls
        ):
            _process_syscall_event(syscall_event, monitor, tid_to_pid_map)
    except KeyboardInterrupt:
        log.info("Run interrupted by user.")
    except Exception as e:
        log.exception(f"Error during run event processing: {e}")
    finally:
        log.info("Run processing finished.")


# --- Main Execution Function (for testing adapter) ---
def main(argv: Optional[List[str]] = None) -> int:
    # Keep main for testing the adapter directly if needed
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
        "  # Assumes monitor.py and strace_cmd.py are importable\n"
        "  python3 %(prog)s -c find . -maxdepth 1\n"
        "  sudo python3 %(prog)s -p 1234",
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
        log.critical("Must provide either -c or -p.")
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
            if i > 20:
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
    # This allows testing the adapter logic directly
    sys.exit(main())
