# Filename: strace.py

import argparse
import logging
import os
import shlex
import sys
from collections.abc import Callable, Iterator  # Use collections.abc

import psutil

# Assuming these are correctly defined in strace_cmd
from lsoph.backend.strace_cmd import (
    DEFAULT_SYSCALLS,
    EXIT_SYSCALLS,
    PROCESS_SYSCALLS,
    Syscall,
    parse_strace_stream,
)
from lsoph.monitor import Monitor

# Assuming this utility exists and works
from lsoph.util.pid import get_cwd as pid_get_cwd

log = logging.getLogger("lsoph.strace")

# --- Helper Functions ---


def _parse_result(result_str: str) -> int | None:
    """Parses strace result string (dec/hex/?), returns integer or None."""
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)
    except ValueError:
        log.warning(f"Could not parse result string: '{result_str}'")
        return None


def _clean_path_arg(path_arg: any) -> str | None:
    """Cleans a potential path argument (removes quotes, handles basic escapes)."""
    if not isinstance(path_arg, str) or not path_arg:
        return None
    path = path_arg
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    try:
        path = path.encode("utf-8", "surrogateescape").decode("unicode_escape")
    except UnicodeDecodeError:
        log.debug(f"Failed unicode_escape decoding path: {path_arg}, using raw.")
    except Exception as e:
        log.warning(f"Unexpected error decoding path '{path_arg}': {e}, using raw.")
    return path


def _resolve_path(
    pid: int, path: str | None, cwd_map: dict[int, str], dirfd: int | str | None = None
) -> str | None:
    """
    Converts a potentially relative path to absolute, using the process's
    tracked CWD if available or dirfd if implemented. Returns original path on failure.
    """
    log.debug(
        f"_resolve_path called: pid={pid}, path='{path}', cwd_map has pid={pid in cwd_map}, dirfd='{dirfd}' (type: {type(dirfd)})"
    )

    if path is None:
        return None
    if (path.startswith("<") and path.endswith(">")) or path.startswith("@"):
        return path

    base_dir = None
    using_dirfd = False

    # --- Handle dirfd ---
    if dirfd is not None:
        using_dirfd = True
        if isinstance(dirfd, str) and dirfd.upper() == "AT_FDCWD":
            base_dir = cwd_map.get(pid)
            log.debug(f"dirfd is AT_FDCWD, using base_dir from cwd_map: '{base_dir}'")
        elif isinstance(dirfd, int) and dirfd >= 0:
            # TODO: Implement proper dirfd lookup using monitor's fd->path map for the pid
            log.warning(
                f"Numeric dirfd={dirfd} handling not implemented. Path resolution might be incorrect. Falling back to CWD for base."
            )
            base_dir = cwd_map.get(pid)
        else:
            log.warning(
                f"Unhandled or invalid dirfd type/value: {dirfd!r}. Falling back to CWD for base."
            )
            base_dir = cwd_map.get(pid)

    # If path is absolute, return it directly.
    if os.path.isabs(path):
        if using_dirfd:
            log.debug(
                f"Path '{path}' is absolute, but dirfd='{dirfd}' was specified. Returning absolute path directly."
            )
        else:
            log.debug(f"Path '{path}' is absolute, returning directly.")
        return path

    # --- Attempt resolution using base_dir (derived from CWD or dirfd fallback) ---
    if base_dir is None and not using_dirfd:
        base_dir = cwd_map.get(pid)
        log.debug(f"No dirfd specified, using base_dir from cwd_map: '{base_dir}'")

    if base_dir:
        try:
            # Attempt to join the base directory (likely the process's CWD) with the relative path
            abs_path = os.path.normpath(os.path.join(base_dir, path))
            log.debug(
                f"Resolved relative path '{path}' using base '{base_dir}' -> '{abs_path}'"
            )
            return abs_path
        except Exception as e:
            # Log if joining fails for some reason
            log.warning(f"Error joining path '{path}' with base_dir '{base_dir}': {e}")
            # Fall through to returning original path

    # --- Fallback: Base directory unknown or join failed ---
    log.warning(
        f"Could not determine base directory for PID {pid} or join failed. Returning original path '{path}'"
    )
    return path  # Return the original path as we cannot reliably resolve it


def _parse_dirfd(dirfd_arg: str | None) -> int | str | None:
    """Parses the dirfd argument string from strace output."""
    if dirfd_arg is None:
        return None
    if isinstance(dirfd_arg, str) and dirfd_arg.upper() == "AT_FDCWD":
        return "AT_FDCWD"
    try:
        return int(str(dirfd_arg), 0)
    except ValueError:
        log.warning(
            f"Could not parse dirfd argument as int after checking for AT_FDCWD: '{dirfd_arg}'"
        )
        return None


# --- Core Event Processing Logic ---
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
    old_path: str | None = None
    new_path: str | None = None
    fd: int | None = None
    details: dict[str, any] = {}
    success = error_name is None
    result_code = _parse_result(result_str)
    dirfd: int | str | None = None
    pid = tid_to_pid_map.get(tid)
    if pid is None:
        try:
            if psutil.pid_exists(tid):
                proc_info = psutil.Process(tid)
                pid = proc_info.pid
                tid_to_pid_map[tid] = pid
                log.debug(f"Looked up PID {pid} for unmapped TID {tid}")
                if pid not in pid_cwd_map:
                    initial_cwd = pid_get_cwd(pid)
                if initial_cwd:
                    pid_cwd_map[pid] = initial_cwd
                    log.info(f"Fetched initial CWD for new PID {pid}: {initial_cwd}")
            else:
                pid = tid
                tid_to_pid_map[tid] = pid
                log.warning(f"TID {tid} not found and process gone, assuming PID=TID.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
            pid = tid
            tid_to_pid_map[tid] = pid
            log.warning(f"Error looking up PID for TID {tid} ({e}), assuming PID=TID.")
    if syscall_name == "exit_group":
        monitor.process_exit(pid, timestamp)
        if tid == pid and tid in tid_to_pid_map:
            del tid_to_pid_map[tid]
        if pid in pid_cwd_map:
            del pid_cwd_map[pid]
        log.debug(f"Cleaned up maps for exiting PID {pid}")
        return
    if syscall_name in PROCESS_SYSCALLS and success:
        try:
            new_id = result_code
            if new_id is not None and new_id > 0:
                if new_id not in tid_to_pid_map:
                    tid_to_pid_map[new_id] = pid
                    log.info(
                        f"Syscall {syscall_name} by PID {pid}: Mapped new TID/PID {new_id} to process group PID {pid}"
                    )
                    parent_cwd = pid_cwd_map.get(pid)
                    if parent_cwd:
                        pid_cwd_map[new_id] = parent_cwd
                        log.debug(
                            f"Inherited CWD '{parent_cwd}' for new PID/TID {new_id} from parent {pid}"
                        )
                    else:
                        new_cwd = pid_get_cwd(new_id)
                    if new_cwd:
                        pid_cwd_map[new_id] = new_cwd
                        log.info(
                            f"Fetched initial CWD for new PID/TID {new_id}: {new_cwd}"
                        )
        except Exception as map_e:
            log.error(f"Error updating maps for {syscall_name}: {map_e}")
        return
    if syscall_name == "chdir" and success:
        new_cwd_path_arg = _clean_path_arg(args[0] if args else None)
        if new_cwd_path_arg:
            resolved_new_cwd = _resolve_path(pid, new_cwd_path_arg, pid_cwd_map)
        if resolved_new_cwd:
            pid_cwd_map[pid] = resolved_new_cwd
            log.info(f"PID {pid} changed CWD via chdir to: {resolved_new_cwd}")
            details["new_cwd"] = resolved_new_cwd
        else:
            log.warning(
                f"Could not resolve chdir path '{new_cwd_path_arg}' for PID {pid}"
            )
    elif syscall_name == "fchdir" and success:
        fd_arg = _parse_result(str(args[0])) if args else None
        if fd_arg is not None:
            target_path = monitor.get_path(pid, fd_arg)
        if target_path and os.path.isdir(target_path):
            pid_cwd_map[pid] = target_path
            log.info(f"PID {pid} changed CWD via fchdir(fd={fd_arg}) to: {target_path}")
            details["new_cwd"] = target_path
        elif target_path:
            log.warning(
                f"fchdir(fd={fd_arg}) target path '{target_path}' is not a known directory for PID {pid}."
            )
        else:
            log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}.")
    try:
        if not success and error_name:
            details["error_name"] = error_name
        if (
            syscall_name in ["read", "pread64", "readv", "write", "pwrite64", "writev"]
            and success
            and result_code is not None
            and result_code >= 0
        ):
            details["bytes"] = result_code
        handler_method: Callable | None = None
        handler_args: tuple = ()

        # Map Syscall to Monitor Method (with correct indentation)
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
            dirfd_arg = args[0] if args else None
            path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            log.debug(
                f"Processing openat: dirfd_arg='{dirfd_arg}', path_arg='{path_arg}'"
            )
            dirfd = _parse_dirfd(dirfd_arg)
            path = _resolve_path(pid, path_arg, pid_cwd_map, dirfd=dirfd)
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
                handler_args = (pid, fd, None, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name}, invalid/missing fd: {event!r}")

        elif syscall_name in ["write", "pwrite64", "writev"]:
            fd_arg = _parse_result(str(args[0])) if args else None
            if fd_arg is not None:
                fd = fd_arg
                handler_method = monitor.write
                handler_args = (pid, fd, None, success, timestamp)
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
            dirfd_arg = args[0] if args else None
            path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            log.debug(
                f"Processing newfstatat: dirfd_arg='{dirfd_arg}', path_arg='{path_arg}'"
            )
            dirfd = _parse_dirfd(dirfd_arg)
            path = _resolve_path(pid, path_arg, pid_cwd_map, dirfd=dirfd)
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
            dirfd_arg = args[0] if args else None
            path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            log.debug(
                f"Processing unlinkat: dirfd_arg='{dirfd_arg}', path_arg='{path_arg}'"
            )
            dirfd = _parse_dirfd(dirfd_arg)
            path = _resolve_path(pid, path_arg, pid_cwd_map, dirfd=dirfd)
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
            old_dirfd_arg = args[0] if args else None
            old_path_arg = _clean_path_arg(args[1] if len(args) > 1 else None)
            new_dirfd_arg = args[2] if len(args) > 2 else None
            new_path_arg = _clean_path_arg(args[3] if len(args) > 3 else None)
            log.debug(
                f"Processing {syscall_name}: old_dirfd='{old_dirfd_arg}', old_path='{old_path_arg}', new_dirfd='{new_dirfd_arg}', new_path='{new_path_arg}'"
            )
            old_dirfd = _parse_dirfd(old_dirfd_arg)
            new_dirfd = _parse_dirfd(new_dirfd_arg)
            old_path = _resolve_path(pid, old_path_arg, pid_cwd_map, dirfd=old_dirfd)
            new_path = _resolve_path(pid, new_path_arg, pid_cwd_map, dirfd=new_dirfd)
            if old_path and new_path:
                handler_method = monitor.rename
                handler_args = (pid, old_path, new_path, success, timestamp)
            else:
                log.warning(f"Skipping {syscall_name}, missing paths: {event!r}")

        # Call Monitor Handler
        if handler_method:
            handler_method(*handler_args, **details)
        else:
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
            monitor=monitor, attach_ids=pids_or_tids, syscalls=combined_syscalls
        ):
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
    tid_to_pid_map: dict[int, int] = {}
    pid_cwd_map: dict[int, str] = {}
    try:
        initial_lsoph_cwd = os.getcwd()
        log.info(f"lsoph initial CWD: {initial_lsoph_cwd}")
    except OSError as e:
        log.error(f"Could not get lsoph's initial CWD: {e}")
        initial_lsoph_cwd = None
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
            monitor=monitor, target_command=command, syscalls=combined_syscalls
        ):
            _process_syscall_event(event, monitor, tid_to_pid_map, pid_cwd_map)
    except KeyboardInterrupt:
        log.info("Run interrupted by user.")
    except Exception as e:
        log.exception(f"Error during run processing: {e}")
    finally:
        log.info("Run finished.")


# --- Main Execution Function (for testing) ---
def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for testing strace adapter."""
    parser = argparse.ArgumentParser(
        description="Strace adapter (Test): runs/attaches strace and updates Monitor state.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 -m lsoph.strace -c find . -maxdepth 1\n  sudo python3 -m lsoph.strace -p 1234",
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
    log.info(f"Log level set to {log_level}")

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
        # Should be unreachable due to mutually_exclusive_group(required=True)
        log.critical("Internal error: Must provide either -c or -p.")
        parser.print_usage(sys.stderr)
        return 1

    if os.geteuid() != 0:
        log.warning("Running without root. strace/psutil may fail or lack permissions.")

    monitor = Monitor(identifier=monitor_id)

    # --- Corrected try block from artifact lsoph_strace_backend_main_fix ---
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
            # This loop prints the results when run standalone
            for i, file_info in enumerate(tracked_files):
                print(f"{i+1}: {repr(file_info)}")
                # Limit output for testing clarity
                if i >= 20:  # Check if we've printed 21 items (0-20)
                    print("...")
                    break  # Stop printing more items

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
    # --- End of corrected try block ---


if __name__ == "__main__":
    sys.exit(main())
