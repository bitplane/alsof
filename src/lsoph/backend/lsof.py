import logging
import os
import re
import subprocess
import time
from typing import Dict, Iterator, List, Optional, Set, Tuple

from lsoph.monitor import Monitor
from lsoph.util.pid import get_descendants

# Setup logging - using the same pattern as other modules
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("lsoph.backend.lsof")  # Use package-aware logger name

# Regular expressions for parsing lsof output
# Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
LSOF_LINE_RE = re.compile(
    r"^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$"
)
FD_TYPE_RE = re.compile(r"(\d+)([rwu])?")


def _parse_fd(fd_str: str) -> Tuple[Optional[int], str]:
    """Parse the FD column from lsof output."""
    if fd_str in ("cwd", "rtd", "txt", "mem"):
        log.debug(f"Special FD type: {fd_str}")
        return None, fd_str

    match = FD_TYPE_RE.match(fd_str)
    if match:
        fd = int(match.group(1))
        mode = match.group(2) or ""
        log.debug(f"Parsed FD {fd} with mode '{mode}'")
        return fd, mode

    log.debug(f"Unparsable FD string: {fd_str}")
    return None, fd_str


def _run_lsof(pids: Optional[List[int]] = None) -> Iterator[Dict]:
    """Run lsof and yield parsed output lines."""
    cmd = ["lsof", "-n", "-F", "pcftn"]  # p=pid, c=command, f=fd, t=type, n=name

    if pids:
        cmd.extend(["-p", ",".join(map(str, pids))])

    log.info(f"Running lsof command: {' '.join(cmd)}")

    try:
        # Redirect stderr to /dev/null to suppress tracefs warnings
        with open(os.devnull, "w") as devnull:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=devnull, text=True
            )

        current_record = {}
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            field_type = line[0]
            value = line[1:]

            if field_type == "p" and current_record:
                # New process, yield previous record
                yield current_record
                current_record = {"pid": int(value)}
            elif field_type == "p":
                current_record = {"pid": int(value)}
            elif field_type == "c":
                current_record["command"] = value
            elif field_type == "f":
                current_record["fd_str"] = value
                fd, mode = _parse_fd(value)
                current_record["fd"] = fd
                current_record["mode"] = mode
            elif field_type == "t":
                current_record["type"] = value
            elif field_type == "n":
                current_record["path"] = value
                log.debug(
                    f"Complete record: PID {current_record.get('pid')}, FD {current_record.get('fd')}, path {value}"
                )
                yield current_record
                current_record = {
                    "pid": current_record["pid"],
                    "command": current_record["command"],
                }

        # Yield final record if any
        if current_record and "path" in current_record:
            log.debug(f"Final record: {current_record}")
            yield current_record

    except subprocess.SubprocessError as e:
        log.error(f"Error running lsof: {e}")
    except Exception as e:
        log.exception(f"Unexpected error in _run_lsof: {e}")
    finally:
        if proc.stdout:
            proc.stdout.close()
        exit_code = proc.wait()
        log.debug(f"lsof process exited with code: {exit_code}")


def _process_lsof_data(record: Dict, monitor: Monitor, timestamp: float) -> None:
    """Process a parsed lsof record and update the monitor."""
    pid = record.get("pid")
    path = record.get("path")
    fd = record.get("fd")

    if not (pid and path):
        log.debug(f"Incomplete record missing pid or path: {record}")
        return

    # If fd is None, this is a special file like cwd, not an open fd
    if fd is None:
        fd_str = record.get("fd_str", "unknown")
        log.debug(f"Special file {fd_str} for PID {pid}: {path}")
        monitor.stat(pid, path, True, timestamp)
        return

    # For regular files, add as open
    log.debug(f"Processing open file: PID {pid}, FD {fd}, path {path}")
    monitor.open(pid, path, fd, True, timestamp)

    # Check mode to determine if it's being read/written
    mode = record.get("mode", "")
    if "r" in mode:
        log.debug(f"File has read mode: PID {pid}, FD {fd}")
        monitor.read(pid, fd, path, True, timestamp)
    if "w" in mode:
        log.debug(f"File has write mode: PID {pid}, FD {fd}")
        monitor.write(pid, fd, path, True, timestamp)


def _attach_with_descendants(pids: List[int], monitor: Monitor) -> None:
    """
    Attach to processes, their descendants, and monitor their open files using lsof.
    This version tracks child processes by periodically checking for descendants.
    """
    log.info(f"Attaching to initial PIDs: {pids}")

    # Keep track of all PIDs we're monitoring (including descendants)
    all_pids = set(pids)

    # Keep track of file descriptors we've seen for each PID
    # to detect closures on subsequent runs
    seen_fds: Dict[int, Set[Tuple[int, str]]] = {}

    try:
        poll_interval = 1.0  # seconds
        child_check_interval = 5.0  # check for new children every 5 polls
        poll_count = 0

        log.info(f"Starting lsof polling with interval: {poll_interval} seconds")

        while True:
            timestamp = time.time()
            poll_count += 1

            # Check for descendants periodically
            if poll_count % child_check_interval < 1:
                log.debug(f"Checking for new child processes of {pids}")
                new_pids = set()
                for parent_pid in pids:
                    try:
                        descendants = get_descendants(parent_pid)
                        for child_pid in descendants:
                            if child_pid not in all_pids:
                                log.info(f"Found new child process: {child_pid}")
                                new_pids.add(child_pid)
                    except Exception as e:
                        log.debug(
                            f"Error checking descendants for PID {parent_pid}: {e}"
                        )

                # Add any new PIDs to our tracking set
                if new_pids:
                    log.info(
                        f"Adding {len(new_pids)} new child processes to monitoring"
                    )
                    all_pids.update(new_pids)

            # Convert set back to list for lsof
            current_pids = list(all_pids)
            current_fds: Dict[int, Set[Tuple[int, str]]] = {}

            record_count = 0
            for record in _run_lsof(current_pids):
                record_count += 1
                pid = record.get("pid")
                fd = record.get("fd")
                path = record.get("path")

                if pid and fd is not None and path:
                    if pid not in current_fds:
                        current_fds[pid] = set()
                    current_fds[pid].add((fd, path))

                _process_lsof_data(record, monitor, timestamp)

            log.debug(f"Processed {record_count} lsof records")

            # Detect closed files (present in seen_fds but not in current_fds)
            close_count = 0
            for pid, fd_paths in seen_fds.items():
                current_pid_fds = current_fds.get(pid, set())
                for fd, path in fd_paths:
                    if (fd, path) not in current_pid_fds:
                        log.debug(
                            f"Detected closed file: PID {pid}, FD {fd}, path {path}"
                        )
                        monitor.close(pid, fd, True, timestamp)
                        close_count += 1

            if close_count > 0:
                log.debug(f"Detected {close_count} closed files")

            seen_fds = current_fds
            log.debug(f"Sleeping for {poll_interval} seconds")
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        log.info("lsof monitoring interrupted by user")
    except Exception as e:
        log.exception(f"Unexpected error in lsof attach: {e}")


def attach(pids: List[int], monitor: Monitor) -> None:
    """
    Standard attach function which monitors the specified PIDs without tracking descendants.
    For command execution with descendants tracking, use _attach_with_descendants.
    """
    log.info(f"Attaching to PIDs: {pids}")

    # Keep track of file descriptors we've seen for each PID
    # to detect closures on subsequent runs
    seen_fds: Dict[int, Set[Tuple[int, str]]] = {}

    try:
        poll_interval = 1.0  # seconds
        log.info(f"Starting lsof polling with interval: {poll_interval} seconds")

        while True:
            timestamp = time.time()
            current_fds: Dict[int, Set[Tuple[int, str]]] = {}

            record_count = 0
            for record in _run_lsof(pids):
                record_count += 1
                pid = record.get("pid")
                fd = record.get("fd")
                path = record.get("path")

                if pid and fd is not None and path:
                    if pid not in current_fds:
                        current_fds[pid] = set()
                    current_fds[pid].add((fd, path))

                _process_lsof_data(record, monitor, timestamp)

            log.debug(f"Processed {record_count} lsof records")

            # Detect closed files (present in seen_fds but not in current_fds)
            close_count = 0
            for pid, fd_paths in seen_fds.items():
                current_pid_fds = current_fds.get(pid, set())
                for fd, path in fd_paths:
                    if (fd, path) not in current_pid_fds:
                        log.debug(
                            f"Detected closed file: PID {pid}, FD {fd}, path {path}"
                        )
                        monitor.close(pid, fd, True, timestamp)
                        close_count += 1

            if close_count > 0:
                log.debug(f"Detected {close_count} closed files")

            seen_fds = current_fds
            log.debug(f"Sleeping for {poll_interval} seconds")
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        log.info("lsof monitoring interrupted by user")
    except Exception as e:
        log.exception(f"Unexpected error in lsof attach: {e}")


def run(command: List[str], monitor: Monitor) -> None:
    """Run a command and monitor its open files using lsof."""
    log.info(f"Running command: {' '.join(command)}")

    proc = None
    try:
        log.debug("Launching subprocess")
        proc = subprocess.Popen(command)
        pid = proc.pid
        log.info(f"Command started with PID: {pid}")

        # Track the parent process and all its descendants
        pids = [pid]
        # Use a custom attach function to track descendants
        _attach_with_descendants(pids, monitor)

    except subprocess.SubprocessError as e:
        log.error(f"Error launching command: {e}")
    except Exception as e:
        log.exception(f"Unexpected error in lsof run: {e}")
    finally:
        if proc and proc.poll() is None:
            log.info(f"Terminating command process (PID: {proc.pid})")
            proc.terminate()
            try:
                proc.wait(timeout=1)
                log.debug(
                    f"Process terminated gracefully with exit code: {proc.returncode}"
                )
            except subprocess.TimeoutExpired:
                log.debug(
                    f"Process did not terminate gracefully, killing PID {proc.pid}"
                )
                proc.kill()
                proc.wait()
                log.debug(f"Process killed with exit code: {proc.returncode}")
