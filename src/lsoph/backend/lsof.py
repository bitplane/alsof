# Filename: src/lsoph/backend/lsof.py
import logging
import os
import re
import subprocess
import time
from typing import Dict, Iterator, List, Optional, Set, Tuple

from lsoph.monitor import Monitor
from lsoph.util.pid import get_descendants

# Setup logging
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("lsoph.backend.lsof")

# --- Constants ---
DEFAULT_LSOF_POLL_INTERVAL = 1.0  # seconds
CHILD_CHECK_INTERVAL_MULTIPLIER = 5  # Check for children every N polls

# --- Regular Expressions ---
# Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (Original, not used with -F)
# LSOF_LINE_RE = re.compile(
#     r"^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$"
# )
FD_TYPE_RE = re.compile(r"(\d+)([rwu])?")


# --- Parsing Logic ---


def _parse_fd(fd_str: str) -> Tuple[Optional[int], str]:
    """Parse the FD column from lsof output (field 'f')."""
    # Handle special file descriptors like current working directory, root directory,
    # program text (code and data), and memory-mapped files.
    if fd_str in ("cwd", "rtd", "txt", "mem"):
        log.debug(f"Special FD type: {fd_str}")
        return None, fd_str  # Return None for FD number, and the string identifier

    # Attempt to match numeric file descriptors possibly followed by access mode (r, w, u)
    match = FD_TYPE_RE.match(fd_str)
    if match:
        fd = int(match.group(1))  # Extract the numeric file descriptor
        mode = match.group(2) or ""  # Extract the mode (r, w, u) or default to empty
        log.debug(f"Parsed FD {fd} with mode '{mode}'")
        return fd, mode

    # Log if the FD string doesn't match known patterns
    log.debug(f"Unparsable FD string: {fd_str}")
    return None, fd_str  # Return None for FD number, and the original string


def _parse_lsof_f_output(lines: Iterator[str]) -> Iterator[Dict]:
    """
    Parses the output of `lsof -F pcftn`.

    Args:
        lines: An iterator yielding lines from lsof's stdout.

    Yields:
        Dictionaries representing parsed file records.
        Each record corresponds to one file descriptor or special file type
        (like cwd, txt) per process.
    """
    current_record: Dict[str, any] = {}
    # Iterate through each line received from the lsof command output
    for line in lines:
        line = line.strip()
        # Skip empty lines
        if not line:
            continue

        # The first character indicates the field type (e.g., 'p' for PID)
        field_type = line[0]
        # The rest of the line is the value for that field
        value = line[1:]

        # 'p' indicates the start of a new process record
        if field_type == "p":
            # If there's an existing record being built, yield it before starting anew
            # This check ensures we only yield complete records (implicitly requires 'n' field)
            # Note: The original logic yielded *before* processing 'n'. This version yields
            # *after* 'n' is processed, ensuring more complete records are yielded.
            # We reset the record when a new 'p' is encountered.
            current_record = {"pid": int(value)}
        # 'c' indicates the command name
        elif field_type == "c":
            current_record["command"] = value
        # 'f' indicates the file descriptor string
        elif field_type == "f":
            current_record["fd_str"] = value
            # Parse the FD string to get numeric FD and mode
            fd, mode = _parse_fd(value)
            current_record["fd"] = fd
            current_record["mode"] = mode
        # 't' indicates the file type
        elif field_type == "t":
            current_record["type"] = value
        # 'n' indicates the name/path of the file
        elif field_type == "n":
            current_record["path"] = value
            # 'n' is the last field for a given file descriptor record.
            # Yield the complete record now.
            log.debug(
                f"Yielding complete record: PID {current_record.get('pid')}, "
                f"FD {current_record.get('fd_str')}, Path {value}"
            )
            yield current_record
            # Reset parts of the record for the next file descriptor of the same process,
            # keeping pid and command.
            # Important: If lsof output guarantees p/c before f/t/n for *each* fd,
            # this reset needs adjustment. Assuming p/c comes once per process block.
            # Based on `lsof -F` man page, p/c likely appear once per process.
            current_record = {
                "pid": current_record.get("pid"),
                "command": current_record.get("command"),
            }
        else:
            log.warning(
                f"Ignoring unknown lsof field type: {field_type} in line: {line}"
            )

    # The loop finishes, but the last record might not have been yielded if the
    # stream ended unexpectedly after fields other than 'n'.
    # However, yielding only after 'n' is generally safer.


# --- I/O Logic ---


def _run_lsof_command(pids: Optional[List[int]] = None) -> Iterator[str]:
    """
    Runs the lsof command and yields its raw standard output lines.

    Args:
        pids: Optional list of PIDs to filter lsof output. If None, runs for all processes.

    Yields:
        Raw lines from lsof standard output.

    Raises:
        RuntimeError: If lsof command fails to execute.
        FileNotFoundError: If lsof executable is not found.
    """
    lsof_path = shutil.which("lsof")
    if not lsof_path:
        raise FileNotFoundError("lsof command not found in PATH")

    # Base command using '-F' for machine-readable output.
    # p=pid, c=command, f=fd/filetype, t=type, n=name/path
    cmd = [lsof_path, "-n", "-F", "pcftn"]

    # If specific PIDs are provided, add them to the command
    if pids:
        cmd.extend(["-p", ",".join(map(str, pids))])

    log.info(f"Running lsof command: {' '.join(cmd)}")
    proc = None
    try:
        # Redirect stderr to /dev/null to suppress potential warnings (e.g., tracefs)
        # Using subprocess.DEVNULL is cleaner than opening os.devnull
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",  # Handle potential encoding errors gracefully
        )

        # Ensure stdout is available before iterating
        if proc.stdout:
            for line in proc.stdout:
                yield line
        else:
            log.error("lsof command did not produce stdout.")

    except FileNotFoundError:  # Should be caught by shutil.which, but belt-and-braces
        log.exception("lsof command not found.")
        raise
    except subprocess.SubprocessError as e:
        log.exception(f"Error running lsof: {e}")
        raise RuntimeError(f"lsof command failed: {e}") from e
    except Exception as e:
        log.exception(f"Unexpected error running lsof command: {e}")
        raise RuntimeError(f"Unexpected error running lsof: {e}") from e
    finally:
        if proc:
            # Ensure resources are cleaned up
            if proc.stdout:
                proc.stdout.close()
            # Check exit code
            exit_code = proc.wait()
            log.debug(f"lsof process exited with code: {exit_code}")
            if exit_code != 0:
                # lsof returns 1 if some requested PIDs don't exist, which is not necessarily an error for us.
                # Log non-zero exits other than 1 as warnings.
                if exit_code != 1:
                    log.warning(f"lsof command exited with non-zero code: {exit_code}")


# --- State Update Logic ---


def _process_lsof_record(record: Dict, monitor: Monitor, timestamp: float) -> None:
    """
    Process a single parsed lsof record and update the monitor state.

    Args:
        record: A dictionary representing a parsed file record from lsof.
        monitor: The Monitor instance to update.
        timestamp: The time the event occurred or was processed.
    """
    pid = record.get("pid")
    path = record.get("path")

    # Basic validation: require PID and path for meaningful updates
    if not (pid and path):
        log.debug(f"Incomplete record missing pid or path: {record}")
        return

    fd = record.get("fd")  # Can be None for special types like cwd, txt
    fd_str = record.get("fd_str", "unknown")  # Original fd string (e.g., 'cwd', '3u')
    mode = record.get("mode", "")  # Access mode (e.g., 'r', 'w', 'u')

    # If fd is None, it's a special file type (cwd, txt, etc.), treat as 'stat'
    if fd is None:
        log.debug(f"Special file type '{fd_str}' for PID {pid}: {path}")
        monitor.stat(pid, path, True, timestamp, source="lsof", fd_str=fd_str)
        return

    # For regular file descriptors, register the 'open' event
    log.debug(f"Processing open file: PID {pid}, FD {fd}, Path {path}")
    # Use fd_str for details as fd might be just the number
    monitor.open(
        pid, path, fd, True, timestamp, source="lsof", fd_str=fd_str, mode=mode
    )

    # Check access mode to infer read/write activity
    # Note: This is an approximation based on the mode lsof reports.
    # It doesn't track actual read/write syscalls.
    if "r" in mode or "u" in mode:  # 'u' means read/write
        log.debug(f"File implies read access: PID {pid}, FD {fd}")
        monitor.read(
            pid, fd, path, True, timestamp, source="lsof", bytes=0
        )  # Bytes unknown
    if "w" in mode or "u" in mode:  # 'u' means read/write
        log.debug(f"File implies write access: PID {pid}, FD {fd}")
        monitor.write(
            pid, fd, path, True, timestamp, source="lsof", bytes=0
        )  # Bytes unknown


def _perform_lsof_poll(
    pids_to_monitor: List[int],
    monitor: Monitor,
    seen_fds: Dict[int, Set[Tuple[int, str]]],
) -> Dict[int, Set[Tuple[int, str]]]:
    """
    Performs a single poll cycle using lsof.
    Fetches data, processes records, detects closures, and updates the monitor.

    Args:
        pids_to_monitor: List of PIDs to query with lsof.
        monitor: The Monitor instance.
        seen_fds: Dictionary tracking FDs seen in the *previous* poll cycle.
                  Format: {pid: {(fd, path), ...}}

    Returns:
        A dictionary representing the FDs seen in *this* poll cycle,
        to be used as `seen_fds` in the next iteration.
    """
    timestamp = time.time()
    current_fds: Dict[int, Set[Tuple[int, str]]] = {}
    record_count = 0

    try:
        lsof_output_lines = _run_lsof_command(pids_to_monitor)
        parsed_records = _parse_lsof_f_output(lsof_output_lines)

        for record in parsed_records:
            record_count += 1
            pid = record.get("pid")
            fd = record.get("fd")
            path = record.get("path")

            # Track currently open FDs (excluding special types where fd is None)
            if pid and fd is not None and path:
                if pid not in current_fds:
                    current_fds[pid] = set()
                current_fds[pid].add((fd, path))

            # Update monitor state based on the record
            _process_lsof_record(record, monitor, timestamp)

        log.debug(f"Processed {record_count} lsof records in this poll.")

    except (RuntimeError, FileNotFoundError) as e:
        log.error(f"lsof poll failed: {e}. Skipping state update for this cycle.")
        # Return the previously seen FDs to avoid incorrectly marking all as closed
        return seen_fds
    except Exception as e:
        log.exception(f"Unexpected error during lsof poll: {e}")
        # Return previously seen FDs
        return seen_fds

    # --- Detect closed files ---
    # Compare FDs seen in the previous poll (seen_fds) with the current poll (current_fds)
    close_count = 0
    for pid, previous_fd_paths in seen_fds.items():
        current_pid_fds = current_fds.get(pid, set())  # Get current FDs for this PID
        for fd, path in previous_fd_paths:
            # If an FD+Path from the previous poll is NOT in the current poll's set...
            if (fd, path) not in current_pid_fds:
                log.debug(
                    f"Detected closed file via poll diff: PID {pid}, FD {fd}, Path {path}"
                )
                # Register a 'close' event in the monitor
                monitor.close(pid, fd, True, timestamp, source="lsof_poll")
                close_count += 1

    if close_count > 0:
        log.debug(f"Detected {close_count} closed files in this poll.")

    # Return the FDs seen in *this* cycle for the next comparison
    return current_fds


# --- Main Backend Loop Logic ---


def _lsof_monitoring_loop(
    initial_pids: List[int],
    monitor: Monitor,
    track_descendants: bool,
    poll_interval: float = DEFAULT_LSOF_POLL_INTERVAL,
) -> None:
    """
    The main loop for monitoring processes using lsof polling.

    Args:
        initial_pids: The initial list of PIDs to monitor.
        monitor: The Monitor instance.
        track_descendants: Whether to periodically check for and add descendant processes.
        poll_interval: Time in seconds between lsof polls.
    """
    log.info(
        f"Starting lsof monitoring loop. Initial PIDs: {initial_pids}, "
        f"Track Descendants: {track_descendants}, Poll Interval: {poll_interval}s"
    )

    # Set of all PIDs currently being monitored (including descendants if tracked)
    monitored_pids: Set[int] = set(initial_pids)
    # State of file descriptors seen in the *previous* poll cycle
    # Format: {pid: {(fd, path), ...}}
    seen_fds: Dict[int, Set[Tuple[int, str]]] = {}
    poll_count = 0
    child_check_frequency = int(CHILD_CHECK_INTERVAL_MULTIPLIER / poll_interval)
    if child_check_frequency < 1:
        child_check_frequency = (
            1  # Ensure we check at least every poll if interval is large
        )

    try:
        while True:
            # --- Check for Descendants (if enabled) ---
            if track_descendants and (poll_count % child_check_frequency == 0):
                log.debug(f"Checking for new child processes of {initial_pids}")
                newly_found_pids = set()
                current_monitored_list = list(
                    monitored_pids
                )  # Check descendants of all currently monitored
                for parent_pid in current_monitored_list:
                    try:
                        # Use psutil to find descendants for robustness
                        descendants = get_descendants(parent_pid)
                        for child_pid in descendants:
                            if child_pid not in monitored_pids:
                                log.info(
                                    f"Found new child process: {child_pid} (parent: {parent_pid})"
                                )
                                newly_found_pids.add(child_pid)
                    except Exception as e:
                        # Log errors getting descendants but continue monitoring
                        log.debug(
                            f"Error checking descendants for PID {parent_pid}: {e}"
                        )

                # Add any newly found PIDs to the set we are monitoring
                if newly_found_pids:
                    log.info(
                        f"Adding {len(newly_found_pids)} new child processes to monitoring."
                    )
                    monitored_pids.update(newly_found_pids)

            # --- Perform lsof Poll ---
            pids_to_poll = list(monitored_pids)
            if not pids_to_poll:
                log.info("No PIDs left to monitor. Exiting lsof loop.")
                break

            # Perform the poll and get the FDs seen in this cycle
            current_fds = _perform_lsof_poll(pids_to_poll, monitor, seen_fds)

            # Update seen_fds for the next iteration
            seen_fds = current_fds

            # --- Check if initial processes still exist (if not tracking descendants) ---
            # If we are not tracking descendants, we should stop if all initial PIDs are gone.
            # If tracking descendants, the loop continues as long as any monitored PID exists.
            # Note: psutil.pid_exists might be more reliable here. lsof might fail for a PID
            # if it exits between the start of lsof and when it checks that PID.
            # We rely on _perform_lsof_poll handling lsof errors/empty results.
            # A more robust check might involve psutil.pid_exists on `initial_pids` here.
            # For simplicity, we assume the loop continues if `monitored_pids` is not empty.

            # --- Sleep ---
            poll_count += 1
            log.debug(f"Sleeping for {poll_interval} seconds...")
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        log.info("lsof monitoring loop interrupted by user.")
    except Exception as e:
        # Catch unexpected errors in the loop itself
        log.exception(f"Unexpected error in lsof monitoring loop: {e}")
    finally:
        log.info("Exiting lsof monitoring loop.")


# --- Public Backend Interface ---


def attach(pids: List[int], monitor: Monitor) -> None:
    """
    Attaches to existing processes using lsof polling. Does NOT track descendants.

    Args:
        pids: List of PIDs to monitor.
        monitor: The Monitor instance.
    """
    if not pids:
        log.warning("lsof.attach called with no PIDs.")
        return
    # Call the main loop, explicitly disabling descendant tracking
    _lsof_monitoring_loop(initial_pids=pids, monitor=monitor, track_descendants=False)


def run(command: List[str], monitor: Monitor) -> None:
    """
    Runs a command, monitors it and its descendants using lsof polling.

    Args:
        command: The command and arguments to execute.
        monitor: The Monitor instance.
    """
    log.info(f"Running command with lsof backend: {' '.join(command)}")
    proc = None
    try:
        log.debug("Launching subprocess for the target command.")
        # Launch the target command
        proc = subprocess.Popen(command)
        pid = proc.pid
        log.info(f"Command '{' '.join(command)}' started with PID: {pid}")

        # Start the monitoring loop, tracking the initial PID and its descendants
        _lsof_monitoring_loop(
            initial_pids=[pid], monitor=monitor, track_descendants=True
        )

    except FileNotFoundError:
        log.exception(f"Command not found: {command[0]}")
        # No process started, so monitoring loop won't run.
    except subprocess.SubprocessError as e:
        log.exception(f"Error launching command '{' '.join(command)}': {e}")
        # No process started.
    except Exception as e:
        log.exception(f"Unexpected error in lsof run setup: {e}")
        # Might have started the process, ensure cleanup.
    finally:
        log.info("Cleaning up after lsof run.")
        # Ensure the monitored command process is terminated if it's still running
        if proc and proc.poll() is None:
            log.info(f"Terminating command process (PID: {proc.pid})...")
            try:
                proc.terminate()  # Ask nicely first
                proc.wait(timeout=1.0)  # Wait a short time
                log.debug(f"Command process {proc.pid} terminated gracefully.")
            except subprocess.TimeoutExpired:
                log.warning(
                    f"Command process {proc.pid} did not terminate gracefully, killing."
                )
                proc.kill()  # Force kill
                proc.wait()  # Wait for kill to complete
                log.debug(f"Command process {proc.pid} killed.")
            except Exception as term_err:
                log.exception(f"Error during command process termination: {term_err}")

        # The monitoring loop should exit on its own or via KeyboardInterrupt.
