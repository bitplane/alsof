# Filename: src/lsoph/backend/lsof/helpers.py
"""Helper functions for the lsof backend."""

import asyncio
import logging
import shutil
import time
from collections.abc import AsyncIterator
from typing import Any

from lsoph.monitor import Monitor

# Import parsing functions from the sibling module
from .parse import _parse_fd, _parse_lsof_f_output

log = logging.getLogger(__name__)  # Use specific logger

# Timeout for waiting for lsof command (prevent hangs)
LSOF_COMMAND_TIMEOUT = 10.0


# --- Async I/O Logic ---


# Define helper function outside the main try block
async def _read_stream(
    stream: asyncio.StreamReader | None,
    stream_name: str,
    process_pid: int | str,
    timeout: float,
) -> list[str]:
    """Reads lines from a stream with a timeout."""
    lines = []
    if not stream:
        return lines
    while True:
        try:
            # Use wait_for for readline to prevent hangs on the stream read itself
            line_bytes = await asyncio.wait_for(stream.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            # Log timeout reading the stream, but the process might still finish
            log.error(f"Timeout reading {stream_name} from lsof (PID {process_pid}).")
            # Don't kill the process here, let the outer timeout handle it
            # if the process itself hangs.
            break  # Stop reading this stream
        except asyncio.IncompleteReadError as read_err:
            # Can happen if process exits while reading
            log.debug(f"Incomplete read from lsof {stream_name}: {read_err}")
            break
        except Exception as read_err:
            log.error(f"Error reading lsof {stream_name}: {read_err}")
            break  # Stop reading on other errors

        if not line_bytes:
            break  # EOF reached
        lines.append(line_bytes.decode("utf-8", errors="replace").strip())
    return lines


async def _run_lsof_command_async(
    pids: list[int] | None = None,
) -> AsyncIterator[str]:
    """
    Runs the lsof command asynchronously and yields its raw standard output lines.
    Handles potential hangs using a timeout.
    """
    lsof_path = shutil.which("lsof")
    if not lsof_path:
        raise FileNotFoundError("lsof command not found in PATH")

    # Base command: -n (no host resolution), -P (no port resolution), -F pcftn (parseable output)
    # Added +c 0 to show full command names
    # Added +L to prevent listing link counts (can be slow)
    cmd = [lsof_path, "-n", "-P", "+c", "0", "+L", "-F", "pcftn"]
    if pids:
        # Filter out non-positive PIDs just in case
        valid_pids = [str(p) for p in pids if p > 0]
        if not valid_pids:
            log.warning("lsof called with no valid PIDs to monitor.")
            # Use a bare return to stop the async generator, yielding nothing.
            return

        cmd.extend(["-p", ",".join(valid_pids)])
        log.debug(f"Running lsof for PIDs: {valid_pids}")
    else:
        # If no PIDs specified, maybe log a warning or raise error?
        # For now, let it run system-wide (potentially slow/resource intensive)
        log.warning("Running lsof without specific PIDs (system-wide).")

    process: asyncio.subprocess.Process | None = None
    try:
        log.debug(f"Executing lsof command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,  # Capture stderr as well
        )
        process_pid_str = str(process.pid) if process.pid else "N/A"
        log.debug(f"lsof process started with PID: {process_pid_str}")

        # Wait for the process and stream readers to complete, with an overall timeout
        try:
            # Pass necessary info to the helper function
            read_timeout = LSOF_COMMAND_TIMEOUT / 2
            stdout_task = asyncio.create_task(
                _read_stream(process.stdout, "stdout", process_pid_str, read_timeout)
            )
            stderr_task = asyncio.create_task(
                _read_stream(process.stderr, "stderr", process_pid_str, read_timeout)
            )
            process_wait_task = asyncio.create_task(process.wait())

            # Wait for all tasks (streams reading + process exit)
            done, pending = await asyncio.wait(
                [stdout_task, stderr_task, process_wait_task],
                timeout=LSOF_COMMAND_TIMEOUT,
                return_when=asyncio.ALL_COMPLETED,
            )

            # Check if the process itself timed out (didn't complete)
            if process_wait_task not in done:
                log.error(
                    f"lsof command (PID {process_pid_str}) timed out after {LSOF_COMMAND_TIMEOUT}s."
                )
                # Cancel pending stream readers
                for task in pending:
                    if (
                        task is not process_wait_task
                    ):  # Don't cancel the wait task itself
                        task.cancel()
                        try:
                            await task  # Allow cancellation to propagate
                        except asyncio.CancelledError:
                            pass
                # Kill the hung process
                if process.returncode is None:
                    log.warning(f"Killing timed-out lsof process {process_pid_str}")
                    try:
                        process.kill()
                        await process.wait()  # Wait for kill confirmation
                    except ProcessLookupError:
                        pass  # Already gone
                    except Exception as kill_e:
                        log.error(f"Error killing timed-out lsof process: {kill_e}")
                raise TimeoutError("lsof command timed out")  # Signal timeout to caller

            # Process finished within timeout, get results
            stdout_lines = await stdout_task
            stderr_lines = await stderr_task
            return_code = await process_wait_task  # Get exit code

            # Log stderr if any content was captured
            if stderr_lines:
                log.debug(
                    f"lsof stderr (PID {process_pid_str}, Exit Code {return_code}):\n"
                    + "\n".join(stderr_lines)
                )

            # Yield stdout lines for parsing
            for line in stdout_lines:
                yield line

            # Check exit code after processing output
            # lsof exits with 1 if some PIDs weren't found or other non-fatal issues
            if return_code != 0 and return_code != 1:
                log.warning(
                    f"lsof command (async) exited with unexpected code: {return_code}"
                )

        except asyncio.TimeoutError:
            # Re-raise timeout if caught from wait_for
            raise TimeoutError("lsof command timed out")
        except Exception as e:
            log.exception(f"Error managing async lsof execution: {e}")
            raise RuntimeError(f"async lsof command failed: {e}") from e

    except FileNotFoundError:
        log.exception("lsof command not found.")
        raise  # Propagate FileNotFoundError
    except (OSError, Exception) as e:
        log.exception(f"Error starting async lsof: {e}")
        # Ensure process is cleaned up if creation failed partially
        if process and process.returncode is None:
            try:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                pass
            except Exception:
                pass  # Ignore errors during cleanup
        raise RuntimeError(f"async lsof command failed: {e}") from e


# --- State Update Logic ---
def _process_lsof_record(
    record: dict[str, Any], monitor: Monitor, timestamp: float
) -> None:
    """Process a single parsed lsof record and update the monitor state."""
    pid = record.get("pid")
    path = record.get("path")
    if not (pid and path):
        log.debug(f"Skipping lsof record missing PID or path: {record}")
        return

    # Use helper to get or create FileInfo (handles ignored paths)
    # This ensures we don't process events for paths the user wants ignored
    info = monitor._get_or_create_fileinfo(path, timestamp)
    if not info:
        # Using trace level logging requires a custom setup or library like 'loguru'
        # log.trace(f"Skipping lsof record for ignored/invalid path: {path}")
        return  # Path was ignored or invalid

    fd = record.get("fd")
    fd_str = record.get("fd_str", "unknown")
    mode = record.get("mode", "")
    file_type = record.get("type")  # e.g., REG, DIR, CHR, FIFO, unix, IPv4, IPv6

    # Gather details specific to this lsof event
    details = {
        "source": "lsof",
        "fd_str": fd_str,
        "mode": mode,
        "file_type": file_type,
        "command": record.get("command"),  # Include command if available
    }

    # Handle different types of entries based on FD presence/value
    if fd is None:  # Special file type (cwd, txt, mem, DEL, etc.)
        # Treat these as access/stat operations in the monitor
        # log.trace(f"Processing lsof special entry: PID={pid}, FD={fd_str}, Path={path}")
        monitor.stat(pid, path, True, timestamp, **details)
        # Specific logging for deleted-but-mapped files
        if fd_str == "DEL":
            log.debug(f"PID {pid} has deleted file mapped: {path}")
            # Consider adding a specific status or detail for this case in FileInfo?
    elif fd >= 0:
        # Regular file descriptor
        # log.trace(f"Processing lsof FD entry: PID={pid}, FD={fd}, Path={path}, Mode={mode}")
        # Report open event (idempotent, ensures FD is mapped)
        monitor.open(pid, path, fd, True, timestamp, **details)

        # Simulate read/write based on mode flags ('r', 'w', 'u')
        # This is an approximation as lsof only shows the open mode, not actual operations
        if "r" in mode or "u" in mode:
            monitor.read(pid, fd, path, True, timestamp, bytes=0, **details)
        if "w" in mode or "u" in mode:
            monitor.write(pid, fd, path, True, timestamp, bytes=0, **details)
    else:
        # Should not happen if _parse_fd works correctly, but log defensively
        log.debug(f"Skipping lsof record with invalid FD: {record}")


async def _perform_lsof_poll_async(
    pids_to_monitor: list[int],
    monitor: Monitor,
    seen_fds: dict[int, set[tuple[int, str]]],
) -> tuple[dict[int, set[tuple[int, str]]], set[int]]:
    """
    Performs a single async poll cycle using lsof.

    Fetches lsof data, parses it, updates the monitor state, detects closures,
    and returns the current state of open FDs and the PIDs seen in the output.

    Args:
        pids_to_monitor: List of PIDs to query with lsof.
        monitor: The central Monitor instance to update.
        seen_fds: The state of FDs from the *previous* poll cycle, used for comparison.
                  Format: {pid: {(fd, path), ...}}

    Returns:
        A tuple containing:
        - current_fds: State of FDs found in *this* poll cycle. Format: {pid: {(fd, path), ...}}
        - pids_seen_in_output: Set of PIDs that appeared in the lsof output.
    """
    timestamp = time.time()  # Timestamp for this poll cycle
    current_fds: dict[int, set[tuple[int, str]]] = {}  # FDs found in this poll
    pids_seen_in_output: set[int] = set()  # PIDs found in this poll's output
    record_count = 0
    lines_processed = 0

    if not pids_to_monitor:
        log.debug("Skipping lsof poll cycle: no PIDs to monitor.")
        return seen_fds, pids_seen_in_output  # Return previous state, no PIDs seen

    try:
        # 1. Run lsof command asynchronously and get output lines
        lsof_output_lines = []
        log.debug(f"Starting lsof command for {len(pids_to_monitor)} PIDs...")
        async for line in _run_lsof_command_async(pids_to_monitor):
            lsof_output_lines.append(line)
            lines_processed += 1
        log.debug(f"lsof command finished, processed {lines_processed} lines.")

        # 2. Parse the collected lines
        parsed_records = _parse_lsof_f_output(iter(lsof_output_lines))

        # 3. Process each record: update monitor and track current state
        for record in parsed_records:
            record_count += 1
            pid = record.get("pid")
            fd = record.get("fd")
            path = record.get("path")

            if pid:
                pids_seen_in_output.add(pid)  # Track PIDs found in output

            # Store numeric FDs >= 0 and their paths for close detection later
            if pid and fd is not None and fd >= 0 and path:
                current_fds.setdefault(pid, set()).add((fd, path))

            # Update monitor state based on the record
            _process_lsof_record(record, monitor, timestamp)
        log.debug(f"Processed {record_count} records from lsof output.")

    except (RuntimeError, FileNotFoundError, TimeoutError) as e:
        # Handle errors during lsof execution or parsing
        log.error(f"Async lsof poll failed: {e}. Skipping state update for this cycle.")
        # On error, assume no PIDs were seen reliably, return previous FD state
        return seen_fds, set()
    except Exception as e:
        # Catch unexpected errors during the poll process
        log.exception(f"Unexpected error during async lsof poll: {e}")
        # Assume state is unreliable, return previous FD state
        return seen_fds, set()

    # 4. Detect closed files by comparing previous state (seen_fds) with current state (current_fds)
    close_count = 0
    # Iterate over PIDs that were present in the *previous* poll cycle
    pids_from_previous_poll = list(seen_fds.keys())

    for pid in pids_from_previous_poll:
        # Check if the PID was actually found in the *current* lsof output
        if pid in pids_seen_in_output:
            # PID still exists, check for FDs that were open but are now gone
            previous_pid_fds = seen_fds.get(pid, set())
            current_pid_fds = current_fds.get(
                pid, set()
            )  # FDs found for this PID in current poll
            for fd, path in previous_pid_fds:
                if (fd, path) not in current_pid_fds:
                    # This specific (FD, Path) tuple existed before but not now -> closed
                    # log.trace(f"Detected close: PID={pid}, FD={fd}, Path={path}")
                    monitor.close(pid, fd, True, timestamp, source="lsof_poll")
                    close_count += 1
        else:
            # PID was tracked previously but missing in current output -> process likely exited
            # Close all previously known FDs associated with this PID
            log.debug(
                f"PID {pid} not found in current lsof output, closing its known FDs."
            )
            previous_pid_fds = seen_fds.get(pid, set())
            for fd, path in previous_pid_fds:
                # log.trace(f"Closing FD {fd} for exited PID {pid} (Path: {path})")
                monitor.close(pid, fd, True, timestamp, source="lsof_poll_exit")
                close_count += 1
            # Signal process exit to the monitor for general cleanup related to the PID
            monitor.process_exit(pid, timestamp)

    if close_count > 0:
        log.debug(f"Detected {close_count} file closures in lsof poll cycle.")

    # Return the state of FDs seen in *this* cycle and the PIDs seen in *this* cycle's output
    return current_fds, pids_seen_in_output
