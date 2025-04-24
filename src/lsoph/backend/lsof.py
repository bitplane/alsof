# Filename: src/lsoph/backend/lsof.py
import asyncio
import logging
import os
import re
import shutil
import subprocess  # Keep for DEVNULL if needed
import time
from collections.abc import AsyncIterator, Iterator

from lsoph.monitor import Monitor
from lsoph.util.pid import get_descendants  # Keep for descendant logic if needed

# Import the base class
from .base import Backend

# Setup logging
log = logging.getLogger("lsoph.backend.lsof")

# --- Constants ---
DEFAULT_LSOF_POLL_INTERVAL = 1.0
CHILD_CHECK_INTERVAL_MULTIPLIER = (
    5  # Check for children every N polls (only relevant if attach tracked descendants)
)

# --- Regular Expressions ---
FD_TYPE_RE = re.compile(r"(\d+)([rwu])?")


# --- Parsing Logic (remains synchronous) ---
def _parse_fd(fd_str: str) -> tuple[int | None, str]:
    """Parse the FD column from lsof output (field 'f')."""
    if fd_str in ("cwd", "rtd", "txt", "mem"):
        return None, fd_str
    match = FD_TYPE_RE.match(fd_str)
    if match:
        return int(match.group(1)), match.group(2) or ""
    log.debug(f"Unparsable FD string: {fd_str}")
    return None, fd_str


def _parse_lsof_f_output(
    lines: Iterator[str],
) -> Iterator[dict]:
    """Parses the output of `lsof -F pcftn`."""
    current_record: dict[str, Any] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        field_type = line[0]
        value = line[1:]
        if field_type == "p":
            # Yield happens on 'n' field below
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
            # Yield the complete record when the path ('n') is encountered
            yield current_record
            # Reset for the next record, keeping pid/command if they exist
            current_record = {
                "pid": current_record.get("pid"),
                "command": current_record.get("command"),
            }


# --- Async I/O Logic ---
async def _run_lsof_command_async(
    pids: list[int] | None = None,
) -> AsyncIterator[str]:
    """
    Runs the lsof command asynchronously and yields its raw standard output lines.
    """
    lsof_path = shutil.which("lsof")
    if not lsof_path:
        raise FileNotFoundError("lsof command not found in PATH")
    cmd = [lsof_path, "-n", "-F", "pcftn"]
    if pids:
        cmd.extend(["-p", ",".join(map(str, pids))])
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            # No text mode in asyncio subprocess, decode manually
        )
        if process.stdout:
            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break  # EOF
                yield line_bytes.decode("utf-8", errors="replace").strip()
        else:
            log.error("lsof command (async) did not produce stdout.")

        await process.wait()  # Wait for process to finish
        # lsof exits with 1 if some PIDs weren't found, which is not an error for us
        if process.returncode != 0 and process.returncode != 1:
            log.warning(
                f"lsof command (async) exited with unexpected code: {process.returncode}"
            )

    except FileNotFoundError:
        log.exception("lsof command not found.")
        raise
    except (OSError, Exception) as e:
        log.exception(f"Error running async lsof: {e}")
        raise RuntimeError(f"async lsof command failed: {e}") from e
    finally:
        if process and process.returncode is None:
            log.warning("lsof process did not exit, attempting to kill.")
            try:
                process.kill()
                await process.wait()  # Wait for kill
            except ProcessLookupError:
                pass  # Already gone
            except Exception as kill_e:
                log.error(f"Error killing lsof process: {kill_e}")


# --- State Update Logic (synchronous) ---
def _process_lsof_record(record: dict, monitor: Monitor, timestamp: float) -> None:
    """Process a single parsed lsof record and update the monitor state."""
    pid = record.get("pid")
    path = record.get("path")
    if not (pid and path):
        return
    fd = record.get("fd")
    fd_str = record.get("fd_str", "unknown")
    mode = record.get("mode", "")
    if fd is None:  # Special file type (cwd, txt, etc.)
        monitor.stat(pid, path, True, timestamp, source="lsof", fd_str=fd_str)
        return
    # Regular file descriptor
    monitor.open(
        pid, path, fd, True, timestamp, source="lsof", fd_str=fd_str, mode=mode
    )
    # Simulate read/write based on mode (as lsof doesn't show actual operations)
    if "r" in mode or "u" in mode:
        monitor.read(pid, fd, path, True, timestamp, source="lsof", bytes=0)
    if "w" in mode or "u" in mode:
        monitor.write(pid, fd, path, True, timestamp, source="lsof", bytes=0)


async def _perform_lsof_poll_async(
    pids_to_monitor: list[int],
    monitor: Monitor,
    seen_fds: dict[int, set[tuple[int, str]]],
) -> dict[int, set[tuple[int, str]]]:
    """Performs a single async poll cycle using lsof."""
    timestamp = time.time()
    current_fds: dict[int, set[tuple[int, str]]] = {}
    record_count = 0
    lines_processed = 0

    try:
        # Use the async version of the command runner
        lsof_output_lines = []
        async for line in _run_lsof_command_async(pids_to_monitor):
            lsof_output_lines.append(line)
            lines_processed += 1

        # Parse the collected lines (sync parsing is fine)
        parsed_records = _parse_lsof_f_output(iter(lsof_output_lines))

        for record in parsed_records:
            record_count += 1
            pid = record.get("pid")
            fd = record.get("fd")
            path = record.get("path")
            # Only track numeric FDs for close detection
            if pid and fd is not None and path:
                current_fds.setdefault(pid, set()).add((fd, path))
            _process_lsof_record(record, monitor, timestamp)  # Update monitor (sync)

    except (RuntimeError, FileNotFoundError) as e:
        log.error(f"Async lsof poll failed: {e}. Skipping state update.")
        return seen_fds  # Return previous state on error
    except Exception as e:
        log.exception(f"Unexpected error during async lsof poll: {e}")
        return seen_fds  # Return previous state on error

    # --- Detect closed files (sync logic) ---
    close_count = 0
    for pid, previous_fd_paths in seen_fds.items():
        current_pid_fds = current_fds.get(pid, set())
        for fd, path in previous_fd_paths:
            if (fd, path) not in current_pid_fds:
                monitor.close(pid, fd, True, timestamp, source="lsof_poll")
                close_count += 1

    return current_fds  # Return FDs seen in *this* cycle


# --- Async Backend Class ---


class LsofBackend(Backend):
    """Async backend implementation using lsof polling."""

    def __init__(
        self, monitor: Monitor, poll_interval: float = DEFAULT_LSOF_POLL_INTERVAL
    ):
        super().__init__(monitor)
        self.poll_interval = poll_interval
        # State is managed within the run methods

    async def attach(self, pids: list[int]):
        """Implementation of the attach method."""
        if not pids:
            log.warning("LsofBackend.attach called with no PIDs.")
            return

        log.info(
            f"Starting lsof attach monitoring loop. PIDs: {pids}, Poll Interval: {self.poll_interval}s"
        )
        monitored_pids: set[int] = set(pids)
        seen_fds: dict[int, set[tuple[int, str]]] = {}
        # Attach never tracks descendants in this implementation

        try:
            while not self.should_stop:
                start_time = time.monotonic()

                pids_to_poll = list(monitored_pids)
                if not pids_to_poll:
                    log.info("No PIDs left to monitor in lsof attach. Exiting loop.")
                    break  # Exit if all initial PIDs are gone

                # Perform the async poll
                current_fds = await _perform_lsof_poll_async(
                    pids_to_poll, self.monitor, seen_fds
                )
                seen_fds = current_fds  # Update state for next poll

                # Optional: Check if initial PIDs still exist using psutil?
                # For simplicity, we rely on lsof errors or empty results if PIDs vanish.

                # Check stop event again after polling
                if self.should_stop:
                    break

                # Asynchronous sleep
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, self.poll_interval - elapsed)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            log.info("Lsof backend attach cancelled.")
        except Exception as e:
            log.exception(f"Unexpected error in lsof async attach loop: {e}")
        finally:
            log.info("Exiting lsof async attach loop.")

    # run_command is inherited from the base class
