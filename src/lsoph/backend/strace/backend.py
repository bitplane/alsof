# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend implementation using refactored components."""

import asyncio
import logging
import os
import shlex
import shutil
import sys
from collections.abc import AsyncIterator
from typing import Any

import psutil  # Keep for pid_exists check

# Corrected import path for handlers and helpers
from lsoph.backend.strace import handlers, helpers
from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

from ..base import Backend
from .parse import (
    EXIT_SYSCALLS,
    PROCESS_SYSCALLS,
    Syscall,
    parse_strace_stream,
)
from .terminate import terminate_strace_process

log = logging.getLogger(__name__)

# --- Constants ---
# Restore -qq to suppress attach/detach/exit messages for cleaner parsing
STRACE_BASE_OPTIONS = ["-f", "-qq", "-s", "4096", "-xx", "-o", "/dev/stderr"]
# Define default syscalls here
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
        set(PROCESS_SYSCALLS)
        | set(FILE_STRUCT_SYSCALLS)
        | set(IO_SYSCALLS)
        | set(EXIT_SYSCALLS)
        | {"chdir", "fchdir"}  # Ensure chdir/fchdir are included
    )
)
# --- End Constants ---


# --- Event Processing Helper ---
# _process_single_event remains unchanged


async def _process_single_event(
    event: Syscall, monitor: Monitor, cwd_map: dict[int, str]
):
    """Processes a single Syscall event, updating state and CWD map."""
    pid = event.pid
    syscall_name = event.syscall

    # Ensure CWD is known for the PID before processing path-dependent syscalls
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        # Use the imported pid_get_cwd utility function
        cwd = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
            log.info(f"Fetched CWD for new PID {pid}: {cwd}")
        else:
            log.warning(
                f"Could not determine CWD for PID {pid}. Relative paths may be incorrect."
            )
            # Store None to avoid repeated lookups? Or leave it absent?
            # Let's leave it absent for now.

    # Reduced logging
    # log.debug(f"Processing event: {event!r}")

    # Handle specific syscalls that modify state or need special handling first
    if syscall_name in ["chdir", "fchdir"]:
        handlers.update_cwd(pid, cwd_map, monitor, event)
        return

    if syscall_name in EXIT_SYSCALLS:
        monitor.process_exit(pid, event.timestamp)
        # Clean up CWD map on exit
        if pid in cwd_map:
            del cwd_map[pid]
            # log.debug(f"Removed PID {pid} CWD map on exit.") # Reduced logging
        return

    # Dispatch to generic handlers for file operations
    handler = handlers.SYSCALL_HANDLERS.get(syscall_name)
    if handler:
        try:
            handler(event, monitor, cwd_map)
        except Exception as e:
            log.exception(f"Handler error for {syscall_name} (event: {event!r}): {e}")
    # else: # Log unhandled syscalls if needed (might be noisy)
    #     log.debug(f"No specific handler for syscall: {syscall_name}")


# --- End Event Processing Helper ---


# --- Backend Class ---
class Strace(Backend):  # Renamed from StraceBackend
    """Async backend implementation using strace (refactored)."""

    # Class attribute for the command-line name
    backend_name = "strace"

    def __init__(self, monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS):
        super().__init__(monitor)
        # Ensure essential syscalls are always included
        self.syscalls = sorted(
            list(
                set(syscalls)
                | set(PROCESS_SYSCALLS)
                | set(EXIT_SYSCALLS)
                | {"chdir", "fchdir"}  # Explicitly add chdir/fchdir
            )
        )
        self._strace_process: asyncio.subprocess.Process | None = None

    @staticmethod
    def is_available() -> bool:
        """Check if the strace executable is available in the system PATH."""
        available = shutil.which("strace") is not None
        log.debug(
            f"Checking availability for {Strace.backend_name}: {available}"
        )  # Use class name
        return available

    # --- Stream Reading Helper ---
    async def _read_stderr_lines(
        self, stderr: asyncio.StreamReader, stop_event: asyncio.Event
    ) -> AsyncIterator[str]:
        """Reads lines from the strace stderr stream asynchronously."""
        pid_str = str(self._strace_process.pid) if self._strace_process else "unknown"
        # log.debug(f"Starting stderr reader loop for strace process {pid_str}") # Reduced logging
        read_count = 0
        while not stop_event.is_set():
            try:
                # Read line by line
                line_bytes = await stderr.readline()
                if not line_bytes:
                    log.info(
                        f"EOF reached on strace stderr after reading {read_count} lines."
                    )
                    break  # End of stream
                read_count += 1
                line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\n")
                yield line_str
            except asyncio.CancelledError:
                log.info(
                    f"Stderr reader task cancelled after reading {read_count} lines."
                )
                break
            except Exception as read_err:
                # Avoid logging common errors when process exits expectedly
                if not stop_event.is_set():
                    log.exception(
                        f"Error reading strace stderr after {read_count} lines: {read_err}"
                    )
                break  # Stop reading on error
        # log.debug("Exiting stderr reader loop.") # Reduced logging

    # --- End Stream Reading Helper ---

    # --- Event Stream Processing ---
    async def _process_event_stream(
        self,
        event_stream: AsyncIterator[Syscall],
        pid_cwd_map: dict[int, str],
    ):
        """Internal helper method to process the stream of Syscall events."""
        log.info("Starting internal event processing loop...")
        processed_count = 0
        try:
            async for event in event_stream:
                if self.should_stop:  # Check stop flag before processing
                    log.info("Stop signal detected during event processing.")
                    break
                processed_count += 1
                # Call the local _process_single_event which uses imported handlers
                await _process_single_event(event, self.monitor, pid_cwd_map)

            log.info(
                f"Finished internal event loop. Processed {processed_count} events."
            )
        except asyncio.CancelledError:
            log.info("Event processing stream task cancelled.")
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            # Log specific errors that might occur during parsing/processing
            log.error(f"Error during event stream processing: {e}")
            await self.stop()  # Signal stop on critical errors
        except Exception as e:
            log.exception(f"Unexpected error processing event stream: {e}")
            await self.stop()  # Signal stop on unexpected errors
        finally:
            log.info("Exiting internal event processing loop.")

    # --- End Event Stream Processing ---

    # --- Attach Method ---
    async def attach(self, pids: list[int]):
        """Implementation of the attach method."""
        if not pids:
            log.warning(
                f"{self.__class__.__name__}.attach called with no PIDs."
            )  # Use class name
            return

        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        pid_cwd_map: dict[int, str] = {}
        # Pre-populate CWD map for initially attached PIDs
        for pid in pids:
            # Use the imported pid_get_cwd utility function
            cwd = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd
            else:
                log.warning(f"Could not get initial CWD for attached PID {pid}.")
        log.info(f"Initial CWDs for attach: {pid_cwd_map}")

        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return

        # Use the syscall list defined in __init__
        # Use STRACE_BASE_OPTIONS which now includes -qq
        strace_command = [
            strace_path,
            *STRACE_BASE_OPTIONS,
            "-e",
            f"trace={','.join(self.syscalls)}",
        ]
        # Filter out PIDs that don't exist before attaching
        valid_attach_ids = [str(pid) for pid in pids if psutil.pid_exists(pid)]
        if not valid_attach_ids:
            log.error("No valid PIDs/TIDs provided to attach to.")
            return
        strace_command.extend(["-p", ",".join(valid_attach_ids)])
        log.info(f"Preparing to attach (async) to existing IDs: {valid_attach_ids}")

        try:
            log.info(
                f"Executing async: {' '.join(shlex.quote(c) for c in strace_command)}"
            )
            process = await asyncio.create_subprocess_exec(
                *strace_command,
                stdout=asyncio.subprocess.DEVNULL,  # Ignore stdout
                stderr=asyncio.subprocess.PIPE,  # Capture stderr
            )
            self._strace_process = process  # Store the process handle
            strace_pid = process.pid
            self.monitor.backend_pid = strace_pid  # Inform monitor about backend PID
            log.info(f"Strace started asynchronously with PID: {strace_pid}")

            if not process.stderr:
                log.error(
                    f"Strace process {strace_pid} has no stderr stream! Cannot attach."
                )
                await self.stop()  # Signal stop if stderr is missing
                return

            # Start reading and parsing the stream
            raw_lines = self._read_stderr_lines(process.stderr, self._should_stop)
            event_stream = parse_strace_stream(
                raw_lines,
                self.monitor,
                self._should_stop,
                syscalls=self.syscalls,  # Pass the syscall list
                attach_ids=pids,  # Pass initial PIDs for map population
            )
            # Process the events
            await self._process_event_stream(event_stream, pid_cwd_map)

        except FileNotFoundError as e:
            log.error(f"Strace command failed: {e}")
        except ValueError as e:  # Catch potential errors from parse_strace_stream setup
            log.error(f"Strace configuration error: {e}")
        except asyncio.CancelledError:
            log.info("Strace attach task cancelled externally.")
        except Exception as e:
            log.exception(f"Error setting up or running strace attach: {e}")
        finally:
            log.info("Strace attach finished.")
            # Ensure stop is called if the loop finishes unexpectedly
            if not self.should_stop:
                await self.stop()

    # --- End Attach Method ---

    # --- Run Command Method ---
    async def run_command(self, command: list[str]):
        """Implementation of the run_command method."""
        if not command:
            log.error(
                f"{self.__class__.__name__}.run_command called empty."
            )  # Use class name
            return

        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        pid_cwd_map: dict[int, str] = {}

        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return

        # Use the syscall list defined in __init__
        # Use STRACE_BASE_OPTIONS which now includes -qq
        strace_command = [
            strace_path,
            *STRACE_BASE_OPTIONS,
            "-e",
            f"trace={','.join(self.syscalls)}",
        ]
        # Use "--" to separate strace options from the command to run
        strace_command.extend(["--", *command])
        log.info(
            f"Preparing to launch (async): {' '.join(shlex.quote(c) for c in command)}"
        )

        try:
            log.info(
                f"Executing async: {' '.join(shlex.quote(c) for c in strace_command)}"
            )
            process = await asyncio.create_subprocess_exec(
                *strace_command,
                stdout=asyncio.subprocess.DEVNULL,  # Ignore target command stdout
                stderr=asyncio.subprocess.PIPE,  # Capture strace output on stderr
            )
            self._strace_process = process  # Store the process handle
            strace_pid = process.pid
            self.monitor.backend_pid = strace_pid  # Inform monitor
            log.info(f"Strace started asynchronously with PID: {strace_pid}")

            if not process.stderr:
                log.error(
                    f"Strace process {strace_pid} has no stderr stream! Cannot run command."
                )
                await self.stop()  # Signal stop
                return

            # Start reading and parsing the stream
            raw_lines = self._read_stderr_lines(process.stderr, self._should_stop)
            event_stream = parse_strace_stream(
                raw_lines,
                self.monitor,
                self._should_stop,
                syscalls=self.syscalls,
                # No attach_ids needed for run_command mode
            )
            # Process the events
            await self._process_event_stream(event_stream, pid_cwd_map)

        except FileNotFoundError as e:
            # Could be strace or the target command
            log.error(f"Strace or target command failed: {e}")
        except ValueError as e:  # Catch potential errors from parse_strace_stream setup
            log.error(f"Strace configuration error: {e}")
        except asyncio.CancelledError:
            log.info("Strace run task cancelled externally.")
        except Exception as e:
            log.exception(f"Error setting up or running strace run_command: {e}")
        finally:
            log.info("Strace run_command finished.")
            # Ensure stop is called if the loop finishes unexpectedly
            if not self.should_stop:
                await self.stop()

    # --- End Run Command Method ---

    # --- Stop Method ---
    async def stop(self):
        """Signals the backend's running task to stop and terminates the managed strace process."""
        if not self._should_stop.is_set():
            log.info(
                f"Signalling backend {self.__class__.__name__} to stop."
            )  # Use class name
            self._should_stop.set()  # Set the event first

            # Get process handle and PID *before* calling terminate helper
            process_to_term = self._strace_process
            pid_to_term = process_to_term.pid if process_to_term else -1

            log.info(
                f"Attempting termination of stored strace process (PID: {pid_to_term})..."
            )
            # Call the termination helper function
            await terminate_strace_process(process_to_term, pid_to_term)

            # Clear the stored process handle after termination attempt
            self._strace_process = None
        # else: # Reduced logging
        # log.debug(f"Backend {self.__class__.__name__} stop already signalled.")

    # --- End Stop Method ---


# --- End Backend Class ---
