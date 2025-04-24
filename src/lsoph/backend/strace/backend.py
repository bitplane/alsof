# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend implementation using refactored components."""

import asyncio
import logging
import os
import shlex
import shutil
import sys
from collections.abc import AsyncIterator
from typing import Any, Set  # Added Set

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
# Using options without -xx for direct UTF-8 output
STRACE_BASE_OPTIONS = ["-f", "-qq", "-s", "4096", "-o", "/dev/stderr"]
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


async def _process_single_event(
    event: Syscall, monitor: Monitor, cwd_map: dict[int, str], initial_pids: Set[int]
):
    """
    Processes a single Syscall event, updating state and CWD map.
    Handles CWD inheritance for new processes.
    """
    pid = event.pid
    syscall_name = event.syscall

    # 1. Handle process creation CWD inheritance
    if (
        syscall_name in PROCESS_SYSCALLS
        and event.success
        and event.child_pid is not None
    ):
        child_pid = event.child_pid
        parent_cwd = cwd_map.get(pid)  # Get parent's CWD
        if parent_cwd:
            cwd_map[child_pid] = parent_cwd
            log.debug(f"PID {child_pid} inherited CWD from parent {pid}: {parent_cwd}")
        else:
            # Parent CWD unknown (maybe parent exited?), try looking up child directly
            log.warning(
                f"Parent PID {pid} CWD unknown for new child {child_pid}. Attempting direct lookup."
            )
            child_cwd = pid_get_cwd(child_pid)
            if child_cwd:
                cwd_map[child_pid] = child_cwd
                log.info(f"Fetched CWD for new child PID {child_pid}: {child_cwd}")
            else:
                log.warning(f"Could not determine CWD for new child PID {child_pid}.")
        # Don't process the clone/fork syscall itself further for file ops
        return

    # 2. Ensure CWD is known for other syscalls
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        # Only lookup CWD if it wasn't inherited and it's not an exit call
        # Also check if it was one of the initially attached PIDs
        cwd = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
            if pid in initial_pids:
                log.info(f"Fetched CWD for initial PID {pid}: {cwd}")
            # else: # Reduce noise for non-initial PIDs where inheritance might have failed
            #      log.debug(f"Fetched CWD for PID {pid}: {cwd}")
        else:
            # Check if process exited before logging warning
            if psutil.pid_exists(pid):
                log.warning(
                    f"Could not determine CWD for PID {pid} (still exists). Relative paths may be incorrect."
                )
            # else: Process likely exited before lookup, expected behaviour sometimes
            #      log.debug(f"Could not determine CWD for PID {pid} (process exited).") # Reduce noise

    # 3. Handle chdir/fchdir
    if syscall_name in ["chdir", "fchdir"]:
        handlers.update_cwd(pid, cwd_map, monitor, event)
        return  # update_cwd calls monitor.stat internally

    # 4. Handle exit
    if syscall_name in EXIT_SYSCALLS:
        monitor.process_exit(pid, event.timestamp)
        if pid in cwd_map:
            del cwd_map[pid]
        return

    # 5. Dispatch to generic handlers
    handler = handlers.SYSCALL_HANDLERS.get(syscall_name)
    if handler:
        try:  # Keep try/except around handler call itself
            handler(event, monitor, cwd_map)
        except Exception as e:
            log.exception(f"Handler error for {syscall_name} (event: {event!r}): {e}")


# --- End Event Processing Helper ---


# --- Backend Class ---
class Strace(Backend):
    """Async backend implementation using strace (refactored)."""

    backend_name = "strace"

    def __init__(self, monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS):
        super().__init__(monitor)
        self.syscalls = sorted(
            list(
                set(syscalls)
                | set(PROCESS_SYSCALLS)
                | set(EXIT_SYSCALLS)
                | {"chdir", "fchdir"}
            )
        )
        self._strace_process: asyncio.subprocess.Process | None = None
        self._initial_pids: Set[int] = set()  # Store initially attached PIDs

    @staticmethod
    def is_available() -> bool:
        """Check if the strace executable is available in the system PATH."""
        return shutil.which("strace") is not None

    # --- Stream Reading Helper ---
    async def _read_stderr_lines(
        self, stderr: asyncio.StreamReader, stop_event: asyncio.Event
    ) -> AsyncIterator[str]:
        """Reads lines from the strace stderr stream asynchronously."""
        while not stop_event.is_set():
            try:
                line_bytes = await stderr.readline()
                if not line_bytes:
                    break
                # Use STRICT UTF-8 decoding
                line_str = line_bytes.decode("utf-8").rstrip("\n")
                yield line_str
            except UnicodeDecodeError as e:
                log.error(
                    f"UTF-8 Decode Error reading strace stderr: {e}. Offending bytes: {line_bytes[e.start:e.end]!r}"
                )
                raise  # Re-raise the exception to stop the stream processing
            except asyncio.CancelledError:
                break
            except Exception as read_err:
                if not stop_event.is_set():
                    log.exception(f"Error reading strace stderr: {read_err}")
                break

    # --- End Stream Reading Helper ---

    # --- Event Stream Processing ---
    async def _process_event_stream(
        self,
        event_stream: AsyncIterator[Syscall],
        pid_cwd_map: dict[int, str],
    ):
        """Internal helper method to process the stream of Syscall events."""
        processed_count = 0
        try:
            async for event in event_stream:
                if self.should_stop:
                    break
                processed_count += 1
                # Pass the initial PIDs set for context
                await _process_single_event(
                    event, self.monitor, pid_cwd_map, self._initial_pids
                )
        except asyncio.CancelledError:
            log.info("Event processing stream task cancelled.")
        finally:
            log.info(
                f"Exiting internal event processing loop. Processed {processed_count} events."
            )

    # --- End Event Stream Processing ---

    # --- Attach Method ---
    async def attach(self, pids: list[int]):
        """Implementation of the attach method."""
        if not pids:
            return
        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        self._initial_pids = set(pids)  # Store initial PIDs
        pid_cwd_map: dict[int, str] = {}
        for pid in pids:
            cwd = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd
            else:
                log.warning(f"Could not get initial CWD for attached PID {pid}.")

        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return

        strace_command = [
            strace_path,
            *STRACE_BASE_OPTIONS,
            "-e",
            f"trace={','.join(self.syscalls)}",
        ]
        valid_attach_ids = [str(pid) for pid in pids if psutil.pid_exists(pid)]
        if not valid_attach_ids:
            log.error("No valid PIDs/TIDs provided to attach to.")
            return
        strace_command.extend(["-p", ",".join(valid_attach_ids)])
        log.info(f"Preparing to attach (async) to existing IDs: {valid_attach_ids}")

        try:
            process = await asyncio.create_subprocess_exec(
                *strace_command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            self._strace_process = process
            strace_pid = process.pid
            self.monitor.backend_pid = strace_pid
            log.info(f"Strace started asynchronously with PID: {strace_pid}")
            if not process.stderr:
                log.error(f"Strace process {strace_pid} has no stderr stream!")
                await self.stop()
                return

            raw_lines = self._read_stderr_lines(process.stderr, self._should_stop)
            event_stream = parse_strace_stream(
                raw_lines,
                self.monitor,
                self._should_stop,
                syscalls=self.syscalls,
                attach_ids=pids,
            )
            await self._process_event_stream(event_stream, pid_cwd_map)

        except FileNotFoundError as e:
            log.error(f"Strace command failed: {e}")
        except ValueError as e:
            log.error(f"Strace configuration error: {e}")
        except asyncio.CancelledError:
            log.info("Strace attach task cancelled externally.")
        # Let other exceptions (like UnicodeDecodeError) propagate
        finally:
            log.info("Strace attach finished.")
            if not self.should_stop:
                await self.stop()

    # --- End Attach Method ---

    # --- Run Command Method ---
    async def run_command(self, command: list[str]):
        """Implementation of the run_command method."""
        if not command:
            log.error(f"{self.__class__.__name__}.run_command called empty.")
            return
        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        pid_cwd_map: dict[int, str] = {}
        self._initial_pids = set()  # No initial PIDs in run mode

        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return

        strace_command = [
            strace_path,
            *STRACE_BASE_OPTIONS,
            "-e",
            f"trace={','.join(self.syscalls)}",
        ]
        strace_command.extend(["--", *command])

        try:
            process = await asyncio.create_subprocess_exec(
                *strace_command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            self._strace_process = process
            strace_pid = process.pid
            self.monitor.backend_pid = strace_pid
            log.info(f"Strace started asynchronously with PID: {strace_pid}")
            if not process.stderr:
                log.error(f"Strace process {strace_pid} has no stderr stream!")
                await self.stop()
                return

            raw_lines = self._read_stderr_lines(process.stderr, self._should_stop)
            event_stream = parse_strace_stream(
                raw_lines, self.monitor, self._should_stop, syscalls=self.syscalls
            )
            await self._process_event_stream(event_stream, pid_cwd_map)

        except FileNotFoundError as e:
            log.error(f"Strace or target command failed: {e}")
        except ValueError as e:
            log.error(f"Strace configuration error: {e}")
        except asyncio.CancelledError:
            log.info("Strace run task cancelled externally.")
        # Let other exceptions (like UnicodeDecodeError) propagate
        finally:
            log.info("Strace run_command finished.")
            if not self.should_stop:
                await self.stop()

    # --- End Run Command Method ---

    # --- Stop Method ---
    async def stop(self):
        """Signals the backend's running task to stop and terminates the managed strace process."""
        if not self._should_stop.is_set():
            self._should_stop.set()
            process_to_term = self._strace_process
            pid_to_term = process_to_term.pid if process_to_term else -1
            await terminate_strace_process(process_to_term, pid_to_term)
            self._strace_process = None

    # --- End Stop Method ---


# --- End Backend Class ---
