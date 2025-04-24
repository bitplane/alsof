# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend implementation using refactored components. Works with bytes paths."""

import asyncio
import logging
import os  # For os.fsdecode
import shlex
import shutil
import sys
from collections.abc import AsyncIterator
from typing import Any, Set

import psutil  # Keep for pid_exists check

# Corrected import path for handlers and helpers
# Handlers now expect bytes cwd_map, helpers work with bytes paths
from lsoph.backend.strace import handlers, helpers
from lsoph.monitor import Monitor

# pid_get_cwd now returns bytes
from lsoph.util.pid import get_cwd as pid_get_cwd

from ..base import Backend

# parse_strace_stream yields Syscall objects
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
    event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes], initial_pids: Set[int]
):
    """
    Processes a single Syscall event, updating state and CWD map (bytes).
    Handles CWD inheritance for new processes.
    """
    pid = event.pid
    syscall_name = event.syscall  # This is str

    # --- ADDED: Log entry to this function ---
    log.debug(f"Processing event: {event!r}")
    # -----------------------------------------

    # 1. Handle process creation CWD inheritance
    if (
        syscall_name in PROCESS_SYSCALLS
        and event.success
        and event.child_pid is not None
    ):
        child_pid = event.child_pid
        parent_cwd: bytes | None = cwd_map.get(pid)
        if parent_cwd:
            cwd_map[child_pid] = parent_cwd
            log.debug(
                f"PID {child_pid} inherited CWD from parent {pid}: {os.fsdecode(parent_cwd)!r}"
            )
        else:
            log.warning(
                f"Parent PID {pid} CWD unknown for new child {child_pid}. Attempting direct lookup."
            )
            child_cwd: bytes | None = pid_get_cwd(child_pid)
            if child_cwd:
                cwd_map[child_pid] = child_cwd
                log.info(
                    f"Fetched CWD for new child PID {child_pid}: {os.fsdecode(child_cwd)!r}"
                )
            else:
                log.warning(f"Could not determine CWD for new child PID {child_pid}.")
        return  # Return after handling clone/fork

    # 2. Ensure CWD is known for other syscalls
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        cwd: bytes | None = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
            if pid in initial_pids:
                log.info(f"Fetched CWD for initial PID {pid}: {os.fsdecode(cwd)!r}")
            else:
                log.debug(
                    f"Fetched CWD for PID {pid}: {os.fsdecode(cwd)!r}"
                )  # Log CWD fetch for non-initial too
        else:
            if psutil.pid_exists(pid):
                log.warning(
                    f"Could not determine CWD for PID {pid} (still exists). Relative paths may be incorrect."
                )
            else:
                log.debug(f"Could not determine CWD for PID {pid} (process exited).")

    # 3. Handle chdir/fchdir
    if syscall_name in ["chdir", "fchdir"]:
        log.debug(f"Dispatching {syscall_name} to handlers.update_cwd")
        handlers.update_cwd(pid, cwd_map, monitor, event)
        return

    # 4. Handle exit
    if syscall_name in EXIT_SYSCALLS:
        log.debug(f"Dispatching {syscall_name} to monitor.process_exit")
        monitor.process_exit(pid, event.timestamp)
        if pid in cwd_map:
            del cwd_map[pid]
        return

    # 5. Dispatch to generic handlers
    handler = handlers.SYSCALL_HANDLERS.get(syscall_name)
    # --- ADDED: Log handler lookup result ---
    if handler:
        log.debug(f"Found handler for {syscall_name}: {handler.__name__}")
        try:
            handler(event, monitor, cwd_map)
        except Exception as e:
            log.exception(f"Handler error for {syscall_name} (event: {event!r}): {e}")
    else:
        # Log if no handler is found for a syscall that isn't explicitly ignored above
        log.debug(f"No specific handler found for syscall: {syscall_name}")
    # --------------------------------------


# --- End Event Processing Helper ---


# --- Backend Class ---
class Strace(Backend):
    """Async backend implementation using strace (refactored). Works with bytes paths."""

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
    ) -> AsyncIterator[bytes]:  # Yields bytes
        """Reads lines (as bytes) from the strace stderr stream asynchronously, stripping newline."""
        while not stop_event.is_set():
            try:
                line_bytes = await stderr.readline()  # Reads up to and including \n
                if not line_bytes:
                    break
                # --- FIX: Strip trailing newline bytes ---
                if line_bytes.endswith(b"\n"):
                    line_bytes = line_bytes[:-1]
                if line_bytes.endswith(b"\r"):  # Handle potential \r\n on some systems
                    line_bytes = line_bytes[:-1]
                # ---------------------------------------
                # Yield stripped bytes
                yield line_bytes
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
        pid_cwd_map: dict[int, bytes],  # Expects bytes CWD map
    ):
        """Internal helper method to process the stream of Syscall events."""
        processed_count = 0
        try:
            async for event in event_stream:
                if self.should_stop:
                    break
                processed_count += 1
                # Pass the initial PIDs set and bytes CWD map for context
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
        """Implementation of the attach method. Uses bytes CWD map."""
        if not pids:
            return
        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        self._initial_pids = set(pids)  # Store initial PIDs
        # --- CWD MAP IS NOW BYTES ---
        pid_cwd_map: dict[int, bytes] = {}
        # ---------------------------
        for pid in pids:
            # pid_get_cwd returns bytes
            cwd: bytes | None = pid_get_cwd(pid)
            if cwd:
                pid_cwd_map[pid] = cwd  # Store bytes
            else:
                log.warning(f"Could not get initial CWD for attached PID {pid}.")

        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return

        # Command list uses strings
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

            # _read_stderr_lines yields bytes (now stripped)
            raw_lines_bytes = self._read_stderr_lines(process.stderr, self._should_stop)
            # parse_strace_stream accepts bytes, yields Syscall
            event_stream = parse_strace_stream(
                raw_lines_bytes,
                self.monitor,
                self._should_stop,
                syscalls=self.syscalls,
                attach_ids=pids,
            )
            # Pass bytes CWD map
            await self._process_event_stream(event_stream, pid_cwd_map)

        except FileNotFoundError as e:
            log.error(f"Strace command failed: {e}")
        except ValueError as e:
            log.error(f"Strace configuration error: {e}")
        except asyncio.CancelledError:
            log.info("Strace attach task cancelled externally.")
        # Let other exceptions propagate
        finally:
            log.info("Strace attach finished.")
            if not self.should_stop:
                await self.stop()

    # --- End Attach Method ---

    # --- Run Command Method ---
    async def run_command(self, command: list[str]):
        """Implementation of the run_command method. Uses bytes CWD map."""
        if not command:
            log.error(f"{self.__class__.__name__}.run_command called empty.")
            return
        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        # --- CWD MAP IS NOW BYTES ---
        pid_cwd_map: dict[int, bytes] = {}
        # ---------------------------
        self._initial_pids = set()  # No initial PIDs in run mode

        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return

        # Command list uses strings
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

            # _read_stderr_lines yields bytes (now stripped)
            raw_lines_bytes = self._read_stderr_lines(process.stderr, self._should_stop)
            # parse_strace_stream accepts bytes, yields Syscall
            event_stream = parse_strace_stream(
                raw_lines_bytes, self.monitor, self._should_stop, syscalls=self.syscalls
            )
            # Pass bytes CWD map
            await self._process_event_stream(event_stream, pid_cwd_map)

        except FileNotFoundError as e:
            log.error(f"Strace or target command failed: {e}")
        except ValueError as e:
            log.error(f"Strace configuration error: {e}")
        except asyncio.CancelledError:
            log.info("Strace run task cancelled externally.")
        # Let other exceptions propagate
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
