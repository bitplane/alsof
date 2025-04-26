# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend implementation using pyparsing parser and a temporary FIFO."""

import asyncio
import logging
import os
import pathlib
import shlex
import shutil
import sys
import tempfile
from collections.abc import AsyncIterator
from typing import Any, Set

import psutil

# Corrected import path for handlers and helpers
from lsoph.backend.strace import handlers, helpers
from lsoph.log import TRACE_LEVEL_NUM
from lsoph.monitor import Monitor
from lsoph.util.fifo import temp_fifo
from lsoph.util.pid import get_cwd as pid_get_cwd

from ..base import Backend
from .parse import parse_strace_stream_pyparsing as parse_strace_stream
from .syscall import EXIT_SYSCALLS, PROCESS_SYSCALLS, Syscall
from .terminate import terminate_strace_process

log = logging.getLogger(__name__)

# --- Constants ---
STRACE_BASE_OPTIONS = ["-f", "-qq", "-s", "4096"]

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
        | {"chdir", "fchdir"}
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
    Receives Syscall object with string args from pyparsing parser.
    """
    pid = event.pid
    syscall_name = event.syscall

    log.debug(f"Processing event: {event!r}")

    # 1. Handle process creation CWD inheritance
    if (
        syscall_name in PROCESS_SYSCALLS
        and event.success
        and event.child_pid is not None
    ):
        child_pid = event.child_pid
        parent_cwd = cwd_map.get(pid)
        if parent_cwd:
            cwd_map[child_pid] = parent_cwd
            log.debug(
                f"PID {child_pid} inherited CWD from parent {pid}: "
                f"{os.fsdecode(parent_cwd)!r}"
            )
        else:
            log.warning(
                f"Parent PID {pid} CWD unknown for new child {child_pid}. "
                "Attempting direct lookup."
            )
            child_cwd = pid_get_cwd(child_pid)
            if child_cwd:
                cwd_map[child_pid] = child_cwd
                log.info(
                    f"Fetched CWD for new child PID {child_pid}: "
                    f"{os.fsdecode(child_cwd)!r}"
                )
            else:
                log.warning(f"Could not determine CWD for new child PID {child_pid}.")
        return  # Return after handling clone/fork

    # 2. Ensure CWD is known for other syscalls
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        cwd = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
            if pid in initial_pids:
                log.info(f"Fetched CWD for initial PID {pid}: {os.fsdecode(cwd)!r}")
            else:
                log.debug(f"Fetched CWD for PID {pid}: {os.fsdecode(cwd)!r}")
        else:
            if psutil.pid_exists(pid):
                log.warning(
                    f"Could not determine CWD for PID {pid} (still exists). "
                    "Relative paths may be incorrect."
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
    if handler:
        log.debug(f"Found handler for {syscall_name}: {handler.__name__}")
        try:
            handler(event, monitor, cwd_map)
        except Exception as e:
            log.exception(f"Handler error for {syscall_name} (event: {event!r}): {e}")
    else:
        log.debug(f"No specific handler found for syscall: {syscall_name}")


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
        self._initial_pids: Set[int] = set()
        self._output_read_task: asyncio.Task | None = None
        self._stderr_read_task: asyncio.Task | None = None

    @staticmethod
    def is_available() -> bool:
        """Check if the strace executable is available in the system PATH."""
        return shutil.which("strace") is not None

    async def _read_fifo(
        self, fifo_path: str, stop_event: asyncio.Event
    ) -> AsyncIterator[bytes]:
        """Reads lines (as bytes) from the strace output FIFO asynchronously using StreamReader."""
        log.debug(
            f"Attempting to open and read from FIFO: {fifo_path} using StreamReader"
        )
        reader = None
        transport = None
        read_fd = -1
        fifo_file_obj = None
        loop = asyncio.get_running_loop()

        try:
            # Open the FIFO for reading. This might block.
            log.debug(f"Opening FIFO {fifo_path} (blocking)...")
            read_fd = os.open(fifo_path, os.O_RDONLY)
            log.debug(f"Opened FIFO {fifo_path} with FD {read_fd}")

            # Create a file object from the FD for connect_read_pipe with raw I/O
            fifo_file_obj = os.fdopen(read_fd, "rb", buffering=0)
            read_fd = -1  # FD is now owned by fifo_file_obj

            # Create StreamReader and connect it to the pipe file object
            reader = asyncio.StreamReader(loop=loop)
            protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
            transport, _ = await loop.connect_read_pipe(lambda: protocol, fifo_file_obj)
            log.debug(f"Connected FIFO read via file object to StreamReader")

            while not stop_event.is_set():
                try:
                    line_bytes = await reader.readline()
                    if not line_bytes:
                        log.debug(f"FIFO {fifo_path} EOF reached.")
                        break  # EOF

                    # Strip trailing newline bytes
                    if line_bytes.endswith(b"\n"):
                        line_bytes = line_bytes[:-1]
                    if line_bytes.endswith(b"\r"):
                        line_bytes = line_bytes[:-1]

                    yield line_bytes

                except asyncio.IncompleteReadError:
                    log.debug("Incomplete read from FIFO, likely closed.")
                    break
                except asyncio.CancelledError:
                    log.info("FIFO reading task cancelled.")
                    break
                except Exception as read_err:
                    if not stop_event.is_set():
                        log.exception(f"Error reading FIFO {fifo_path}: {read_err}")
                    break

        except FileNotFoundError:
            # This can happen if the context manager cleans up before we open
            if not stop_event.is_set():  # Only log error if not stopping anyway
                log.error(
                    f"FIFO path not found (likely already cleaned up): {fifo_path}"
                )
        except Exception as e:
            log.exception(f"Failed to open or read FIFO {fifo_path}: {e}")
        finally:
            log.debug(f"Cleaning up FIFO reader for {fifo_path}.")
            if transport and not transport.is_closing():
                transport.close()

            # Close the file object if it was created
            if fifo_file_obj:
                try:
                    fifo_file_obj.close()
                    log.debug(f"Closed FIFO file object for {fifo_path}")
                except Exception as close_err:
                    log.warning(f"Error closing FIFO file object: {close_err}")
            # Ensure original FD is closed if fdopen failed
            elif read_fd != -1:
                try:
                    os.close(read_fd)
                except OSError:
                    pass

    async def _read_and_log_stderr(
        self, stderr: asyncio.StreamReader | None, stop_event: asyncio.Event
    ):
        """Reads strace's stderr pipe and logs any output."""
        if not stderr:
            log.warning("Strace process has no stderr stream to monitor.")
            return

        log.debug("Starting strace stderr reader task.")
        try:
            while not stop_event.is_set():
                try:
                    line_bytes = await stderr.readline()
                    if not line_bytes:
                        log.debug("Strace stderr EOF reached.")
                        break

                    line_str = line_bytes.decode("utf-8", "replace").rstrip()
                    # Log strace's own messages at WARNING level to make them visible
                    log.warning(f"Strace stderr: {line_str}")
                except asyncio.IncompleteReadError:
                    log.debug("Incomplete read from strace stderr, likely closed.")
                    break
                except asyncio.CancelledError:
                    log.info("Strace stderr reader task cancelled.")
                    break
                except Exception as e:
                    if not stop_event.is_set():
                        log.exception(f"Error reading strace stderr: {e}")
                    break
        finally:
            log.debug("Exiting strace stderr reader task.")

    async def _process_event_stream(
        self,
        event_stream: AsyncIterator[Syscall],
        pid_cwd_map: dict[int, bytes],
        initial_pids: Set[int],
    ):
        """
        Internal helper method to process the stream of Syscall events.
        """
        log.debug("Starting event processing stream...")
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
                # Yield control periodically for responsiveness
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            log.info("Event processing stream task cancelled.")
        finally:
            log.info(
                f"Exiting internal event processing loop. Processed {processed_count} events."
            )

    async def _consume_fifo_stream(
        self, fifo_path: str, pid_cwd_map: dict[int, bytes], attach_ids: list[int]
    ):
        """Helper coroutine to read FIFO lines, parse, and process events."""
        try:
            # Get the async iterator for reading lines
            fifo_output_lines = self._read_fifo(fifo_path, self._should_stop)

            # Create the event stream using the parser
            event_stream = parse_strace_stream(
                fifo_output_lines,
                self.monitor,
                self._should_stop,
                syscalls=self.syscalls,
                attach_ids=attach_ids,
            )

            # Process the event stream
            await self._process_event_stream(
                event_stream, pid_cwd_map, self._initial_pids
            )
        except asyncio.CancelledError:
            log.info("FIFO consumer task cancelled.")
        except Exception as e:
            log.exception(f"Error in FIFO consumer task: {e}")

    async def _launch_strace(
        self,
        strace_command: list[str],
        pid_cwd_map: dict[int, bytes],
        attach_ids: list[int] | None,
    ):
        """Launches strace, sets up FIFO reading, stderr reading, and processes events."""
        try:
            with temp_fifo(prefix="lsoph_strace_") as fifo_path:
                # 1. Add the -o option pointing to the FIFO
                strace_command_with_output = strace_command + ["-o", fifo_path]
                log.info(
                    f"Executing strace command: "
                    f"{' '.join(shlex.quote(s) for s in strace_command_with_output)}"
                )

                # 2. Launch strace process, capturing its stderr
                process = await asyncio.create_subprocess_exec(
                    *strace_command_with_output,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,  # Capture strace's own stderr
                )
                self._strace_process = process
                strace_pid = process.pid
                self.monitor.backend_pid = strace_pid
                log.info(f"Strace started asynchronously with PID: {strace_pid}")

                # 3. Start task to read strace's stderr pipe
                self._stderr_read_task = asyncio.create_task(
                    self._read_and_log_stderr(process.stderr, self._should_stop),
                    name=f"strace_stderr_reader_{strace_pid}",
                )

                # 4. Start reading from the FIFO and processing in a separate task
                self._output_read_task = asyncio.create_task(
                    self._consume_fifo_stream(
                        fifo_path,
                        pid_cwd_map,
                        attach_ids if attach_ids else list(self._initial_pids),
                    ),
                    name=f"strace_fifo_processor_{strace_pid}",
                )

                # 5. Wait for the main FIFO processor task OR strace process exit
                process_wait_task = asyncio.create_task(
                    process.wait(), name=f"strace_wait_{strace_pid}"
                )
                tasks_to_wait = [self._output_read_task, process_wait_task]
                done, pending = await asyncio.wait(
                    tasks_to_wait, return_when=asyncio.FIRST_COMPLETED
                )

                # Check results
                process_exited_first = process_wait_task in done
                fifo_task_finished_first = self._output_read_task in done

                if process_exited_first:
                    exit_code = process_wait_task.result()
                    log.info(
                        f"Strace process {strace_pid} exited first (code {exit_code})."
                    )
                    # Cancel the FIFO processor if it's still running
                    if self._output_read_task in pending:
                        log.info("Cancelling FIFO processing task as strace exited.")
                        self._output_read_task.cancel()
                elif fifo_task_finished_first:
                    log.info("FIFO processing task completed.")
                    # Check if strace process also exited
                    if process.returncode is not None:
                        log.info(
                            f"Strace process {strace_pid} also exited "
                            f"(code {process.returncode})."
                        )
                    else:
                        log.warning(
                            f"FIFO processing finished but strace process "
                            f"{strace_pid} still running?"
                        )
                        # Wait briefly for strace to exit naturally
                        try:
                            await asyncio.wait_for(process_wait_task, timeout=1.0)
                            log.info(
                                f"Strace process {strace_pid} exited after FIFO processing "
                                f"(code {process_wait_task.result()})."
                            )
                        except asyncio.TimeoutError:
                            log.warning(
                                f"Strace process {strace_pid} did not exit promptly "
                                f"after FIFO processing."
                            )

                # Ensure completed tasks are awaited to retrieve potential exceptions
                for task in done:
                    if task and not task.cancelled():
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass  # Expected
                        except Exception as e:
                            log.exception(
                                f"Error retrieving result from completed task "
                                f"{task.get_name()}: {e}"
                            )

        except FileNotFoundError as e:
            log.error(f"Strace command failed: {e}")
        except ValueError as e:
            log.error(f"Strace configuration error: {e}")
        except RuntimeError as e:  # Catch FIFO creation errors
            log.error(f"Strace setup failed: {e}")
        except asyncio.CancelledError:
            log.info("Strace task cancelled externally.")
        except Exception as e:
            log.exception(f"Unexpected error during strace launch/processing: {e}")
        finally:
            log.info("Strace launch/processing finished.")
            # FIFO/temp dir cleanup handled by context manager
            # Ensure strace process is stopped if loop didn't handle it
            if not self.should_stop:
                await self.stop()  # Calls terminate_strace_process

    async def attach(self, pids: list[int]):
        """Implementation of the attach method. Uses bytes CWD map and FIFO."""
        if not pids:
            return

        log.info(f"Attaching strace to PIDs/TIDs: {pids}")
        self._initial_pids = set(pids)
        pid_cwd_map: dict[int, bytes] = {}

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

        await self._launch_strace(strace_command, pid_cwd_map, attach_ids=pids)

    async def run_command(self, command: list[str]):
        """Implementation of the run_command method. Uses bytes CWD map and FIFO."""
        if not command:
            log.error(f"{self.__class__.__name__}.run_command called empty.")
            return

        log.info(
            f"Running command via strace: {' '.join(shlex.quote(c) for c in command)}"
        )
        pid_cwd_map: dict[int, bytes] = {}
        self._initial_pids = set()

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

        await self._launch_strace(strace_command, pid_cwd_map, attach_ids=None)

    async def stop(self):
        """Signals the backend's running task to stop and terminates the strace process."""
        if not self._should_stop.is_set():
            log.info("Stopping Strace backend...")
            self._should_stop.set()

            # Cancel the FIFO reader/processor task first
            if self._output_read_task and not self._output_read_task.done():
                log.debug("Cancelling FIFO processor/logger task...")
                self._output_read_task.cancel()
                try:
                    await self._output_read_task  # Allow cancellation to complete
                except asyncio.CancelledError:
                    pass  # Expected
                log.debug("FIFO processor/logger task cancelled.")
            self._output_read_task = None

            # Cancel the stderr reader task
            if self._stderr_read_task and not self._stderr_read_task.done():
                log.debug("Cancelling strace stderr reader task...")
                self._stderr_read_task.cancel()
                try:
                    await self._stderr_read_task
                except asyncio.CancelledError:
                    pass  # Expected
                log.debug("Strace stderr reader task cancelled.")
            self._stderr_read_task = None

            # Terminate the strace process
            process_to_term = self._strace_process
            pid_to_term = process_to_term.pid if process_to_term else -1
            await terminate_strace_process(process_to_term, pid_to_term)
            self._strace_process = None
            log.info("Strace backend stopped.")
