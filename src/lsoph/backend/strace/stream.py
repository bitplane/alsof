# Filename: src/lsoph/backend/strace/stream.py
"""Contains logic for running strace and streaming its output."""

import asyncio
import logging
import shlex
import shutil
from typing import TYPE_CHECKING, AsyncIterator, List, Optional

import psutil

from lsoph.monitor import Monitor

# Import from the new terminate module
from .terminate import terminate_strace_process

# Use TYPE_CHECKING to avoid circular import for type hint
if TYPE_CHECKING:
    from .backend import StraceBackend

log = logging.getLogger(__name__)

# Define constants needed by this module
STRACE_BASE_OPTIONS = ["-f", "-s", "4096", "-xx", "-o", "/dev/stderr"]


async def stream_strace_output(
    # Add backend instance parameter
    backend: "StraceBackend",
    monitor: Monitor,
    should_stop: asyncio.Event,
    target_command: Optional[list[str]] = None,
    attach_ids: Optional[list[int]] = None,
    syscalls: Optional[list[str]] = None,  # Made optional, default handled elsewhere
) -> AsyncIterator[str]:
    """
    Asynchronously runs strace, reads its stderr pipe directly, and yields lines.
    Handles cancellation via the should_stop event. Stores process handle on backend.
    """
    # --- Add Logging Here ---
    log.debug(
        f"stream_strace_output called with target_command={target_command!r}, attach_ids={attach_ids!r}"
    )
    # --- End Logging ---

    # Validate arguments
    if target_command and attach_ids:
        # This is where the error is happening
        log.error(
            f"Validation failed! Both target_command ({target_command!r}) and attach_ids ({attach_ids!r}) have values."
        )
        raise ValueError("Cannot provide both target_command and attach_ids.")
    if not target_command and not attach_ids:
        raise ValueError("Must provide target_command or attach_ids.")
    if not syscalls:
        raise ValueError("Syscall list cannot be empty.")

    # Find strace executable
    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable.")

    # Initialize state variables
    process: asyncio.subprocess.Process | None = None
    strace_pid = -1
    monitor.backend_pid = None
    # Clear any stale process handle on the backend instance
    backend._strace_process = None

    try:
        # Construct the strace command
        strace_command = [
            strace_path,
            *STRACE_BASE_OPTIONS,
            "-e",
            f"trace={','.join(syscalls)}",
        ]

        # Add target command or PIDs to attach
        if target_command:
            strace_command.extend(["--", *target_command])
            log.info(
                f"Preparing to launch (async): {' '.join(shlex.quote(c) for c in target_command)}"
            )
        elif attach_ids:
            valid_attach_ids = [
                str(pid) for pid in attach_ids if psutil.pid_exists(pid)
            ]
            if not valid_attach_ids:
                raise ValueError("No valid PIDs/TIDs provided to attach to.")
            strace_command.extend(["-p", ",".join(valid_attach_ids)])
            log.info(f"Preparing to attach (async) to existing IDs: {valid_attach_ids}")

        # Execute the strace command asynchronously, capturing stderr
        log.info(f"Executing async: {' '.join(shlex.quote(c) for c in strace_command)}")
        process = await asyncio.create_subprocess_exec(
            *strace_command,
            stdout=asyncio.subprocess.DEVNULL,  # Ignore stdout
            stderr=asyncio.subprocess.PIPE,  # Capture stderr directly
        )
        # --- Store process handle on backend instance ---
        backend._strace_process = process
        # --- End Store ---
        strace_pid = process.pid
        monitor.backend_pid = strace_pid
        log.info(f"Strace started asynchronously with PID: {strace_pid}")

        # --- Read directly from stderr pipe ---
        if process.stderr:
            log.debug(f"Reading directly from strace process {strace_pid} stderr...")
            read_count = 0
            while not should_stop.is_set():
                try:
                    log.debug(
                        f"Attempting readline on strace {strace_pid} stderr (read {read_count} lines so far)..."
                    )
                    line_bytes = await process.stderr.readline()
                    log.debug(
                        f"Readline completed for strace {strace_pid}. EOF: {not line_bytes}. Bytes: {line_bytes!r}"
                    )

                    if not line_bytes:
                        log.info(
                            f"EOF reached on strace process {strace_pid} stderr after reading {read_count} lines."
                        )
                        break

                    read_count += 1
                    line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\n")
                    yield line_str

                except asyncio.CancelledError:
                    log.info(
                        f"Stderr readline task cancelled after reading {read_count} lines."
                    )
                    break
                except Exception as read_err:
                    log.exception(
                        f"Error reading strace stderr after {read_count} lines: {read_err}"
                    )
                    break
        else:
            log.error(f"Strace process {strace_pid} has no stderr stream.")

        if should_stop.is_set():
            log.info("Stop event received, exiting stream.")

        if process and process.returncode is None:
            log.debug(
                f"Waiting for strace process {strace_pid} to exit after stream processing."
            )
            try:
                await asyncio.wait_for(process.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                log.debug(
                    f"Strace process {strace_pid} did not exit promptly after stream end."
                )
            except Exception as wait_err:
                log.error(
                    f"Error waiting for strace process {strace_pid} exit: {wait_err}"
                )

    except FileNotFoundError as e:
        log.error(f"Strace command not found: {e}.")
        raise
    except ValueError as e:
        log.error(f"Strace configuration error: {e}")
        raise
    except asyncio.CancelledError:
        log.info("stream_strace_output task cancelled.")
    except Exception as e:
        log.exception(
            f"Error during async strace execution/setup (PID {strace_pid}): {e}"
        )
        raise
    finally:
        log.info(
            f"Cleaning up async stream_strace_output (strace PID: {strace_pid if strace_pid != -1 else 'unknown'})..."
        )
        # This line clears the PID stored on the central monitor state object
        monitor.backend_pid = None
        # --- Clear process handle on backend instance ---
        stored_process = backend._strace_process
        backend._strace_process = None
        # --- End Clear ---
        # Use the local 'process' or the 'stored_process' for termination
        process_to_terminate = process if process else stored_process
        await terminate_strace_process(process_to_terminate, strace_pid)
