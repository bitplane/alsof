# Filename: src/lsoph/backend/strace_cmd.py

import asyncio
import contextlib
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

# Use Python 3.10+ style hints
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import List, Optional, TextIO

import psutil

from lsoph.monitor import Monitor

log = logging.getLogger("lsoph.backend.strace_cmd")

# --- Constants ---
PROCESS_SYSCALLS = ["clone", "fork", "vfork"]
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
EXIT_SYSCALLS = ["exit_group"]
DEFAULT_SYSCALLS = sorted(
    list(
        set(
            PROCESS_SYSCALLS
            + FILE_STRUCT_SYSCALLS
            + IO_SYSCALLS
            + EXIT_SYSCALLS
            + ["chdir", "fchdir"]
        )
    )
)
# Removed -qq to allow attach/error messages on stderr
STRACE_BASE_OPTIONS = ["-f", "-s", "4096", "-xx"]  # Removed -qq
STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"
    r"(?P<syscall>\w+)\("
    r"(?P<args>.*?)"
    r"\)\s+=\s+"
    r"(?P<result>-?\d+|\?|0x[\da-fA-F]+)"
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
    r"(?:\s+<(?P<tag>unfinished|resumed)\s+...>)?$"
)
QUEUE_END_SENTINEL = object()


@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    timestamp: float
    tid: int
    pid: int
    syscall: str
    args: list[str]
    result_str: str
    error_name: Optional[str] = None
    error_msg: Optional[str] = None


# --- Helper Functions (synchronous) ---
def _parse_args_state_machine(args_str: str) -> list[str]:
    """Parses the complex argument string from strace output."""
    args = []
    current_arg = ""
    nesting_level = 0
    in_quotes = False
    escape_next = False
    i = 0
    n = len(args_str)
    while i < n:
        char = args_str[i]
        append_char = True
        if escape_next:
            escape_next = False
        elif char == "\\":
            escape_next = True
        elif char == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if char in ("(", "{", "["):
                nesting_level += 1
            elif char in (")", "}", "]"):
                nesting_level = max(0, nesting_level - 1)
            elif char == "," and nesting_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
                append_char = False
        if append_char:
            current_arg += char
        i += 1
    args.append(current_arg.strip())
    return [arg for arg in args if arg]


@contextlib.contextmanager
def temporary_fifo() -> Iterator[str]:
    """Creates and yields the path to a temporary FIFO, cleaning up afterwards."""
    fifo_path = None
    temp_dir = None
    try:
        with tempfile.TemporaryDirectory(prefix="strace_fifo_") as temp_dir_path:
            temp_dir = temp_dir_path
            fifo_path = os.path.join(temp_dir, "strace_output.fifo")
            os.mkfifo(fifo_path)
            log.info(f"Created temporary FIFO: {fifo_path}")
            yield fifo_path
    except OSError as e:
        raise RuntimeError(f"Failed to create FIFO in {temp_dir}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to set up temporary directory/FIFO: {e}") from e
    finally:
        if fifo_path:
            log.debug(f"FIFO {fifo_path} will be cleaned up with directory {temp_dir}.")


# --- Blocking FIFO Reader Function (puts lines into asyncio.Queue) ---
def _read_fifo_blocking_to_queue(
    fifo_path: str,
    should_stop: asyncio.Event,
    queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
):
    """Opens FIFO, reads lines, puts into queue. Runs in thread."""
    log.info(f"Blocking reader thread trying to open FIFO: {fifo_path}")
    fifo_f: Optional[TextIO] = None
    lines_read = 0
    try:
        fifo_f = open(fifo_path, "r", encoding="utf-8", errors="replace")
        log.info(f"Blocking reader thread opened FIFO: {fifo_path}")
        while not should_stop.is_set():
            line = fifo_f.readline()
            if not line:
                log.info("EOF reached on strace output FIFO (blocking read).")
                break
            loop.call_soon_threadsafe(queue.put_nowait, line.rstrip("\n"))
            lines_read += 1
            time.sleep(0.001)
    except FileNotFoundError:
        log.error(f"FIFO path not found: {fifo_path}")
    except Exception as e:
        log.exception(f"Error reading FIFO in blocking thread: {e}")
    finally:
        if fifo_f:
            try:
                fifo_f.close()
                log.info("Blocking reader thread closed FIFO.")
            except Exception as close_e:
                log.warning(f"Error closing FIFO in blocking reader: {close_e}")
        log.info(
            f"Reader thread finished. Read {lines_read} lines. Signalling queue end."
        )
        loop.call_soon_threadsafe(queue.put_nowait, QUEUE_END_SENTINEL)


# --- Async Strace Command Execution and Output Streaming ---
async def _terminate_strace_process(
    process: asyncio.subprocess.Process | None, pid: int
):
    """Helper to terminate the strace process robustly."""
    if not process or process.returncode is not None:
        return
    log.warning(f"Attempting to terminate strace process (PID: {pid})...")
    stderr_bytes = b""  # To store stderr
    try:
        log.debug(f"Sending SIGTERM to strace process {pid}")
        process.terminate()
        # Capture stderr while waiting
        try:
            _, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=1.5)
        except asyncio.TimeoutError:
            log.warning(
                f"Strace process {pid} did not exit after SIGTERM, sending SIGKILL."
            )
            raise  # Re-raise timeout to trigger kill block
        except Exception as comm_err:
            log.error(
                f"Error communicating with strace process {pid} during terminate: {comm_err}"
            )
            # Process might be stuck, proceed to kill
            raise asyncio.TimeoutError  # Treat as timeout to trigger kill

        log.info(
            f"Strace process {pid} terminated gracefully (SIGTERM, code {process.returncode})."
        )
        # Log stderr if needed after graceful exit
        if process.returncode != 0 and stderr_bytes:
            log.warning(
                f"Strace {pid} stderr (exit {process.returncode}):\n{stderr_bytes.decode('utf-8', 'replace').strip()}"
            )
        return  # Success
    except ProcessLookupError:
        log.warning(f"Strace process {pid} already exited before SIGTERM.")
        return
    except asyncio.TimeoutError:
        pass  # Expected if terminate timed out, proceed to kill
    except Exception as term_err:
        log.exception(f"Error during SIGTERM for strace {pid}: {term_err}")

    # If SIGTERM failed or timed out, try SIGKILL
    if process.returncode is None:
        try:
            log.debug(f"Sending SIGKILL to strace process {pid}")
            process.kill()
            # Capture stderr after kill (might not get much)
            try:
                _, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=1.0
                )
            except asyncio.TimeoutError:
                log.error(f"Strace process {pid} did not exit even after SIGKILL!")
            except Exception as comm_err:
                log.error(
                    f"Error communicating with strace process {pid} after kill: {comm_err}"
                )

            log.info(
                f"Strace process {pid} killed (SIGKILL, code {process.returncode})."
            )
            # Log stderr after kill
            if stderr_bytes:
                log.warning(
                    f"Strace {pid} stderr (after kill, exit {process.returncode}):\n{stderr_bytes.decode('utf-8', 'replace').strip()}"
                )

        except ProcessLookupError:
            log.warning(f"Strace process {pid} already exited before SIGKILL.")
        except Exception as kill_err:
            log.exception(f"Error during SIGKILL for strace {pid}: {kill_err}")


async def stream_strace_output(
    monitor: Monitor,
    should_stop: asyncio.Event,
    target_command: Optional[list[str]] = None,
    attach_ids: Optional[list[int]] = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> AsyncIterator[str]:
    """
    Asynchronously runs strace, reads output via a queue filled by a blocking reader thread,
    and yields lines. Handles cancellation via the should_stop event.
    """
    if not target_command and not attach_ids:
        raise ValueError("Must provide target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")
    if not syscalls:
        raise ValueError("Syscall list cannot be empty.")
    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable.")

    process: asyncio.subprocess.Process | None = None
    strace_pid = -1
    monitor.backend_pid = None
    reader_thread_task: asyncio.Task | None = None
    queue: asyncio.Queue[str | object] = asyncio.Queue(maxsize=2000)
    loop = asyncio.get_running_loop()
    stderr_capture = b""  # Variable to store stderr

    try:
        with temporary_fifo() as fifo_path:
            # Use STRACE_BASE_OPTIONS which no longer includes -qq
            strace_command = [
                strace_path,
                *STRACE_BASE_OPTIONS,
                "-e",
                f"trace={','.join(syscalls)}",
                "-o",
                fifo_path,
            ]
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
                log.info(
                    f"Preparing to attach (async) to existing IDs: {valid_attach_ids}"
                )

            log.info(
                f"Executing async: {' '.join(shlex.quote(c) for c in strace_command)}"
            )
            process = await asyncio.create_subprocess_exec(
                *strace_command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,  # Capture stderr
            )
            strace_pid = process.pid
            monitor.backend_pid = strace_pid
            log.info(f"Strace started asynchronously with PID: {strace_pid}")

            try:
                # Wait briefly, check exit code, capture stderr
                await asyncio.wait_for(
                    process.wait(), timeout=0.3
                )  # Slightly longer timeout
                # If it exited, read stderr
                if process.stderr:
                    stderr_capture = await process.stderr.read()
                raise RuntimeError(
                    f"Strace process (PID {strace_pid}) exited immediately (code {process.returncode}). "
                    f"Stderr: {stderr_capture.decode('utf-8', 'replace')[:500]}"
                )
            except asyncio.TimeoutError:
                log.debug(f"Strace process {strace_pid} running.")
            except Exception as wait_err:
                log.error(f"Error checking initial strace status: {wait_err}")
                raise

            log.info("Starting blocking FIFO reader thread to fill queue...")
            reader_thread_task = asyncio.create_task(
                asyncio.to_thread(
                    _read_fifo_blocking_to_queue, fifo_path, should_stop, queue, loop
                ),
                name=f"fifo_reader_{strace_pid}",
            )

            # --- Read from Queue Async ---
            while not should_stop.is_set():
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=0.1)
                    queue.task_done()
                    if item is QUEUE_END_SENTINEL:
                        log.info("Received queue end sentinel.")
                        break
                    elif isinstance(item, str):
                        yield item
                    else:
                        log.warning(
                            f"Received unexpected item from queue: {type(item)}"
                        )
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    log.info("Queue get task cancelled.")
                    break
                except Exception as q_err:
                    log.exception(f"Error processing item from queue: {q_err}")
                    break

            if should_stop.is_set():
                log.info("Stop event received, exiting stream.")

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
        monitor.backend_pid = None
        # Ensure reader task is handled
        if reader_thread_task and not reader_thread_task.done():
            log.debug("Final cleanup: Waiting briefly for reader task to finish.")
            try:
                await asyncio.wait_for(reader_thread_task, timeout=0.5)
            except asyncio.TimeoutError:
                log.warning("Reader task did not finish quickly during cleanup.")
            except asyncio.CancelledError:
                pass
        # Ensure strace process is terminated and log final stderr
        await _terminate_strace_process(process, strace_pid)


# --- Async Generator: Parsing the Stream ---
# parse_strace_stream remains the same internally as previous async version
async def parse_strace_stream(
    monitor: Monitor,
    should_stop: asyncio.Event,
    target_command: Optional[list[str]] = None,
    attach_ids: Optional[list[int]] = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> AsyncIterator[Syscall]:
    """
    Asynchronously runs strace via stream_strace_output and parses lines into Syscall objects.
    """
    log.info("Starting async parse_strace_stream...")
    tid_to_pid_map: dict[int, int] = {}
    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        for initial_tid in attach_ids:
            try:
                if not psutil.pid_exists(initial_tid):
                    continue
                proc_info = psutil.Process(initial_tid)
                pid = proc_info.pid
                tid_to_pid_map[initial_tid] = pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                tid_to_pid_map[initial_tid] = initial_tid
                log.warning(
                    f"Error getting PID for initial TID {initial_tid}: {e}. Mapping TID to itself."
                )

    combined_syscalls = sorted(
        list(set(syscalls) | set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS))
    )

    try:
        async for line in stream_strace_output(
            monitor, should_stop, target_command, attach_ids, combined_syscalls
        ):
            if should_stop.is_set():
                break
            timestamp = time.time()
            match = STRACE_LINE_RE.match(line)
            if not match:
                continue
            data = match.groupdict()
            if data.get("tag") in ("unfinished", "resumed"):
                continue
            try:
                tid = int(data["tid"])
                syscall = data["syscall"]
                args_str = data["args"]
                result_str = data["result"]
                error_name = data.get("error")
                error_msg = data.get("errmsg")
                pid = tid_to_pid_map.get(tid)
                if pid is None:
                    try:
                        if psutil.pid_exists(tid):
                            proc_info = psutil.Process(tid)
                            pid = proc_info.pid
                            tid_to_pid_map[tid] = pid
                        else:
                            pid = tid
                            tid_to_pid_map[tid] = pid
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        Exception,
                    ) as map_e:
                        pid = tid
                        tid_to_pid_map[tid] = pid
                        log.warning(
                            f"Error looking up PID for TID {tid} ({map_e}), assuming PID=TID."
                        )
                parsed_args_list = _parse_args_state_machine(args_str)
                if syscall in PROCESS_SYSCALLS and error_name is None:
                    try:
                        new_id_str = result_str
                        new_id = (
                            int(new_id_str) if new_id_str and new_id_str != "?" else -1
                        )
                        if new_id > 0 and new_id not in tid_to_pid_map:
                            tid_to_pid_map[new_id] = pid
                    except (ValueError, TypeError) as proc_e:
                        log.error(
                            f"Error parsing result '{result_str}' for {syscall}: {proc_e}"
                        )
                elif syscall in EXIT_SYSCALLS:
                    if tid in tid_to_pid_map:
                        del tid_to_pid_map[tid]
                yield Syscall(
                    timestamp=timestamp,
                    tid=tid,
                    pid=pid,
                    syscall=syscall,
                    args=parsed_args_list,
                    result_str=result_str,
                    error_name=error_name,
                    error_msg=error_msg,
                )
            except Exception as parse_exc:
                log.error(f"Error parsing matched line content: {line} -> {parse_exc}")
    except asyncio.CancelledError:
        log.info("Async strace parsing stream cancelled.")
    except Exception as stream_exc:
        log.exception(
            f"Error occurred in the async strace stream processing: {stream_exc}"
        )
        raise
    finally:
        log.info("Async parse_strace_stream finished.")
