# Filename: src/lsoph/backend/strace_cmd.py

import contextlib
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import List, Optional  # Added Optional

import psutil

# Import Monitor for type hint (used by stream_strace_output)
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

# Default set includes essential file operations, process/exit tracking, and CWD changes
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

# Base options for strace:
# -f: Follow forks
# -s 4096: Max string size to print
# -qq: Suppress attach/detach messages (reduces noise)
# -ttt: Print microsecond timestamps (useful but removed in favor of Python timing for consistency)
# -T: Show time spent in syscalls (can be added if needed)
# -xx: Print non-ascii strings in hex (useful for binary data in paths/args)
STRACE_BASE_OPTIONS = ["-f", "-s", "4096", "-qq", "-xx"]

# Regex to parse a typical strace line (may need adjustments based on strace version/options)
# Handles optional timestamp, TID, syscall, args, result, and error
STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"  # Thread ID (mandatory)
    # Optional timestamp (like 11:22:33.456789) - Not used if strace doesn't provide it
    # r"(?:\d{2}:\d{2}:\d{2}\.\d+\s+)?"
    r"(?P<syscall>\w+)\("  # Syscall name and opening parenthesis
    r"(?P<args>.*?)"  # Arguments (non-greedy match)
    r"\)\s+=\s+"  # Closing parenthesis, equals sign
    r"(?P<result>-?\d+|\?|0x[\da-fA-F]+)"  # Result (decimal, hex, or '?')
    # Optional error block (e.g., "ENOENT (No such file or directory)")
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
    # Optional <unfinished ...> or <... resumed> tags
    r"(?:\s+<(?P<tag>unfinished|resumed)\s+...>)?$"
)


@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    timestamp: float  # Timestamp captured by Python when the line was processed
    tid: int
    pid: int  # Process ID (group leader), derived later from TID if possible
    syscall: str
    args: list[str]
    result_str: str
    error_name: Optional[str] = None
    error_msg: Optional[str] = None


# --- Helper Functions ---


def _parse_args_state_machine(args_str: str) -> list[str]:
    """
    Parses the complex argument string from strace output.
    Handles nested structures like {}, [], (), quotes, and escapes.
    This is a best-effort parser, as strace output can be ambiguous.
    """
    args = []
    current_arg = ""
    nesting_level = 0  # Tracks nesting of (), {}, []
    in_quotes = False
    escape_next = False
    i = 0
    n = len(args_str)

    while i < n:
        char = args_str[i]
        append_char = True

        if escape_next:
            # Append the escaped character literally
            escape_next = False
        elif char == "\\":
            # Mark the next character as escaped, but still append the backslash
            # (strace often includes literal backslashes for escapes)
            escape_next = True
        elif char == '"':
            # Toggle quote state
            in_quotes = not in_quotes
        elif not in_quotes:
            # Handle nesting outside quotes
            if char in ("(", "{", "["):
                nesting_level += 1
            elif char in (")", "}", "]"):
                nesting_level = max(0, nesting_level - 1)  # Prevent going below zero
            elif char == "," and nesting_level == 0:
                # Comma at the top level separates arguments
                args.append(current_arg.strip())
                current_arg = ""
                append_char = False  # Don't append the comma itself

        if append_char:
            current_arg += char
        i += 1

    # Append the last argument
    args.append(current_arg.strip())
    # Filter out potentially empty strings if the input ends with a comma
    return [arg for arg in args if arg]


@contextlib.contextmanager
def temporary_fifo() -> Iterator[str]:
    """Creates and yields the path to a temporary FIFO, cleaning up afterwards."""
    fifo_path = None
    temp_dir = None
    try:
        # Create a temporary directory to hold the FIFO
        with tempfile.TemporaryDirectory(prefix="strace_fifo_") as temp_dir_path:
            temp_dir = temp_dir_path
            fifo_path = os.path.join(temp_dir, "strace_output.fifo")
            # Create the FIFO (named pipe)
            os.mkfifo(fifo_path)
            log.info(f"Created temporary FIFO: {fifo_path}")
            yield fifo_path
    except OSError as e:
        # Handle errors during FIFO creation (e.g., permissions)
        raise RuntimeError(f"Failed to create FIFO in {temp_dir}: {e}") from e
    except Exception as e:
        # Handle errors during temporary directory setup
        raise RuntimeError(f"Failed to set up temporary directory/FIFO: {e}") from e
    finally:
        # The TemporaryDirectory context manager handles cleanup of the directory
        # and the FIFO within it automatically.
        if fifo_path:
            log.debug(f"FIFO {fifo_path} will be cleaned up with directory {temp_dir}.")


# --- Low-level Strace Command Execution and Output Streaming ---


def stream_strace_output(
    monitor: Monitor,  # Pass Monitor to store backend PID
    target_command: Optional[list[str]] = None,
    attach_ids: Optional[list[int]] = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> Iterator[str]:
    """
    Runs the strace command targeting a new command or existing PIDs/TIDs,
    redirecting output to a FIFO, and yields lines read from that FIFO.
    Stores the strace process PID in `monitor.backend_pid`.

    Args:
        monitor: The Monitor instance to store the strace PID.
        target_command: The command and arguments to execute and trace.
        attach_ids: A list of PIDs or TIDs to attach to.
        syscalls: A list of syscalls to trace.

    Yields:
        Raw output lines from the strace process.

    Raises:
        ValueError: If neither target_command nor attach_ids is provided,
                    or if both are provided, or if syscall list is empty.
        FileNotFoundError: If the 'strace' executable cannot be found.
        RuntimeError: If strace fails to start or encounters issues with the FIFO.
    """
    # --- Input Validation ---
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")
    if not syscalls:
        raise ValueError("Syscall list cannot be empty for tracing.")

    # --- Find strace Executable ---
    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable in PATH.")

    proc: Optional[subprocess.Popen] = None
    fifo_reader = None
    strace_pid = -1
    monitor.backend_pid = None  # Ensure it's clear initially

    try:
        # --- Create FIFO and Build Command ---
        with temporary_fifo() as fifo_path:
            strace_command = [strace_path, *STRACE_BASE_OPTIONS]
            # Specify syscalls to trace
            strace_command.extend(["-e", f"trace={','.join(syscalls)}"])
            # Redirect output to the FIFO
            strace_command.extend(["-o", fifo_path])

            if target_command:
                # Append the target command and its arguments
                strace_command.extend(["--", *target_command])
                log.info(
                    f"Preparing to launch: {' '.join(shlex.quote(c) for c in target_command)}"
                )
            elif attach_ids:
                # Filter attach_ids to only include currently existing ones
                valid_attach_ids = [
                    str(pid) for pid in attach_ids if psutil.pid_exists(pid)
                ]
                if not valid_attach_ids:
                    # If no valid PIDs remain, strace would exit immediately.
                    raise ValueError("No valid PIDs/TIDs provided to attach to.")
                strace_command.extend(["-p", ",".join(valid_attach_ids)])
                log.info(f"Preparing to attach to existing IDs: {valid_attach_ids}")

            # --- Launch Strace ---
            log.info(f"Executing: {' '.join(shlex.quote(c) for c in strace_command)}")
            proc = subprocess.Popen(
                strace_command,
                stdout=subprocess.DEVNULL,  # Ignore strace's own stdout
                stderr=subprocess.PIPE,  # Capture stderr for errors
                text=True,
                encoding="utf-8",
                errors="replace",  # Handle potential decoding errors in stderr
            )
            strace_pid = proc.pid
            monitor.backend_pid = strace_pid  # Store the strace PID
            log.info(f"Strace started with PID: {strace_pid}")

            # --- Check for Immediate Exit ---
            # Give strace a moment to start and potentially fail
            time.sleep(0.1)
            proc_status = proc.poll()
            if proc_status is not None:
                # Strace exited immediately, likely an error
                stderr_output = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(
                    f"Strace process (PID {strace_pid}) exited immediately (code {proc_status}). "
                    f"Stderr: {stderr_output[:500]}"  # Show first 500 chars of stderr
                )

            # --- Open FIFO for Reading ---
            # This blocks until strace opens the FIFO for writing
            log.info(
                f"Opening FIFO {fifo_path} for reading (strace PID: {strace_pid})..."
            )
            try:
                # Use a timeout? No, opening the read end should wait for the writer.
                fifo_reader = open(fifo_path, "r", encoding="utf-8", errors="replace")
                log.info("FIFO opened. Reading stream...")
            except Exception as e:
                # If opening the FIFO fails, check if strace is still running
                proc_status = proc.poll()
                stderr_output = proc.stderr.read() if proc.stderr else ""
                stderr_msg = (
                    f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                )
                if proc_status is not None:
                    # Strace exited before we could open the FIFO
                    raise RuntimeError(
                        f"Strace process (PID {strace_pid}) exited (code {proc_status}) "
                        f"before FIFO could be read.{stderr_msg} Error: {e}"
                    ) from e
                else:
                    # Strace is running, but we failed to open the FIFO (unexpected)
                    raise RuntimeError(
                        f"Failed to open FIFO '{fifo_path}' for reading while strace "
                        f"(PID {strace_pid}) is running.{stderr_msg} Error: {e}"
                    ) from e

            # --- Yield Lines from FIFO ---
            if fifo_reader:
                for line in fifo_reader:
                    yield line.rstrip("\n")  # Yield lines without newline
                log.info("End of FIFO stream reached (strace likely exited).")
            else:
                # Should be unreachable if FIFO opening logic is correct
                log.warning("FIFO reader was unexpectedly None after open attempt.")

    except FileNotFoundError as e:
        # Raised if strace_path is invalid (should be caught earlier)
        log.error(f"Strace command not found: {e}.")
        raise
    except ValueError as e:  # Catch validation errors (e.g., no valid PIDs)
        log.error(f"Strace configuration error: {e}")
        raise
    except Exception as e:
        # Catch other errors during setup or execution
        log.exception(
            f"An error occurred during strace execution or setup (PID {strace_pid}): {e}"
        )
        raise  # Re-raise the exception
    finally:
        # --- Cleanup ---
        log.info(
            f"Cleaning up stream_strace_output (strace PID: {strace_pid if strace_pid != -1 else 'unknown'})..."
        )
        monitor.backend_pid = None  # Clear the PID on exit/cleanup

        if fifo_reader:
            try:
                fifo_reader.close()
                log.debug("Closed FIFO reader during cleanup.")
            except Exception as close_err:
                log.warning(f"Error closing FIFO reader during cleanup: {close_err}")

        if proc:
            # Check final status and handle termination if necessary
            exit_code = proc.poll()
            stderr_output = ""
            if proc.stderr:
                try:
                    # Read remaining stderr
                    stderr_output = proc.stderr.read()
                    proc.stderr.close()
                except Exception as serr:
                    log.warning(f"Error reading/closing strace stderr: {serr}")

            if exit_code is None:
                # Process still running, terminate it
                log.info(
                    f"Waiting for strace process (PID {strace_pid}) to terminate..."
                )
                try:
                    # Ask nicely first
                    proc.terminate()
                    exit_code = proc.wait(timeout=1.0)  # Wait briefly
                except subprocess.TimeoutExpired:
                    log.warning(
                        f"Strace process (PID {strace_pid}) did not exit after terminate, killing."
                    )
                    proc.kill()  # Force kill
                    exit_code = proc.wait()  # Wait for kill
                except Exception as term_err:
                    log.exception(
                        f"Error during strace termination for PID {strace_pid}: {term_err}"
                    )
                    exit_code = (
                        proc.poll() if proc.poll() is not None else 1
                    )  # Assume error

            # Log final status
            if (
                exit_code is not None and exit_code != 0 and exit_code != 130
            ):  # 130 is common for Ctrl+C
                log.error(
                    f"Strace process (PID {strace_pid}) failed with exit code {exit_code}.\n"
                    f"Stderr: {stderr_output.strip() if stderr_output else '<empty>'}"
                )
            else:
                log.info(
                    f"Strace process (PID {strace_pid}) finished with exit code {exit_code}."
                )
                # Log stderr only if it contains something other than typical attach messages
                if stderr_output and stderr_output.strip():
                    is_attach_msg = (
                        "ptrace(PTRACE_ATTACH" in stderr_output
                        or "ptrace(PTRACE_SEIZE" in stderr_output
                    )
                    if not is_attach_msg:
                        log.debug(
                            f"Strace stderr (exit code {exit_code}):\n{stderr_output.strip()}"
                        )
                    else:
                        log.debug(
                            "Strace stderr contained only standard attach/seize messages."
                        )


# --- High-level Generator: Parsing the Stream ---


def parse_strace_stream(
    monitor: Monitor,  # Pass monitor for stream_strace_output
    target_command: Optional[list[str]] = None,
    attach_ids: Optional[list[int]] = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> Iterator[Syscall]:
    """
    Runs strace via stream_strace_output and parses the output lines into Syscall objects.
    Handles TID to PID mapping internally for parsed events.

    Args:
        monitor: The Monitor instance (passed to stream_strace_output).
        target_command: The command and arguments to execute and trace.
        attach_ids: A list of PIDs or TIDs to attach to.
        syscalls: A list of syscalls to trace.

    Yields:
        Syscall objects representing parsed strace events.
    """
    log.info("Starting parse_strace_stream...")
    # TID to PID mapping - managed internally by this parser function
    tid_to_pid_map: dict[int, int] = {}

    # Pre-populate map for initial attach IDs
    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        for initial_tid in attach_ids:
            try:
                # Check existence first
                if not psutil.pid_exists(initial_tid):
                    log.warning(
                        f"Initial TID {initial_tid} does not exist. Skipping map entry."
                    )
                    continue
                # Get process info to find the actual PID (thread group leader)
                proc_info = psutil.Process(initial_tid)
                pid = proc_info.pid  # The real PID
                tid_to_pid_map[initial_tid] = pid
                log.debug(f"Mapped initial TID {initial_tid} to PID {pid}")
            except psutil.NoSuchProcess:
                log.warning(
                    f"Process/Thread with TID {initial_tid} disappeared during initial mapping."
                )
            except psutil.AccessDenied:
                # Cannot determine real PID, map TID to itself as a fallback
                tid_to_pid_map[initial_tid] = initial_tid
                log.warning(
                    f"Access denied getting PID for initial TID {initial_tid}. Mapping TID to itself."
                )
            except Exception as e:
                # Other errors, map TID to itself
                tid_to_pid_map[initial_tid] = initial_tid
                log.error(
                    f"Error getting PID for initial TID {initial_tid}: {e}. Mapping TID to itself."
                )

    # Determine the full set of syscalls needed (including process/exit)
    combined_syscalls = sorted(
        list(set(syscalls) | set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS))
    )

    try:
        # Stream raw lines from strace
        for line in stream_strace_output(
            monitor, target_command, attach_ids, combined_syscalls
        ):
            timestamp = time.time()  # Capture timestamp when line is processed
            match = STRACE_LINE_RE.match(
                line
            )  # Use strip() inside loop? No, already stripped.

            if not match:
                # Ignore lines that don't match the expected pattern
                # (e.g., signals, detached messages if -qq wasn't fully effective)
                if (
                    " <unfinished ...>" not in line
                    and "<... resumed>" not in line
                    and "+++ exited" not in line
                    and "--- SIG" not in line
                ):
                    log.debug(f"Ignoring unmatched strace line: {line}")
                continue

            data = match.groupdict()

            # Skip unfinished/resumed lines for now (can be complex to stitch together)
            if data.get("tag") in ("unfinished", "resumed"):
                log.debug(f"Skipping {data['tag']} line: {line}")
                continue

            try:
                tid = int(data["tid"])
                syscall = data["syscall"]
                args_str = data["args"]
                result_str = data["result"]
                error_name = data.get("error")
                error_msg = data.get("errmsg")

                # --- PID Mapping ---
                pid = tid_to_pid_map.get(tid)
                if pid is None:
                    # TID not seen before, try to look up its PID
                    try:
                        if psutil.pid_exists(tid):
                            proc_info = psutil.Process(tid)
                            pid = proc_info.pid
                            tid_to_pid_map[tid] = pid
                            log.debug(f"Dynamically mapped TID {tid} to PID {pid}")
                        else:
                            # Process gone before we could map it, use TID as fallback PID
                            pid = tid
                            tid_to_pid_map[tid] = pid  # Cache the fallback
                            log.warning(
                                f"TID {tid} not found and process gone, assuming PID=TID."
                            )
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        Exception,
                    ) as map_e:
                        # Error during lookup, use TID as fallback PID
                        pid = tid
                        tid_to_pid_map[tid] = pid  # Cache the fallback
                        log.warning(
                            f"Error looking up PID for TID {tid} ({map_e}), assuming PID=TID."
                        )
                # --- End PID Mapping ---

                # Parse arguments string
                parsed_args_list = _parse_args_state_machine(args_str)

                # --- Handle Process Creation/Exit Syscalls Internally ---
                # Update internal TID->PID map based on process events
                if syscall in PROCESS_SYSCALLS and error_name is None:
                    try:
                        # The result of fork/vfork/clone is the new TID/PID
                        new_id_str = result_str
                        new_id = (
                            int(new_id_str) if new_id_str and new_id_str != "?" else -1
                        )
                        if new_id > 0 and new_id not in tid_to_pid_map:
                            # Map the new TID/PID to the *parent's* PID
                            tid_to_pid_map[new_id] = pid
                            log.info(
                                f"Syscall {syscall}: Mapped new TID/PID {new_id} to parent process group PID {pid}"
                            )
                    except (ValueError, TypeError) as proc_e:
                        log.error(
                            f"Error parsing result '{result_str}' for {syscall}: {proc_e}"
                        )
                elif syscall in EXIT_SYSCALLS:
                    # Clean up map when a thread/process exits
                    if tid in tid_to_pid_map:
                        log.debug(
                            f"Syscall {syscall}: Removing TID {tid} (PID {pid}) from map."
                        )
                        del tid_to_pid_map[tid]
                # --- End Internal Handling ---

                # Yield the parsed Syscall object
                yield Syscall(
                    timestamp=timestamp,
                    tid=tid,
                    pid=pid,  # Use the mapped PID
                    syscall=syscall,
                    args=parsed_args_list,
                    result_str=result_str,
                    error_name=error_name,
                    error_msg=error_msg,
                )

            except Exception as parse_exc:
                log.error(f"Error parsing matched line content: {line} -> {parse_exc}")

    except Exception as stream_exc:
        # Catch errors from stream_strace_output or during the loop
        log.exception(f"Error occurred in the strace stream processing: {stream_exc}")
        raise  # Re-raise to signal failure
    finally:
        log.info("parse_strace_stream finished.")
