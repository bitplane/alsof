# Filename: strace_cmd.py

import contextlib
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator  # Use collections.abc
from dataclasses import dataclass

import psutil  # For initial PID lookup

# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger(__name__)

# --- Configuration ---
PROCESS_SYSCALLS = ["clone", "fork", "vfork"]
# Added chdir, fchdir
FILE_STRUCT_SYSCALLS = [
    "open",
    "openat",
    "creat",
    "access",
    "stat",
    "lstat",
    "newfstatat",  # Use this instead of fstatat
    "close",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "chdir",  # Track CWD changes
    "fchdir",  # Track CWD changes via FD
]
IO_SYSCALLS = [
    "read",
    "pread64",
    "readv",
    "write",
    "pwrite64",
    "writev",
]
# Add exit_group to detect process termination
EXIT_SYSCALLS = ["exit_group"]

# Default list includes necessary process calls plus common file I/O and exit
DEFAULT_SYSCALLS = sorted(
    list(set(PROCESS_SYSCALLS + FILE_STRUCT_SYSCALLS + IO_SYSCALLS + EXIT_SYSCALLS))
)

STRACE_BASE_OPTIONS = [
    "-f",  # Follow forks/threads/clones
    "-s",
    "4096",  # Capture long strings (paths, data)
    "-qq",  # Suppress informational messages from strace itself
    # Add timestamp options for more accurate timing if needed, e.g., '-tt' or '-ttt'
    # '-ttt', # High-resolution timestamp with microseconds
    # Consider adding -y to print file descriptors paths if available (requires newer strace)
    # '-y', # Prints paths for file descriptor arguments
]

# --- Data Structures ---


@dataclass
class Syscall:
    """Structured representation of a parsed strace line with PID/TID."""

    timestamp: float
    tid: int  # Thread ID (from strace prefix)
    pid: int  # Process ID / Thread Group ID (TGID) - Resolved by parser
    syscall: str
    args: list[str]  # List of raw argument strings (split by state machine)
    result_str: str  # Raw result string (can be '?', hex, or dec)
    error_name: str | None = None  # Use |
    error_msg: str | None = None  # Use |


# --- Regex and Parsing Helpers ---

# Updated Regex to be more robust and handle unfinished/resumed lines if needed
STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"  # Capture TID at the start
    # r"(?:\[\d+\]\s+)?" # Optional core ID for multi-core systems (Removed for simplicity)
    # Handle potential timestamp prefix if using -tt or -ttt
    r"(?:\d{2}:\d{2}:\d{2}\.\d+\s+)?"  # Optional HH:MM:SS.ffffff timestamp from -tt/-ttt
    r"(?P<syscall>\w+)\("  # Syscall name
    # Use cautious non-greedy match for args, handle unfinished lines later if needed
    r"(?P<args>.*?)"
    r"\)\s+=\s+"  # Separator
    # Allow '?' for results of interrupted syscalls, handle hex/dec
    r"(?P<result>-?\d+|\?|0x[\da-fA-F]+)"
    # Optional error part
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
    # Optional unfinished/resumed tags (currently ignored by this regex, handled in parser loop)
    # r"(?:\s+<(?P<status>unfinished|resumed)>)?"
)


def _parse_args_state_machine(args_str: str) -> list[str]:  # Use built-in list
    """
    Parses the strace arguments string by splitting on top-level commas,
    respecting basic nesting of (), {}, [], and "" quotes. Handles basic escapes.
    """
    args = []
    if not args_str:
        return args
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
            # Handle specific escapes if needed, otherwise just append escaped char
            # e.g., if char == 'n': current_arg += '\n'; append_char = False
            escape_next = False
        elif char == "\\":
            escape_next = True
            # Append the backslash itself now, the next char will be appended normally
            # current_arg += char # Decide if backslash itself should be kept
            append_char = True  # Keep the backslash for now
        elif char == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if char in ("(", "{", "["):  # Add brackets
                nesting_level += 1
            elif char in (")", "}", "]"):  # Add brackets
                nesting_level = max(0, nesting_level - 1)
            elif char == "," and nesting_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
                append_char = False  # Don't append the comma
        if append_char:
            current_arg += char
        i += 1

    # Append the last argument
    args.append(current_arg.strip())
    return args


def _parse_result_int(result_str: str) -> int | None:  # Use |
    """Parses strace result string (dec/hex/?) into an integer or None."""
    if not result_str or result_str == "?":  # Handle '?' for interrupted
        return None
    try:
        return int(result_str, 0)  # Handles '0x...' hex and decimal
    except ValueError:
        return None


# --- Temporary FIFO Context Manager ---
@contextlib.contextmanager
def temporary_fifo() -> Iterator[str]:
    """
    Context manager that creates a temporary FIFO in a secure temporary directory.
    Yields the absolute path to the created FIFO.
    Ensures the FIFO and directory are cleaned up afterwards.
    """
    fifo_path = None
    temp_dir = None
    try:
        # Create in a secure temporary directory
        with tempfile.TemporaryDirectory(prefix="strace_fifo_") as temp_dir_path:
            temp_dir = temp_dir_path
            fifo_path = os.path.join(temp_dir, "strace_output.fifo")
            os.mkfifo(fifo_path)
            log.info(f"Created FIFO: {fifo_path}")
            yield fifo_path
    except OSError as e:
        # Specific error for FIFO creation failure
        raise RuntimeError(f"Failed to create FIFO in {temp_dir}: {e}") from e
    except Exception as e:
        # Catch broader exceptions during setup
        raise RuntimeError(f"Failed to set up temporary directory/FIFO: {e}") from e
    finally:
        # Cleanup is handled by TemporaryDirectory context manager automatically
        if fifo_path:
            log.debug(f"FIFO {fifo_path} will be cleaned up with directory {temp_dir}.")


# --- Low-level Strace Output Streamer ---
def stream_strace_output(
    target_command: list[str] | None = None,  # Use built-in list and |
    attach_ids: list[int] | None = None,  # Use built-in list and |
    syscalls: list[str] = DEFAULT_SYSCALLS,  # Use built-in list
) -> Iterator[str]:
    """
    Runs strace (either launching or attaching) and yields raw output lines from FIFO.
    Handles process startup, termination, and errors.
    """
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")
    if not syscalls:
        # Allow empty syscall list? Strace might default trace some.
        # For safety, let's require some syscalls.
        raise ValueError("Syscall list cannot be empty for tracing.")

    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable in PATH.")

    proc: subprocess.Popen | None = None
    fifo_reader = None

    try:
        with temporary_fifo() as fifo_path:
            strace_command = [strace_path, *STRACE_BASE_OPTIONS]
            # Ensure syscall list isn't empty and format correctly
            if syscalls:
                strace_command.extend(["-e", f"trace={','.join(syscalls)}"])
            # else: # Strace might trace default set if -e is omitted, but we enforce providing some.
            #     log.warning("No specific syscalls specified for strace trace.")

            strace_command.extend(["-o", fifo_path])  # Output to FIFO

            if target_command:
                strace_command.extend(["--", *target_command])
                log.info(
                    f"Preparing to launch: {' '.join(shlex.quote(c) for c in target_command)}"
                )
            elif attach_ids:
                valid_attach_ids = []
                for pid_or_tid in attach_ids:
                    # Validate PID/TID existence before attaching if possible
                    if psutil.pid_exists(pid_or_tid):
                        valid_attach_ids.append(str(pid_or_tid))
                    else:
                        log.warning(
                            f"PID/TID {pid_or_tid} does not exist before attach. Skipping."
                        )
                if not valid_attach_ids:
                    raise ValueError("No valid PIDs/TIDs provided to attach to.")
                strace_command.extend(
                    ["-p", ",".join(valid_attach_ids)]
                )  # Attach to comma-separated list
                log.info(f"Preparing to attach to existing IDs: {valid_attach_ids}")

            log.info(f"Executing: {' '.join(shlex.quote(c) for c in strace_command)}")
            proc = subprocess.Popen(
                strace_command,
                stdout=subprocess.DEVNULL,  # Ignore strace stdout
                stderr=subprocess.PIPE,  # Capture strace stderr for errors
                text=True,  # Work with text streams
                encoding="utf-8",  # Specify encoding
                errors="replace",  # Handle potential decoding errors
            )

            # Give strace a moment to start and potentially error out
            time.sleep(0.1)  # Small delay
            proc_status = proc.poll()
            if proc_status is not None:
                # Process exited quickly, likely an error
                stderr_output = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(
                    f"Strace process exited immediately (code {proc_status}). Stderr: {stderr_output[:500]}"
                )

            log.info(f"Opening FIFO {fifo_path} for reading...")
            try:
                # Open FIFO for reading - this blocks until strace writes something or exits
                fifo_reader = open(fifo_path, "r", encoding="utf-8", errors="replace")
                log.info("FIFO opened. Reading stream...")
            except Exception as e:
                # If opening FIFO fails, check if strace died
                proc_status = proc.poll()
                stderr_output = proc.stderr.read() if proc.stderr else ""
                stderr_msg = (
                    f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                )
                if proc_status is not None:
                    raise RuntimeError(
                        f"Strace process exited (code {proc_status}) before FIFO could be read.{stderr_msg} Error: {e}"
                    ) from e
                else:
                    # Strace running but FIFO open failed (permissions?)
                    raise RuntimeError(
                        f"Failed to open FIFO '{fifo_path}' for reading while strace "
                        f"(PID {proc.pid}) is running.{stderr_msg} Error: {e}"
                    ) from e

            # Read lines from the FIFO until strace closes it (on exit)
            if fifo_reader:
                for line in fifo_reader:
                    yield line.rstrip("\n")
                log.info("End of FIFO stream reached (strace likely exited).")
                fifo_reader.close()  # Close reader when done
                fifo_reader = None
            else:
                # Should be unreachable if open didn't raise error
                log.warning("FIFO reader was not available after open attempt.")

            # --- Strace Process Finished ---
            # Wait for strace to ensure it's fully terminated and get exit code
            exit_code = proc.wait()
            stderr_output = ""
            if proc.stderr:
                stderr_output = proc.stderr.read()
                proc.stderr.close()

            # Log stderr, demoting common attach messages
            if stderr_output.strip():
                is_attach_msg = (
                    "ptrace(PTRACE_ATTACH" in stderr_output
                    or "ptrace(PTRACE_SEIZE" in stderr_output
                )
                log_func = log.debug if is_attach_msg else log.warning
                log_func(f"Strace stderr output:\n{stderr_output.strip()}")

            log.info(f"Strace process (PID {proc.pid}) exited with code {exit_code}.")

            # Check for non-zero exit code (excluding common Ctrl+C code 130)
            if exit_code != 0 and exit_code != 130:
                # Log warning instead of raising error, allows processing partial traces
                log.warning(
                    f"Strace process finished with non-zero exit code {exit_code}."
                )

    except FileNotFoundError as e:
        # Specific error if strace or target command not found
        cmd_name = target_command[0] if target_command else "attach target"
        log.error(
            f"Command not found: {e}. Check 'strace' and '{shlex.quote(cmd_name)}' are in PATH and executable."
        )
        raise  # Re-raise
    except Exception as e:
        # Catch and log any other exceptions during setup or streaming
        log.exception(f"An error occurred during strace execution or setup: {e}")
        raise  # Re-raise critical exceptions
    finally:
        log.info("Cleaning up stream_strace_output...")
        # Ensure FIFO reader is closed if it's still open (e.g., due to exception)
        if fifo_reader:
            try:
                fifo_reader.close()
                log.debug("Closed FIFO reader during cleanup.")
            except Exception as close_err:
                log.warning(f"Error closing FIFO reader during cleanup: {close_err}")
        # Ensure strace process is terminated if generator is exited prematurely
        if proc and proc.poll() is None:
            log.warning(
                f"Terminating potentially running strace process (PID {proc.pid})..."
            )
            # Attempt graceful termination first
            proc.terminate()
            try:
                proc.wait(timeout=0.5)  # Wait briefly
            except subprocess.TimeoutExpired:
                log.warning(
                    f"Strace process (PID {proc.pid}) did not terminate gracefully, killing..."
                )
                proc.kill()  # Force kill if terminate fails
            log.info(
                f"Strace process (PID {proc.pid}) terminated or killed on cleanup."
            )


# --- Generator: Parsing the Stream ---


def parse_strace_stream(
    target_command: list[str] | None = None,  # Use built-in list and |
    attach_ids: list[int] | None = None,  # Use built-in list and |
    syscalls: list[str] = DEFAULT_SYSCALLS,  # Use built-in list
) -> Iterator[Syscall]:
    """
    Runs strace (launch or attach) via stream_strace_output, parses the raw lines
    into Syscall objects, and resolves TIDs to PIDs (TGIDs).
    """
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")

    log.info("Starting parse_strace_stream...")
    # tid_to_pid_map maps Thread ID (TID) to Process ID (PID/TGID)
    tid_to_pid_map: dict[int, int] = {}  # Use built-in dict

    # Pre-populate map for initial attach IDs
    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        for initial_tid in attach_ids:
            try:
                if not psutil.pid_exists(initial_tid):
                    log.warning(
                        f"Initial TID {initial_tid} does not exist. Skipping map entry."
                    )
                    continue
                # Get the actual Process ID (TGID) for the thread
                proc_info = psutil.Process(initial_tid)
                pid = proc_info.pid
                tid_to_pid_map[initial_tid] = pid
                log.debug(f"Mapped initial TID {initial_tid} to PID {pid}")
            except psutil.NoSuchProcess:
                log.warning(
                    f"Process/Thread with TID {initial_tid} disappeared during initial mapping."
                )
            except psutil.AccessDenied:
                # Cannot get PID if access denied, map TID to itself as fallback
                tid_to_pid_map[initial_tid] = initial_tid
                log.warning(
                    f"Access denied getting PID for initial TID {initial_tid}. Mapping TID to itself."
                )
            except Exception as e:
                # Catch other errors, fallback to mapping TID to itself
                tid_to_pid_map[initial_tid] = initial_tid
                log.error(
                    f"Error getting PID for initial TID {initial_tid}: {e}. Mapping TID to itself."
                )

    # Ensure necessary syscalls are always traced
    combined_syscalls = sorted(
        list(set(syscalls) | set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS))
    )

    # Wrap the stream_strace_output call in a try/except to catch errors from it
    try:
        for line in stream_strace_output(target_command, attach_ids, combined_syscalls):
            # Update time for each line? Or use strace timestamp if available?
            # Using current time is simpler but less precise than strace's -ttt
            timestamp = time.time()  # Use current time for now
            match = STRACE_LINE_RE.match(line.strip())
            if not match:
                # Handle unfinished/resumed lines explicitly if they cause issues
                if " <unfinished ...>" in line:
                    log.debug(f"Ignoring unfinished strace line: {line.strip()}")
                elif " resumed> " in line:
                    # Resumed lines might contain partial info - harder to parse reliably
                    log.debug(f"Ignoring resumed strace line: {line.strip()}")
                elif line.endswith("+++ exited with 0 +++") or line.endswith(
                    "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=...} ---"
                ):
                    # Ignore common process exit status lines printed by strace
                    log.debug(f"Ignoring strace exit/signal line: {line.strip()}")
                else:
                    log.debug(f"Unmatched strace line: {line.strip()}")
                continue

            data = match.groupdict()
            try:
                tid = int(data["tid"])
                syscall = data["syscall"]
                args_str = data["args"]
                result_str = data["result"]
                error_name = data.get("error")
                error_msg = data.get("errmsg")
                # success = error_name is None # Handled in processor

                # Resolve PID using the map, fallback needed if TID appears suddenly
                pid = tid_to_pid_map.get(tid)
                if pid is None:
                    # New TID encountered. Rely on _process_syscall_event fallback lookup.
                    # Assume TID=PID initially here for parsing.
                    pid = tid
                    # Don't add to map here, let the processor handle it after lookup
                    log.debug(
                        f"TID {tid} appeared without prior mapping. Will attempt lookup."
                    )

                parsed_args_list = _parse_args_state_machine(args_str)

                # Yield the parsed syscall data
                yield Syscall(
                    timestamp=timestamp,
                    tid=tid,
                    pid=pid,  # Pass the initially resolved or fallback PID
                    syscall=syscall,
                    args=parsed_args_list,
                    result_str=result_str,
                    error_name=error_name,
                    error_msg=error_msg,
                )
            except Exception as parse_exc:
                log.error(f"Error parsing matched line: {line.strip()} -> {parse_exc}")
                # Continue parsing other lines if one fails

    except Exception as stream_exc:
        # Log errors from the underlying stream_strace_output generator
        log.exception(f"Error occurred in the strace stream: {stream_exc}")
        # Decide whether to raise or just stop yielding
        # Raising is probably better to signal the failure upstream
        raise
    finally:
        log.info("parse_strace_stream finished.")
