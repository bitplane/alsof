# Filename: strace_cmd.py

import contextlib
import logging  # Keep logging import
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass

import psutil

# --- Setup Logging ---
# REMOVED: logging.basicConfig(...)
log = logging.getLogger(__name__)  # Get logger instance

# --- Constants and Config ---
# ... (rest of the constants remain the same) ...
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
    list(set(PROCESS_SYSCALLS + FILE_STRUCT_SYSCALLS + IO_SYSCALLS + EXIT_SYSCALLS))
)
STRACE_BASE_OPTIONS = ["-f", "-s", "4096", "-qq"]
STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"
    r"(?:\d{2}:\d{2}:\d{2}\.\d+\s+)?"
    r"(?P<syscall>\w+)\("
    r"(?P<args>.*?)"
    r"\)\s+=\s+"
    r"(?P<result>-?\d+|\?|0x[\da-fA-F]+)"
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
)


# --- Data Structures ---
@dataclass
class Syscall:
    timestamp: float
    tid: int
    pid: int
    syscall: str
    args: list[str]
    result_str: str
    error_name: str | None = None
    error_msg: str | None = None


# --- Parsing Helpers ---
# ... (Implementations of _parse_args_state_machine, _parse_result_int remain the same) ...
def _parse_args_state_machine(args_str: str) -> list[str]:
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
            escape_next = False
        elif char == "\\":
            escape_next = True
            append_char = True
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
    return args


def _parse_result_int(result_str: str) -> int | None:
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)
    except ValueError:
        return None


# --- Temporary FIFO ---
# ... (Implementation of temporary_fifo remains the same) ...
@contextlib.contextmanager
def temporary_fifo() -> Iterator[str]:
    fifo_path = None
    temp_dir = None
    try:
        with tempfile.TemporaryDirectory(prefix="strace_fifo_") as temp_dir_path:
            temp_dir = temp_dir_path
            fifo_path = os.path.join(temp_dir, "strace_output.fifo")
            os.mkfifo(fifo_path)
            log.info(f"Created FIFO: {fifo_path}")
            yield fifo_path
    except OSError as e:
        raise RuntimeError(f"Failed to create FIFO in {temp_dir}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to set up temporary directory/FIFO: {e}") from e
    finally:
        if fifo_path:
            log.debug(f"FIFO {fifo_path} will be cleaned up with directory {temp_dir}.")


# --- Low-level Strace Output Streamer ---
# ... (Implementation of stream_strace_output remains the same,
#      including the enhanced error logging in the finally block) ...
def stream_strace_output(
    target_command: list[str] | None = None,
    attach_ids: list[int] | None = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> Iterator[str]:
    """
    Runs strace (either launching or attaching) and yields raw output lines from FIFO.
    Handles process startup, termination, and errors. Enhanced error logging.
    """
    # --- Initial checks and setup (Keep as is) ---
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")
    if not syscalls:
        raise ValueError("Syscall list cannot be empty for tracing.")
    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable in PATH.")

    proc: subprocess.Popen | None = None
    fifo_reader = None
    strace_pid = -1  # Store strace PID for logging

    try:
        with temporary_fifo() as fifo_path:
            strace_command = [strace_path, *STRACE_BASE_OPTIONS]
            if syscalls:
                strace_command.extend(["-e", f"trace={','.join(syscalls)}"])
            strace_command.extend(["-o", fifo_path])

            if target_command:
                strace_command.extend(["--", *target_command])
                log.info(
                    f"Preparing to launch: {' '.join(shlex.quote(c) for c in target_command)}"
                )
            elif attach_ids:
                valid_attach_ids = [
                    str(pid) for pid in attach_ids if psutil.pid_exists(pid)
                ]
                if not valid_attach_ids:
                    raise ValueError("No valid PIDs/TIDs provided to attach to.")
                strace_command.extend(["-p", ",".join(valid_attach_ids)])
                log.info(f"Preparing to attach to existing IDs: {valid_attach_ids}")

            log.info(f"Executing: {' '.join(shlex.quote(c) for c in strace_command)}")
            # Add delay here if testing the timing hypothesis (keep commented out otherwise)
            # import time # Make sure time is imported if using sleep
            # time.sleep(1)
            proc = subprocess.Popen(
                strace_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            strace_pid = proc.pid  # Store PID after launch

            time.sleep(0.1)  # Keep small delay to check for immediate exit
            proc_status = proc.poll()
            if proc_status is not None:
                stderr_output = proc.stderr.read() if proc.stderr else ""
                # Ensure strace_pid is set before raising
                raise RuntimeError(
                    f"Strace process (PID {strace_pid if strace_pid != -1 else 'unknown'}) "
                    f"exited immediately (code {proc_status}). "
                    f"Stderr: {stderr_output[:500]}"
                )

            log.info(
                f"Opening FIFO {fifo_path} for reading (strace PID: {strace_pid})..."
            )
            try:
                fifo_reader = open(fifo_path, "r", encoding="utf-8", errors="replace")
                log.info("FIFO opened. Reading stream...")
            except Exception as e:
                proc_status = proc.poll()
                stderr_output = proc.stderr.read() if proc.stderr else ""
                stderr_msg = (
                    f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                )
                if proc_status is not None:
                    raise RuntimeError(
                        f"Strace process (PID {strace_pid}) exited (code {proc_status}) "
                        f"before FIFO could be read.{stderr_msg} Error: {e}"
                    ) from e
                else:
                    raise RuntimeError(
                        f"Failed to open FIFO '{fifo_path}' for reading "
                        f"while strace (PID {strace_pid}) is running.{stderr_msg} "
                        f"Error: {e}"
                    ) from e

            if fifo_reader:
                for line in fifo_reader:
                    yield line.rstrip("\n")
                log.info("End of FIFO stream reached (strace likely exited).")
                fifo_reader.close()
                fifo_reader = None
            else:
                log.warning("FIFO reader was not available after open attempt.")

    except FileNotFoundError as e:
        cmd_name = target_command[0] if target_command else "attach target"
        log.error(
            f"Command not found: {e}. Check 'strace' and '{shlex.quote(cmd_name)}' are in PATH and executable."
        )
        raise
    except Exception as e:
        # Log exceptions happening during the main execution phase
        log.exception(
            f"An error occurred during strace execution or setup (PID {strace_pid}): {e}"
        )
        raise  # Re-raise critical exceptions
    finally:
        # This block executes even if exceptions occurred above
        log.info(
            f"Cleaning up stream_strace_output (strace PID: {strace_pid if strace_pid != -1 else 'unknown'})..."
        )
        if fifo_reader:
            try:
                fifo_reader.close()
                log.debug("Closed FIFO reader during cleanup.")
            except Exception as close_err:
                log.warning(f"Error closing FIFO reader during cleanup: {close_err}")

        # --- Enhanced Exit Code / Stderr Handling ---
        if proc:
            exit_code = proc.poll()
            # If process hasn't terminated yet (e.g., generator stopped early), wait for it.
            if exit_code is None:
                log.info(
                    f"Waiting for strace process (PID {strace_pid}) to terminate..."
                )
                try:
                    # Use communicate to read remaining stderr/stdout and wait
                    # Set timeout for communicate
                    _, stderr_output_rem = proc.communicate(timeout=1.0)
                    exit_code = proc.returncode  # Get final exit code
                except subprocess.TimeoutExpired:
                    log.warning(
                        f"Strace process (PID {strace_pid}) did not exit after communicate timeout, killing."
                    )
                    proc.kill()
                    # Try reading stderr after kill, might be empty
                    stderr_output_rem = proc.stderr.read() if proc.stderr else ""
                    exit_code = proc.wait()  # Get exit code after kill
                except Exception as comm_err:
                    log.exception(
                        f"Error during process communication/wait for PID {strace_pid}: {comm_err}"
                    )
                    # Try to get exit code if possible, otherwise assume error
                    exit_code = (
                        proc.poll() if proc.poll() is not None else 1
                    )  # Assume error if poll fails
                    stderr_output_rem = ""  # Can't reliably read stderr
            else:
                # Process already exited, read any remaining stderr directly
                stderr_output_rem = proc.stderr.read() if proc.stderr else ""

            # Combine any stderr read before with remaining stderr
            # This part might be redundant if communicate was used, but safe fallback
            stderr_output = (
                stderr_output_rem  # Prioritize stderr read after termination/wait
            )

            # Close stderr stream if it's still open
            if proc.stderr and not proc.stderr.closed:
                proc.stderr.close()

            # Log based on exit code
            if exit_code is not None and exit_code != 0 and exit_code != 130:
                # --- Log non-zero exits (like 1) as ERROR ---
                log.error(
                    f"Strace process (PID {strace_pid}) failed with exit code {exit_code}.\n"
                    f"Stderr: {stderr_output.strip() if stderr_output else '<empty>'}"
                )
            else:
                # Log successful exit or Ctrl+C
                log.info(
                    f"Strace process (PID {strace_pid}) finished with exit code {exit_code}."
                )
                # Optionally log non-error stderr here if needed
                if stderr_output and stderr_output.strip():
                    # Demote common attach messages
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
        # --- End Enhanced Handling ---

        # Final check to terminate strace process if it somehow still runs (e.g. error during cleanup)
        if proc and proc.poll() is None:
            log.warning(
                f"Terminating potentially running strace process (PID {proc.pid}) on final cleanup check..."
            )
            proc.terminate()
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                log.warning(
                    f"Strace process (PID {proc.pid}) did not terminate gracefully, killing..."
                )
                proc.kill()
            log.info(
                f"Strace process (PID {proc.pid}) terminated or killed on final cleanup."
            )


# --- Generator: Parsing the Stream ---
# ... (Implementation of parse_strace_stream remains the same) ...
def parse_strace_stream(
    target_command: list[str] | None = None,
    attach_ids: list[int] | None = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> Iterator[Syscall]:
    """
    Runs strace (launch or attach) via stream_strace_output, parses the raw lines
    into Syscall objects, and resolves TIDs to PIDs (TGIDs).
    """
    # (Keep the implementation of this function exactly as it was)
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")

    log.info("Starting parse_strace_stream...")
    tid_to_pid_map: dict[int, int] = {}

    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        for initial_tid in attach_ids:
            try:
                if not psutil.pid_exists(initial_tid):
                    log.warning(
                        f"Initial TID {initial_tid} does not exist. Skipping map entry."
                    )
                    continue
                proc_info = psutil.Process(initial_tid)
                pid = proc_info.pid
                tid_to_pid_map[initial_tid] = pid
                log.debug(f"Mapped initial TID {initial_tid} to PID {pid}")
            except psutil.NoSuchProcess:
                log.warning(
                    f"Process/Thread with TID {initial_tid} disappeared during initial mapping."
                )
            except psutil.AccessDenied:
                tid_to_pid_map[initial_tid] = initial_tid
                log.warning(
                    f"Access denied getting PID for initial TID {initial_tid}. Mapping TID to itself."
                )
            except Exception as e:
                tid_to_pid_map[initial_tid] = initial_tid
                log.error(
                    f"Error getting PID for initial TID {initial_tid}: {e}. Mapping TID to itself."
                )

    combined_syscalls = sorted(
        list(set(syscalls) | set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS))
    )

    try:
        for line in stream_strace_output(target_command, attach_ids, combined_syscalls):
            timestamp = time.time()
            match = STRACE_LINE_RE.match(line.strip())
            if not match:
                if " <unfinished ...>" in line:
                    log.debug(f"Ignoring unfinished strace line: {line.strip()}")
                elif " resumed> " in line:
                    log.debug(f"Ignoring resumed strace line: {line.strip()}")
                elif line.endswith("+++ exited with 0 +++") or line.endswith(
                    "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=...} ---"
                ):
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
                pid = tid_to_pid_map.get(tid)
                if pid is None:
                    pid = tid  # Rely on _process_syscall_event fallback lookup
                    log.debug(
                        f"TID {tid} appeared without prior mapping. Will attempt lookup."
                    )

                parsed_args_list = _parse_args_state_machine(args_str)
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
                log.error(f"Error parsing matched line: {line.strip()} -> {parse_exc}")

    except Exception as stream_exc:
        log.exception(f"Error occurred in the strace stream: {stream_exc}")
        raise
    finally:
        log.info("parse_strace_stream finished.")
