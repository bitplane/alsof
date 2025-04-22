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
from collections.abc import Iterator
from dataclasses import dataclass

import psutil

# --- ADDED: Import Monitor for type hint ---
from lsoph.monitor import Monitor

# -----------------------------------------

log = logging.getLogger(__name__)

# --- Constants, Dataclasses, Helpers (Keep as is) ---
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


def _parse_args_state_machine(args_str: str) -> list[str]:
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
        log.warning(f"Could not parse result string: '{result_str}'")
        return None


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
def stream_strace_output(
    monitor: Monitor,  # <--- ADD Monitor argument
    target_command: list[str] | None = None,
    attach_ids: list[int] | None = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> Iterator[str]:
    """
    Runs strace, yields output lines, stores strace PID in monitor.
    """
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
    strace_pid = -1
    monitor.backend_pid = None  # Ensure it's clear initially

    try:
        with temporary_fifo() as fifo_path:
            # ... (construct strace_command as before) ...
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
            proc = subprocess.Popen(
                strace_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            strace_pid = proc.pid
            monitor.backend_pid = strace_pid  # <--- STORE PID in monitor
            log.info(f"Strace started with PID: {strace_pid}")

            # ... (rest of try block: check immediate exit, open fifo, yield lines) ...
            time.sleep(0.1)
            proc_status = proc.poll()
            if proc_status is not None:
                stderr_output = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(
                    f"Strace process (PID {strace_pid}) exited immediately (code {proc_status}). Stderr: {stderr_output[:500]}"
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
                        f"Strace process (PID {strace_pid}) exited (code {proc_status}) before FIFO could be read.{stderr_msg} Error: {e}"
                    ) from e
                else:
                    raise RuntimeError(
                        f"Failed to open FIFO '{fifo_path}' for reading while strace (PID {strace_pid}) is running.{stderr_msg} Error: {e}"
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
        log.error(f"Command not found: {e}.")
        raise
    except Exception as e:
        log.exception(
            f"An error occurred during strace execution or setup (PID {strace_pid}): {e}"
        )
        raise
    finally:
        log.info(
            f"Cleaning up stream_strace_output (strace PID: {strace_pid if strace_pid != -1 else 'unknown'})..."
        )
        monitor.backend_pid = None  # <--- CLEAR PID on exit/cleanup
        if fifo_reader:
            try:
                fifo_reader.close()
                log.debug("Closed FIFO reader during cleanup.")
            except Exception as close_err:
                log.warning(f"Error closing FIFO reader during cleanup: {close_err}")

        if proc:
            # ... (Keep the enhanced exit code / stderr handling from previous version) ...
            exit_code = proc.poll()
            if exit_code is None:
                log.info(
                    f"Waiting for strace process (PID {strace_pid}) to terminate..."
                )
                try:
                    _, stderr_output_rem = proc.communicate(timeout=1.0)
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    log.warning(
                        f"Strace process (PID {strace_pid}) did not exit after communicate timeout, killing."
                    )
                    proc.kill()
                    stderr_output_rem = proc.stderr.read() if proc.stderr else ""
                    exit_code = proc.wait()
                except Exception as comm_err:
                    log.exception(
                        f"Error during process communication/wait for PID {strace_pid}: {comm_err}"
                    )
                    exit_code = proc.poll() if proc.poll() is not None else 1
                    stderr_output_rem = ""
            else:
                stderr_output_rem = proc.stderr.read() if proc.stderr else ""
            stderr_output = stderr_output_rem
            if proc.stderr and not proc.stderr.closed:
                proc.stderr.close()

            if exit_code is not None and exit_code != 0 and exit_code != 130:
                log.error(
                    f"Strace process (PID {strace_pid}) failed with exit code {exit_code}.\nStderr: {stderr_output.strip() if stderr_output else '<empty>'}"
                )
            else:
                log.info(
                    f"Strace process (PID {strace_pid}) finished with exit code {exit_code}."
                )
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

        if proc and proc.poll() is None:  # Final check
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
def parse_strace_stream(
    monitor: Monitor,  # <--- ADD Monitor argument
    target_command: list[str] | None = None,
    attach_ids: list[int] | None = None,
    syscalls: list[str] = DEFAULT_SYSCALLS,
) -> Iterator[Syscall]:
    """
    Runs strace via stream_strace_output, parses lines into Syscall objects.
    """
    # ... (Initial checks, map setup, combined_syscalls remain the same) ...
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")
    log.info("Starting parse_strace_stream...")
    tid_to_pid_map: dict[int, int] = {}
    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        # ... (map population logic remains the same) ...
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
        # --- Pass monitor down ---
        for line in stream_strace_output(
            monitor, target_command, attach_ids, combined_syscalls
        ):
            # ... (rest of parsing loop remains the same) ...
            timestamp = time.time()
            match = STRACE_LINE_RE.match(line.strip())
            if not match:
                # ... (ignore unfinished/resumed/exit lines) ...
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
                    pid = tid
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
