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
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional  # Removed Any, sys, argparse

import psutil  # For initial PID lookup

# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger(__name__)

# --- Configuration ---
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
    "rename",
    "renameat",
]
IO_SYSCALLS = [
    "read",
    "pread64",
    "readv",
    "write",
    "pwrite64",
    "writev",
]
# Default list includes necessary process calls plus common file I/O
DEFAULT_SYSCALLS = sorted(
    list(set(PROCESS_SYSCALLS + FILE_STRUCT_SYSCALLS + IO_SYSCALLS))
)

STRACE_BASE_OPTIONS = [
    "-f",  # Follow forks/threads/clones
    "-s",
    "4096",  # Capture long strings (paths, data)
    "-qq",  # Suppress informational messages from strace itself
]

# --- Data Structures ---


@dataclass
class Syscall:
    """Structured representation of a parsed strace line with PID/TID."""

    timestamp: float
    tid: int  # Thread ID (from strace prefix)
    pid: int  # Process ID / Thread Group ID (TGID) - Resolved by parser
    syscall: str
    args: List[str]  # List of raw argument strings (split by state machine)
    result_str: str  # Raw result string
    error_name: Optional[str] = None
    error_msg: Optional[str] = None


# --- Regex and Parsing Helpers ---

STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"  # Capture TID at the start
    r"(?:\[\d+\]\s+)?"  # Optional core ID for multi-core systems
    r"(?P<syscall>\w+)\("  # Syscall name
    r"(?P<args>.*?)"  # Non-greedy capture of args inside parens
    r"\)\s+=\s+"  # Separator
    r"(?P<result>-?\d+|0x[\da-fA-F]+)"  # Result (decimal or hex)
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"  # Optional error
)


def _parse_args_state_machine(args_str: str) -> List[str]:
    """
    Parses the strace arguments string by splitting on top-level commas,
    respecting basic nesting of (), {}, and "" quotes.
    """
    args = []
    if not args_str:
        return args
    current_arg = ""
    nesting_level = 0
    in_quotes = False
    escape_next = False
    for char in args_str:
        append_char = True
        if escape_next:
            escape_next = False
        elif char == "\\":
            escape_next = True
        elif char == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if char in ("(", "{"):
                nesting_level += 1
            elif char in (")", "}"):
                nesting_level = max(0, nesting_level - 1)
            elif char == "," and nesting_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
                append_char = False
        if append_char:
            current_arg += char
    if current_arg or (not args and not args_str):
        args.append(current_arg.strip())
    return args


def _parse_result_int(result_str: str) -> Optional[int]:
    """Parses strace result string (dec/hex) into an integer."""
    # Simple internal helper for PID/TID mapping
    if not result_str:
        return None
    try:
        return int(result_str, 0)
    except ValueError:
        return None


# --- Temporary FIFO Context Manager ---
@contextlib.contextmanager
def temporary_fifo() -> Iterator[str]:
    """
    Context manager that creates a temporary FIFO in a temporary directory.
    Yields the absolute path to the created FIFO.
    Ensures the FIFO and directory are cleaned up afterwards.
    """
    fifo_path = None
    temp_dir = None
    try:
        # TemporaryDirectory cleans itself up on context exit
        with tempfile.TemporaryDirectory(prefix="strace_fifo_") as temp_dir_path:
            temp_dir = temp_dir_path  # Store path for logging
            fifo_path = os.path.join(temp_dir, "strace_output.fifo")
            os.mkfifo(fifo_path)
            log.info(f"Created FIFO: {fifo_path}")
            yield fifo_path
    except OSError as e:
        raise RuntimeError(f"Failed to create FIFO in {temp_dir}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to set up temporary directory/FIFO: {e}") from e
    finally:
        # Cleanup is handled by TemporaryDirectory context manager
        if fifo_path:
            log.info(f"FIFO {fifo_path} will be cleaned up.")


# --- Low-level Strace Output Streamer ---
def stream_strace_output(
    target_command: Optional[List[str]] = None,
    attach_ids: Optional[List[int]] = None,
    syscalls: List[str] = DEFAULT_SYSCALLS,
) -> Iterator[str]:
    """
    Runs strace (either launching or attaching) and yields raw output lines from FIFO.
    """
    if not target_command and not attach_ids:
        raise ValueError("Must provide either target_command or attach_ids.")
    if target_command and attach_ids:
        raise ValueError("Cannot provide both target_command and attach_ids.")
    if not syscalls:
        raise ValueError("Syscall list cannot be empty.")

    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable in PATH.")

    proc: Optional[subprocess.Popen] = None
    fifo_reader = None

    try:
        with temporary_fifo() as fifo_path:
            strace_command = [strace_path, *STRACE_BASE_OPTIONS]
            strace_command.extend(["-e", f"trace={','.join(syscalls)}"])
            strace_command.extend(["-o", fifo_path])

            if target_command:
                strace_command.extend(["--", *target_command])
                log.info(
                    f"Preparing to launch: {' '.join(shlex.quote(c) for c in target_command)}"
                )
            elif attach_ids:
                for pid_or_tid in attach_ids:
                    strace_command.extend(["-p", str(pid_or_tid)])
                log.info(f"Preparing to attach to IDs: {attach_ids}")

            log.info(f"Executing: {' '.join(shlex.quote(c) for c in strace_command)}")
            proc = subprocess.Popen(
                strace_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,  # Capture strace's own errors
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            log.info(f"Opening FIFO {fifo_path} for reading...")
            try:
                # Blocking open waits for strace to open it for writing
                fifo_reader = open(fifo_path, "r", encoding="utf-8", errors="replace")
                log.info("FIFO opened. Reading stream...")
            except Exception as e:
                proc_exit_code = proc.poll()
                stderr_output = proc.stderr.read() if proc.stderr else ""
                if proc_exit_code is not None:
                    stderr_msg = (
                        f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                    )
                    raise RuntimeError(
                        f"Strace process exited (code {proc_exit_code}).{stderr_msg} Error: {e}"
                    ) from e
                else:
                    raise RuntimeError(f"Failed to open FIFO for reading: {e}") from e

            # Check for quick exit after FIFO open attempt
            # Give strace a moment to potentially error out
            time.sleep(0.1)
            proc_exit_code = proc.poll()
            if proc_exit_code is not None:
                stderr_output = proc.stderr.read() if proc.stderr else ""
                stderr_msg = (
                    f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                )
                log.warning(
                    f"Strace process exited quickly (code {proc_exit_code}). Target command/attach issue?{stderr_msg}"
                )
                # Don't raise here, might still be data in FIFO

            if fifo_reader:
                for line in fifo_reader:
                    yield line.rstrip("\n")  # Yield raw line
                log.info("End of FIFO stream reached.")
                fifo_reader.close()
                fifo_reader = None
            else:
                log.warning(
                    "No FIFO reader available or stream was empty (process might have exited quickly)."
                )

            # Wait for process completion and check stderr
            stderr_output = ""
            if proc.stderr:
                stderr_output = proc.stderr.read()
                proc.stderr.close()
            if stderr_output.strip():
                log.warning(f"Strace stderr output:\n{stderr_output.strip()}")

            exit_code = proc.wait()  # Wait for strace process termination
            log.info(f"Strace process exited with code {exit_code}.")

    except FileNotFoundError:
        cmd_name = target_command[0] if target_command else "attach target"
        log.error(f"Command not found. Check 'strace' and '{shlex.quote(cmd_name)}'.")
        raise
    except Exception as e:
        log.exception(f"An error occurred during strace execution: {e}")
        # Don't re-raise here, allow finally block to run
    finally:
        log.info("Cleaning up stream_strace_output...")
        if proc and proc.poll() is None:
            log.warning(
                f"Terminating potentially running strace process (PID {proc.pid})..."
            )
            proc.terminate()
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                log.warning("Process did not terminate gracefully, killing...")
                proc.kill()
            log.info("Strace process terminated on cleanup.")
        if fifo_reader:  # Should be None if closed normally
            try:
                fifo_reader.close()
            except Exception:
                pass
        # FIFO path and temp dir cleanup handled by context manager exit


# --- Generator: Parsing the Stream ---


def parse_strace_stream(
    target_command: Optional[List[str]] = None,
    attach_ids: Optional[List[int]] = None,
    syscalls: List[str] = DEFAULT_SYSCALLS,
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
    tid_to_pid_map: Dict[int, int] = {}

    # --- Pre-populate map if attaching ---
    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        for initial_tid in attach_ids:
            try:
                # Check existence first to avoid warnings on expected missing TIDs
                if not psutil.pid_exists(initial_tid):
                    log.warning(f"Initial TID {initial_tid} does not exist. Skipping.")
                    continue
                proc_info = psutil.Process(initial_tid)
                pid = proc_info.pid  # Get TGID
                tid_to_pid_map[initial_tid] = pid
                log.debug(f"Mapped initial TID {initial_tid} to PID {pid}")
            except psutil.NoSuchProcess:
                log.warning(
                    f"Process/Thread with TID {initial_tid} disappeared during initial mapping."
                )
            except psutil.AccessDenied:
                log.warning(
                    f"Access denied getting PID for initial TID {initial_tid}. Mapping might be incomplete."
                )
            except Exception as e:
                log.error(f"Error getting PID for initial TID {initial_tid}: {e}")

    # --- Process Stream ---
    # Ensure process creation syscalls are traced for mapping
    combined_syscalls = sorted(list(set(syscalls) | set(PROCESS_SYSCALLS)))

    for line in stream_strace_output(target_command, attach_ids, combined_syscalls):
        timestamp = time.time()
        match = STRACE_LINE_RE.match(line.strip())
        if not match:
            log.debug(f"Unmatched strace line: {line.strip()}")
            continue  # Skip unmatched lines

        data = match.groupdict()
        try:
            tid = int(data["tid"])
            syscall = data["syscall"]
            args_str = data["args"]
            result_str = data["result"]
            error_name = data.get("error")
            error_msg = data.get("errmsg")
            success = error_name is None  # Determine success early

            # --- Lookup/Determine PID (TGID) ---
            pid = tid_to_pid_map.get(tid)
            if pid is None:
                # If TID not in map, assume it's a main thread (TID=PID)
                # or we missed its creation (attach mode to non-main thread?)
                # We could try psutil lookup here, but it's slow per-event.
                # Defaulting TID=PID is usually correct for the initial process
                # and clone/fork handling should catch descendants.
                pid = tid
                tid_to_pid_map[tid] = pid
                log.debug(f"TID {tid} not in map, assuming PID=TID.")
            # --- End PID Lookup ---

            # Parse arguments using state machine
            parsed_args_list = _parse_args_state_machine(args_str)

            # --- Update map on clone/fork success ---
            if syscall in PROCESS_SYSCALLS and success:
                try:
                    result_code = _parse_result_int(result_str)
                    if (
                        result_code is not None and result_code > 0
                    ):  # Parent context receiving child ID
                        new_id = result_code
                        if new_id not in tid_to_pid_map:
                            tid_to_pid_map[new_id] = (
                                pid  # Map new TID/PID to parent's PID (TGID)
                            )
                            log.info(
                                f"Syscall {syscall}: Mapped new TID/PID {new_id} to parent PID {pid}"
                            )
                except Exception as map_e:
                    log.error(f"Error updating TID map for {syscall}: {map_e}")
            # --- End Map Update ---

            yield Syscall(
                timestamp=timestamp,
                tid=tid,
                pid=pid,  # Resolved PID (TGID)
                syscall=syscall,
                args=parsed_args_list,
                result_str=result_str,
                error_name=error_name,
                error_msg=error_msg,
            )
        except Exception as parse_exc:
            log.error(f"Error parsing matched line: {line.strip()} -> {parse_exc}")


# --- Main function and entry point removed ---
# This module is now intended only for import.
# Testing should be done via strace.py or dedicated test files.
