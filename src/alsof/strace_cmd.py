#!/usr/bin/env python3

import argparse
import contextlib
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

import psutil  # <-- Import psutil

# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger(__name__)

# --- Configuration ---
# Add clone/fork/vfork to syscalls traced for PID/TID mapping
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
DEFAULT_SYSCALLS = sorted(
    list(set(PROCESS_SYSCALLS + FILE_STRUCT_SYSCALLS + IO_SYSCALLS))
)

STRACE_BASE_OPTIONS = [
    "-f",
    "-s",
    "4096",
    "-qq",
]

# --- Data Structures ---


@dataclass
class Syscall:
    """Structured representation of a parsed strace line with PID/TID."""

    timestamp: float
    tid: int  # Thread ID (from strace prefix)
    pid: int  # Process ID / Thread Group ID (TGID)
    syscall: str
    args: List[str]  # List of raw argument strings
    result_str: str  # Raw result string
    error_name: Optional[str] = None
    error_msg: Optional[str] = None
    # extracted_path field removed


# --- Regex and Parsing Helpers ---

STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"  # <-- Changed group name pid -> tid
    r"(?:\[\d+\]\s+)?"
    r"(?P<syscall>\w+)\("
    r"(?P<args>.*?)"
    r"\)\s+=\s+"
    r"(?P<result>-?\d+|0x[\da-fA-F]+)"
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
)


def _parse_args_state_machine(args_str: str) -> List[str]:
    """
    Parses the strace arguments string by splitting on top-level commas,
    respecting basic nesting of (), {}, and "" quotes.
    (Implementation unchanged)
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


# --- Temporary FIFO Context Manager (Unchanged) ---
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
            log.info(f"FIFO {fifo_path} will be cleaned up.")


# --- Low-level Strace Output Streamer ---
# Signature changed to accept target_command OR attach_ids
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

    proc = None
    fifo_reader = None

    try:
        with temporary_fifo() as fifo_path:
            strace_command = [strace_path, *STRACE_BASE_OPTIONS]
            strace_command.extend(["-e", f"trace={','.join(syscalls)}"])
            strace_command.extend(["-o", fifo_path])

            if target_command:
                # Use '--' to separate strace options from the target command
                strace_command.extend(["--", *target_command])
                log.info(
                    f"Preparing to launch: {' '.join(shlex.quote(c) for c in target_command)}"
                )
            elif attach_ids:
                # Add -p PID for each ID to attach to
                for pid_or_tid in attach_ids:
                    strace_command.extend(["-p", str(pid_or_tid)])
                log.info(f"Preparing to attach to IDs: {attach_ids}")

            log.info(f"Executing: {' '.join(shlex.quote(c) for c in strace_command)}")
            proc = subprocess.Popen(
                strace_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            log.info(f"Opening FIFO {fifo_path} for reading...")
            try:
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

            time.sleep(0.1)  # Check for quick exit
            proc_exit_code = proc.poll()
            if proc_exit_code is not None:
                stderr_output = proc.stderr.read() if proc.stderr else ""
                stderr_msg = (
                    f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                )
                log.warning(
                    f"Strace process exited quickly (code {proc_exit_code}). Target command/attach issue?{stderr_msg}"
                )

            if fifo_reader:
                for line in fifo_reader:
                    yield line.rstrip("\n")  # Yield raw line
                log.info("End of FIFO stream reached.")
                fifo_reader.close()
                fifo_reader = None
            else:
                log.warning("No FIFO reader available or stream was empty.")

            stderr_output = ""
            if proc.stderr:
                stderr_output = proc.stderr.read()
                proc.stderr.close()
            if stderr_output.strip():
                log.warning(f"Strace stderr output:\n{stderr_output.strip()}")

            exit_code = proc.wait()
            log.info(f"Strace process exited with code {exit_code}.")

    except FileNotFoundError:
        cmd_name = target_command[0] if target_command else "attach target"
        log.error(f"Command not found. Check 'strace' and '{shlex.quote(cmd_name)}'.")
        raise
    except Exception as e:
        log.exception(f"An error occurred during strace execution: {e}")
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
                proc.kill()
            log.info("Strace process terminated on cleanup.")
        if fifo_reader:
            try:
                fifo_reader.close()
            except Exception:
                pass
        # FIFO/tempdir cleanup handled by context manager


# --- Generator: Parsing the Stream ---


def parse_strace_stream(
    target_command: Optional[List[str]] = None,
    attach_ids: Optional[List[int]] = None,
    syscalls: List[str] = DEFAULT_SYSCALLS,
) -> Iterator[Syscall]:
    """
    Runs strace (launch or attach) and parses the raw output lines
    into Syscall objects, tracking TID -> PID mapping.
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
                proc_info = psutil.Process(initial_tid)
                # In psutil, pid attribute gives the TGID (main process PID)
                tid_to_pid_map[initial_tid] = proc_info.pid
                log.debug(f"Mapped initial TID {initial_tid} to PID {proc_info.pid}")
            except psutil.NoSuchProcess:
                log.warning(
                    f"Process/Thread with TID {initial_tid} not found during initial mapping."
                )
            except psutil.AccessDenied:
                log.warning(
                    f"Access denied when getting PID for initial TID {initial_tid}. Mapping might be incomplete."
                )
            except Exception as e:
                log.error(f"Error getting PID for initial TID {initial_tid}: {e}")

    # --- Process Stream ---
    for line in stream_strace_output(target_command, attach_ids, syscalls):
        timestamp = time.time()
        match = STRACE_LINE_RE.match(line.strip())
        if match:
            data = match.groupdict()
            try:
                tid = int(data["tid"])  # <-- Renamed group in regex
                syscall = data["syscall"]
                args_str = data["args"]
                result_str = data["result"]
                error_name = data.get("error")
                error_msg = data.get("errmsg")

                # --- Lookup/Determine PID (TGID) ---
                pid = tid_to_pid_map.get(tid)
                if pid is None:
                    # If TID not in map, assume it's a main thread (TID=PID)
                    # or we missed its creation (less likely with -f from start)
                    # Try psutil lookup only if absolutely necessary? Might be slow.
                    # For now, assume TID=PID if not found.
                    pid = tid
                    tid_to_pid_map[tid] = pid
                    log.debug(f"TID {tid} not in map, assuming PID=TID.")
                # --- End PID Lookup ---

                # Parse arguments using state machine
                parsed_args_list = _parse_args_state_machine(args_str)

                # --- Update map on clone/fork success ---
                if syscall in PROCESS_SYSCALLS and error_name is None:
                    try:
                        # Result is the new TID (clone) or PID (fork/vfork) in parent
                        if result_str.startswith("0x"):
                            new_id = int(result_str, 16)
                        else:
                            new_id = int(result_str)

                        if new_id > 0:  # Parent context receiving child ID
                            # The new thread/process inherits the parent's PID (TGID)
                            # Map the new child TID/PID to the *current* process's PID (TGID)
                            if new_id not in tid_to_pid_map:
                                tid_to_pid_map[new_id] = pid
                                log.info(
                                    f"Syscall {syscall}: Mapped new TID/PID {new_id} to parent PID {pid}"
                                )
                            # else: Mapping already exists (e.g. saw attach message earlier?)
                    except ValueError:
                        log.warning(
                            f"Could not parse result '{result_str}' for {syscall} to get new TID/PID."
                        )
                    except Exception as map_e:
                        log.error(f"Error updating TID map for {syscall}: {map_e}")
                # --- End Map Update ---

                yield Syscall(
                    timestamp=timestamp,
                    tid=tid,  # Thread ID from strace line
                    pid=pid,  # Process ID (TGID) from map
                    syscall=syscall,
                    args=parsed_args_list,
                    result_str=result_str,
                    error_name=error_name,
                    error_msg=error_msg,
                )
            except Exception as parse_exc:
                log.error(f"Error parsing matched line: {line.strip()} -> {parse_exc}")
        else:
            log.debug(f"Unmatched strace line: {line.strip()}")
            pass


# --- Main Execution Function ---


def main(argv: Optional[List[str]] = None) -> int:
    """
    Parses command line arguments, runs the parse_strace_stream generator,
    and prints the structured output. Returns an exit code.
    """
    log_level = os.environ.get("LOGLEVEL", "INFO").upper()
    if log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        log_level = "INFO"
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s:%(name)s:%(message)s"
    )
    log.info(f"Log level set to {log_level}")

    parser = argparse.ArgumentParser(
        description="Runs or attaches to a command under strace and prints parsed syscall events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python3 %(prog)s -c find . -maxdepth 1\n"
        "  sudo python3 %(prog)s -p 1234 5678\n"
        "  sudo python3 %(prog)s -c sleep 60",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--command",
        nargs=argparse.REMAINDER,
        help="The target command and its arguments to launch and trace.",
    )
    group.add_argument(
        "-p",
        "--pids",
        nargs="+",
        type=int,
        metavar="PID_OR_TID",
        help="One or more existing process or thread IDs to attach to.",
    )
    # TODO: Add optional --syscalls argument via command line

    args = parser.parse_args(argv)

    # Determine mode and arguments
    target_command: Optional[List[str]] = None
    attach_ids: Optional[List[int]] = None

    if args.command:
        if not args.command:  # Should be caught by REMAINDER but safety check
            log.critical("No command provided for -c.")
            parser.print_usage(sys.stderr)
            return 1
        target_command = args.command
    elif args.pids:
        attach_ids = args.pids
    else:
        # Should be caught by argparse group 'required=True'
        log.critical("Must provide either -c or -p.")
        parser.print_usage(sys.stderr)
        return 1

    if os.geteuid() != 0:
        log.warning(
            "Running without root. 'strace' requires privileges (run this script with sudo)."
        )

    try:
        log.info("Starting trace and parsing...")
        event_count = 0
        # Call the parser with the correct arguments based on mode
        for syscall_event in parse_strace_stream(
            target_command=target_command, attach_ids=attach_ids
        ):
            print(repr(syscall_event))  # Print the structured Syscall object
            event_count += 1
        log.info(f"Finished processing {event_count} syscall events.")
        return 0  # Success

    except (ValueError, FileNotFoundError, RuntimeError) as e:
        log.error(f"Execution failed: {e}")
        return 1
    except KeyboardInterrupt:
        log.info("\nCtrl+C detected. Exiting main script.")
        return 130
    except Exception as e:
        log.exception(f"An unexpected error occurred in main: {e}")
        return 1


# --- Script Entry Point ---

if __name__ == "__main__":
    sys.exit(main())
