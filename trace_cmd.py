#!/usr/bin/env python3

import argparse
import contextlib
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import List, Iterator, Optional, Any, Dict

# --- Setup Logging ---
logging.basicConfig(level=os.environ.get("LOGLEVEL", "WARNING").upper(),
                    format='%(levelname)s:%(name)s:%(message)s')
log = logging.getLogger(__name__)

# --- Configuration ---
# Categorized Syscalls
FILE_STRUCT_SYSCALLS = [
    "open", "openat", "creat", "access", "stat", "lstat", "newfstatat",
    "close", "unlink", "unlinkat", "rename", "renameat",
]
IO_SYSCALLS = [
    "read", "pread64", "readv", "write", "pwrite64", "writev",
]
DEFAULT_SYSCALLS = sorted(list(set(FILE_STRUCT_SYSCALLS + IO_SYSCALLS)))

STRACE_BASE_OPTIONS = [
    "-f", "-s", "4096", "-qq",
]

# --- Data Structures ---

@dataclass
class Syscall: # Renamed from ParsedSyscall
    """Structured representation of a parsed strace line."""
    timestamp: float
    pid: int
    syscall: str
    args: List[Any]     # Parsed arguments list (heuristic)
    result_str: str     # Raw result string
    error_name: Optional[str] = None
    error_msg: Optional[str] = None
    extracted_path: Optional[str] = None # Result of simple path extraction heuristic

# --- Regex and Parsing Helpers ---

STRACE_LINE_RE = re.compile(
    r"^(?P<pid>\d+)\s+"
    r"(?:\[\d+\]\s+)?"
    r"(?P<syscall>\w+)\("
    r"(?P<args>.*?)"
    r"\)\s+=\s+"
    r"(?P<result>-?\d+|0x[\da-fA-F]+)"
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
)

def _parse_args_heuristic(args_str: str) -> List[Any]:
    """
    Performs basic heuristic parsing of the strace arguments string.
    Splits by comma, attempts to convert numbers, unquotes strings.
    WARNING: This is NOT a robust parser for complex args or structs.
    """
    if not args_str:
        return []

    args = []
    # Basic comma split - doesn't handle commas inside quotes/structs well
    # A more robust approach might involve more careful tokenization
    raw_parts = args_str.split(',')
    
    current_part = ""
    in_string = False
    paren_level = 0 # Track parentheses for things like struct args
    
    # Re-join parts that were incorrectly split inside quotes or parens
    processed_parts = []
    for part in raw_parts:
        current_part += part
        if '"' in part:
            # Count quotes, toggle in_string state
            # This is imperfect if quotes are escaped or unbalanced
            if part.count('"') % 2 != 0:
                 in_string = not in_string
        
        # Basic parenthesis tracking
        paren_level += part.count('(')
        paren_level -= part.count(')')
        paren_level += part.count('{') # Treat structs like parens for joining
        paren_level -= part.count('}')
        
        if not in_string and paren_level <= 0:
            processed_parts.append(current_part.strip())
            current_part = ""
        else:
             # Append comma back if we are joining parts
             current_part += "," 
             
    if current_part: # Add any remaining part
        processed_parts.append(current_part.strip())


    for part in processed_parts:
        part = part.strip()
        # Try converting to int (decimal or hex)
        try:
            if part.startswith("0x"):
                args.append(int(part, 16))
                continue
            else:
                # Check if it's potentially octal (starts with 0) but handle simple 0
                if len(part) > 1 and part.startswith('0') and part[1:].isdigit():
                     try:
                         args.append(int(part, 8))
                         continue
                     except ValueError: # Not valid octal, treat as string/decimal
                         pass
                # Try decimal last
                args.append(int(part))
                continue
        except ValueError:
            pass # Not an int

        # Check for quoted strings
        if len(part) >= 2 and part.startswith('"') and part.endswith('"'):
            try:
                # Decode escapes within the string
                args.append(part[1:-1].encode('utf-8').decode('unicode_escape'))
                continue
            except Exception:
                args.append(part[1:-1]) # Keep raw content if unescaping fails
                continue
        
        # Keep other things (constants like O_RDONLY, AT_FDCWD, structs {...}, etc.) as strings
        args.append(part)

    return args


def extract_path_from_parsed_args(syscall: str, args: List[Any]) -> Optional[str]:
    """
    Attempt to extract the primary file path from the *parsed* arguments list.
    """
    try:
        path_arg_index = -1
        if syscall in ["open", "creat", "access", "stat", "lstat", "unlink", "rename"]:
            if len(args) > 0: path_arg_index = 0
        elif syscall in ["openat", "newfstatat", "unlinkat", "renameat"]:
            if len(args) > 1: path_arg_index = 1

        if path_arg_index != -1:
            potential_path = args[path_arg_index]
            # Check if the argument looks like a path (is a string)
            if isinstance(potential_path, str):
                 # Basic check - might need refinement
                 if potential_path.startswith(('/', '.')) or '/' not in potential_path:
                      # Exclude constants that might be strings
                      if potential_path not in ["AT_FDCWD"]:
                           return potential_path
    except Exception:
        pass # Ignore errors in heuristic
    return None


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
# Renamed back to public, signature uses default arg
def stream_strace_output(
    target_command: List[str],
    syscalls: List[str] = DEFAULT_SYSCALLS # Use default arg
) -> Iterator[str]:
    """
    Runs target command under strace, yields raw output lines from FIFO.
    """
    if not target_command:
        raise ValueError("Target command list cannot be empty.")
    # No need for: syscall_list = syscalls or DEFAULT_SYSCALLS
    if not syscalls:
        raise ValueError("Syscall list cannot be empty.")

    strace_path = shutil.which("strace")
    if not strace_path:
        raise FileNotFoundError("Could not find 'strace' executable in PATH.")

    proc = None
    fifo_reader = None

    try:
        with temporary_fifo() as fifo_path:
            strace_command = [
                strace_path, *STRACE_BASE_OPTIONS,
                "-e", f"trace={','.join(syscalls)}", # Use syscalls directly
                "-o", fifo_path, *target_command
            ]

            log.info(f"Executing: {' '.join(shlex.quote(c) for c in strace_command)}")
            proc = subprocess.Popen(
                strace_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace'
            )

            log.info(f"Opening FIFO {fifo_path} for reading...")
            try:
                fifo_reader = open(fifo_path, "r", encoding='utf-8', errors='replace')
                log.info("FIFO opened. Reading stream...")
            except Exception as e:
                proc_exit_code = proc.poll()
                stderr_output = proc.stderr.read() if proc.stderr else ""
                if proc_exit_code is not None:
                    stderr_msg = f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                    raise RuntimeError(f"Failed to open FIFO. Strace process exited early (code {proc_exit_code}).{stderr_msg} Error: {e}") from e
                else:
                    raise RuntimeError(f"Failed to open FIFO for reading: {e}") from e

            time.sleep(0.1) # Check for quick exit
            proc_exit_code = proc.poll()
            if proc_exit_code is not None:
                 stderr_output = proc.stderr.read() if proc.stderr else ""
                 stderr_msg = f" Stderr: '{stderr_output[:500]}'." if stderr_output else ""
                 log.warning(f"Strace process exited quickly (code {proc_exit_code}). Target command issue?{stderr_msg}")

            if fifo_reader:
                for line in fifo_reader:
                    yield line.rstrip('\n') # Yield raw line
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
        log.error(f"Command not found. Check 'strace' and '{shlex.quote(target_command[0])}' are in PATH.")
        raise
    except Exception as e:
        log.exception(f"An error occurred during strace execution: {e}")
    finally:
        log.info("Cleaning up stream_strace_output...")
        if proc and proc.poll() is None:
            log.warning(f"Terminating potentially running strace process (PID {proc.pid})...")
            proc.terminate()
            try: proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired: proc.kill()
            log.info("Strace process terminated on cleanup.")
        if fifo_reader:
             try: fifo_reader.close()
             except Exception: pass
        # FIFO/tempdir cleanup handled by context manager


# --- New Generator: Parsing the Stream ---

def parse_strace_stream( # Signature uses default arg
    target_command: List[str],
    syscalls: List[str] = DEFAULT_SYSCALLS
) -> Iterator[Syscall]: # Yields Syscall objects
    """
    Runs strace via stream_strace_output and parses the raw lines
    into Syscall objects.
    """
    log.info("Starting parse_strace_stream...")
    # Iterate through the raw lines from the helper generator
    for line in stream_strace_output(target_command, syscalls): # Pass syscalls through
        timestamp = time.time() # Record timestamp when line is processed
        match = STRACE_LINE_RE.match(line.strip())
        if match:
            data = match.groupdict()
            try:
                pid = int(data["pid"])
                syscall = data["syscall"]
                args_str = data["args"]
                result_str = data["result"]
                error_name = data.get("error")
                error_msg = data.get("errmsg")

                # Parse arguments heuristically
                parsed_args = _parse_args_heuristic(args_str)

                # Extract path using the heuristic on parsed args
                extracted_path = extract_path_from_parsed_args(syscall, parsed_args)

                # Yield the structured data
                yield Syscall( # Use renamed dataclass
                    timestamp=timestamp,
                    pid=pid,
                    syscall=syscall,
                    args=parsed_args, # Store parsed args list
                    result_str=result_str, # Keep result raw for now
                    error_name=error_name,
                    error_msg=error_msg,
                    extracted_path=extracted_path
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
    if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        log_level = 'INFO'
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s:%(name)s:%(message)s')
    log.info(f"Log level set to {log_level}")

    parser = argparse.ArgumentParser(
        description="Runs a target command under strace and prints parsed syscall events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 %(prog)s find . -maxdepth 1"
    )
    parser.add_argument(
        "command", nargs=argparse.REMAINDER,
        help="The target command and its arguments (e.g., find . -type f)"
    )
    # TODO: Add optional --syscalls argument via command line

    args = parser.parse_args(argv)

    if not args.command:
         log.critical("No command provided.")
         parser.print_usage(sys.stderr)
         return 1

    if os.geteuid() != 0:
        log.warning("Running without root. 'strace' requires privileges (run this script with sudo).")

    try:
        log.info("Starting trace and parsing...")
        event_count = 0
        # Use the parse_strace_stream generator
        for syscall_event in parse_strace_stream(target_command=args.command):
            # Print the structured event (using default dataclass repr)
            print(repr(syscall_event))
            event_count += 1
        log.info(f"Finished processing {event_count} syscall events.")
        return 0 # Success

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
