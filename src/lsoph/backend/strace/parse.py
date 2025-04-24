# Filename: src/lsoph/backend/strace/parse.py
"""Parsing logic for strace output."""

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Optional  # Added Optional

from lsoph.monitor import Monitor

# Import helpers here if needed by parsing logic itself, or keep in backend
from . import helpers

log = logging.getLogger(__name__)

# --- Constants ---
# Syscalls indicating process creation/management
PROCESS_SYSCALLS = ["clone", "fork", "vfork"]
# Syscalls indicating process termination
EXIT_SYSCALLS = ["exit", "exit_group"]
# Syscalls indicating potential resumption after signal
RESUME_SYSCALLS = ["rt_sigreturn", "sigreturn"]

# --- Regular Expressions ---
# Matches the start of a typical strace line: [pid NNNN] or NNNN
PID_RE = re.compile(r"^(?:\[pid\s+)?(\d+)\)?")

# Matches the timestamp at the start of the line (if present)
TIMESTAMP_RE = re.compile(r"^\s*(\d+\.\d+)\s+")

# Matches the core syscall part: syscall_name(arg1, arg2, ...) = result <...>
# Updated to handle various argument formats and potential errors like ERESTARTSYS
# Further updated to handle extraneous text after arguments (e.g., attach messages)
SYSCALL_RE = re.compile(
    r"""
    ^                     # Start of the string (after PID/timestamp removal)
    (?P<syscall>\w+)      # Syscall name (letters, numbers, underscore)
    \(                    # Opening parenthesis for arguments
    (?P<args>.*?)         # Arguments (non-greedy match) - will need further parsing
    \)                    # Closing parenthesis
    # --- Make the result part optional and handle potential extra text ---
    (?:                   # Optional non-capturing group for the result part
        \s*=\s* # Equals sign surrounded by optional whitespace
        (?P<result_str>   # Start capturing result string
            (?:           # Non-capturing group for hex, decimal, or '?'
                -?\d+     # Optional negative sign, followed by digits (decimal)
                |
                0x[0-9a-fA-F]+ # Hexadecimal number
                |
                \?        # Question mark (for unfinished syscalls)
            )
            (?:           # Optional non-capturing group for error code/name
                \s+
                (?P<error_name>[A-Z][A-Z0-9_]+) # Error name (e.g., ENOENT)
                \s*
                \(
                (?P<error_msg>.*?) # Error message (non-greedy)
                \)
            )?            # Error part is optional
        )                 # End capturing result_str
        (?:               # Optional non-capturing group for timing info
            \s+
            <(?P<timing>\d+\.\d+)>
        )?                # Timing part is optional
    )?                    # Make the entire = result ... part optional
    .*?                   # Allow any characters non-greedily after args/result (like the attach message)
    $                     # End of the string
    """,
    re.VERBOSE,
)

# Matches lines indicating syscall was unfinished
UNFINISHED_RE = re.compile(r"<unfinished \.\.\.>$")

# Matches lines indicating syscall resumption
RESUMED_RE = re.compile(r"<\.\.\. (?P<syscall>\w+) resumed> (.*)")

# Matches signal delivery lines
SIGNAL_RE = re.compile(r"--- SIG(\w+) .* ---$")


# --- Dataclass for Parsed Syscall ---
@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    pid: int
    syscall: str
    args: list[str] = field(default_factory=list)
    result_str: str | None = None
    result_int: int | None = None  # Store parsed integer result
    child_pid: int | None = None  # Store child PID for clone/fork/vfork
    error_name: str | None = None
    error_msg: str | None = None
    timing: float | None = None
    timestamp: float = field(default_factory=time.time)  # Timestamp when processed
    raw_line: str = ""  # Store original line for debugging

    @property
    def success(self) -> bool:
        """Determine if the syscall was successful (no error reported)."""
        # Consider a syscall successful if there's no error name
        # AND the result is not typically an error indicator like -1 (unless result is None or ?)
        # This is a heuristic.
        if self.error_name:
            return False
        if self.result_int is not None and self.result_int < 0:
            # Common pattern for errors when error_name isn't parsed (e.g., older strace)
            return False
        # Treat cases with no result or '?' as potentially successful or indeterminate
        return True

    def __repr__(self) -> str:
        # Provide a more concise representation for logging
        err_part = f" ERR={self.error_name}" if self.error_name else ""
        child_part = f" CHILD={self.child_pid}" if self.child_pid else ""
        return f"Syscall(pid={self.pid}, ts={self.timestamp:.3f}, call={self.syscall}(...), ret={self.result_str}{err_part}{child_part})"


# --- Parsing Functions ---


def _parse_args_simple(args_str: str) -> list[str]:
    """
    A simple argument parser. Handles basic quoted strings and commas.
    Limitations: Doesn't handle nested structures or complex escapes perfectly.
    """
    args = []
    current_arg = ""
    in_quotes = False
    escape_next = False
    # Add a dummy comma at the end to help flush the last argument
    args_str += ","

    for char in args_str:
        if escape_next:
            current_arg += char
            escape_next = False
        elif char == "\\":
            escape_next = True
            current_arg += char  # Keep the backslash for now
        elif char == '"':
            in_quotes = not in_quotes
            current_arg += char
        elif char == "," and not in_quotes:
            # Argument finished
            args.append(current_arg.strip())
            current_arg = ""
        else:
            current_arg += char

    # The dummy comma ensures the last argument is processed,
    # but might leave an empty string if the original string ended with a comma.
    # We filter out empty strings that might result from trailing commas or empty args.
    return [arg for arg in args if arg]


def _parse_strace_line(
    line: str, unfinished_syscalls: dict[int, str], current_time: float
) -> Syscall | None:
    """
    Parses a single line of strace output. Handles PID, timestamp, syscall,
    unfinished/resumed lines, and signals. Extracts child PID for clone/fork/vfork.
    """
    original_line = line
    pid: int | None = None
    timestamp: float | None = None

    # 1. Extract PID
    pid_match = PID_RE.match(line)
    if pid_match:
        pid = int(pid_match.group(1))
        line = line[pid_match.end() :].lstrip()
    else:
        signal_match = SIGNAL_RE.match(line)
        if signal_match:
            return None  # Ignore signal lines
        # log.debug(f"Could not extract PID from line: {original_line}") # Reduce noise
        return None

    # 2. Extract Timestamp (optional)
    ts_match = TIMESTAMP_RE.match(line)
    if ts_match:
        try:
            timestamp = float(ts_match.group(1))
        except ValueError:
            pass  # Ignore timestamp parse errors
        line = line[ts_match.end() :].lstrip()

    event_timestamp = timestamp if timestamp is not None else current_time

    # 3. Handle Unfinished/Resumed/Signal lines
    unfinished_match = UNFINISHED_RE.search(line)
    if unfinished_match:
        syscall_part = line[: unfinished_match.start()].strip()
        syscall_name = syscall_part.split("(", 1)[0]
        if syscall_name:  # Only store if we got a name
            unfinished_syscalls[pid] = syscall_name
            # log.debug(f"Stored unfinished syscall for PID {pid}: {syscall_name}") # Reduce noise
        return None

    resumed_match = RESUMED_RE.match(line)
    if resumed_match:
        syscall_name = resumed_match.group("syscall")
        if unfinished_syscalls.get(pid) == syscall_name:
            # log.debug(f"Matched resumed syscall for PID {pid}: {syscall_name}") # Reduce noise
            del unfinished_syscalls[pid]
            line = resumed_match.group(2).strip()  # Process the rest of the line
        else:
            # log.warning(f"Resumed syscall '{syscall_name}' for PID {pid} without matching unfinished call. Stored: {unfinished_syscalls.get(pid)}") # Reduce noise
            return None  # Discard mismatched resumption

    signal_match = SIGNAL_RE.match(line)
    if signal_match:
        if pid in unfinished_syscalls:
            # log.debug(f"Clearing unfinished syscall for PID {pid} due to signal delivery.") # Reduce noise
            del unfinished_syscalls[pid]
        return None

    # 4. Parse the core syscall structure
    syscall_match = SYSCALL_RE.match(line)
    if syscall_match:
        data = syscall_match.groupdict()
        syscall_name = data["syscall"]

        args_list = _parse_args_simple(data.get("args", "") or "")

        result_str = data.get("result_str")
        error_name = data.get("error_name")
        error_msg = data.get("error_msg")
        timing_str = data.get("timing")
        timing = float(timing_str) if timing_str else None

        # Parse integer result and potential child PID
        result_int: Optional[int] = None
        child_pid: Optional[int] = None
        if result_str:
            result_int = helpers.parse_result_int(result_str)
            # If clone/fork/vfork succeeded (no error, result >= 0), result is child PID
            if (
                syscall_name in PROCESS_SYSCALLS
                and not error_name
                and result_int is not None
                and result_int >= 0
            ):
                child_pid = result_int

        # Clear unfinished state if this syscall matches the one stored
        if unfinished_syscalls.get(pid) == syscall_name:
            # log.debug(f"Implicitly clearing unfinished {syscall_name} for PID {pid}") # Reduce noise
            del unfinished_syscalls[pid]

        return Syscall(
            pid=pid,
            syscall=syscall_name,
            args=args_list,
            result_str=result_str,
            result_int=result_int,  # Store parsed int result
            child_pid=child_pid,  # Store parsed child PID
            error_name=error_name,
            error_msg=error_msg,
            timing=timing,
            timestamp=event_timestamp,
            raw_line=original_line,
        )
    else:
        # Reduce noise for common ignored lines
        # if "resumed" in line: pass
        # elif line.startswith("+++ exited with") or line.startswith("+++ killed by"): pass
        # else: log.warning(f"Failed to parse syscall line structure for PID {pid}: {original_line}")
        return None


# --- Async Stream Parser ---
async def parse_strace_stream(
    lines: AsyncIterator[str],
    monitor: Monitor,
    stop_event: asyncio.Event,
    syscalls: list[str] | None = None,
    attach_ids: list[int] | None = None,
) -> AsyncIterator[Syscall]:
    """
    Asynchronously parses a stream of raw strace output lines into Syscall objects.
    """
    # log.info("Starting strace stream parser...") # Reduce noise
    unfinished_syscalls: dict[int, str] = {}
    line_count = 0
    parsed_count = 0

    try:
        async for line in lines:
            line_count += 1
            if stop_event.is_set():
                break

            current_time = time.time()
            parsed_event = _parse_strace_line(line, unfinished_syscalls, current_time)

            if parsed_event:
                if syscalls is None or parsed_event.syscall in syscalls:
                    parsed_count += 1
                    yield parsed_event
            # Prevent tight loop on fast/empty streams
            await asyncio.sleep(0.001)

    except asyncio.CancelledError:
        log.info("Strace stream parsing task cancelled.")
    # Let other exceptions propagate (like UnicodeDecodeError)
    # except Exception as e: log.exception(f"Error during strace stream parsing: {e}")
    finally:
        log.info(
            f"Exiting strace stream parser. Processed {line_count} lines, yielded {parsed_count} events."
        )
        if unfinished_syscalls:
            log.warning(
                f"Parser exiting with unfinished syscalls: {unfinished_syscalls}"
            )
