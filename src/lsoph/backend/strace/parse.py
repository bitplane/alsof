# Filename: src/lsoph/backend/strace/parse.py
"""Parsing logic for strace output."""

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from lsoph.monitor import Monitor

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
SYSCALL_RE = re.compile(
    r"""
    ^                      # Start of the string (after PID/timestamp removal)
    (?P<syscall>\w+)       # Syscall name (letters, numbers, underscore)
    \(                     # Opening parenthesis for arguments
    (?P<args>.*?)          # Arguments (non-greedy match) - will need further parsing
    \)                     # Closing parenthesis
    \s*=\s* # Equals sign surrounded by optional whitespace
    (?P<result_str>        # Start capturing result string
        (?:                # Non-capturing group for hex, decimal, or '?'
            -?\d+          # Optional negative sign, followed by digits (decimal)
            |              # OR
            0x[0-9a-fA-F]+ # Hexadecimal number
            |              # OR
            \?             # Question mark (for unfinished syscalls)
        )
        (?:                # Optional non-capturing group for error code/name
            \s+            # Whitespace separator
            (?P<error_name>[A-Z][A-Z0-9_]+) # Error name (e.g., ENOENT)
            \s* # Optional whitespace
            \(             # Opening parenthesis for error message
            (?P<error_msg>.*?) # Error message (non-greedy)
            \)             # Closing parenthesis
        )?                 # Error part is optional
        (?:                # Optional non-capturing group for timing info
            \s+            # Whitespace separator
            <(?P<timing>\d+\.\d+)> # Timing info in angle brackets
        )?                 # Timing part is optional
    )?                     # Result part itself is optional (for unfinished/resumed)
    $                      # End of the string
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
    error_name: str | None = None
    error_msg: str | None = None
    timing: float | None = None
    timestamp: float = field(default_factory=time.time)  # Timestamp when processed
    raw_line: str = ""  # Store original line for debugging

    def __repr__(self) -> str:
        # Provide a more concise representation for logging
        err_part = f" ERR={self.error_name}" if self.error_name else ""
        return f"Syscall(pid={self.pid}, ts={self.timestamp:.3f}, call={self.syscall}(...), ret={self.result_str}{err_part})"


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
    unfinished/resumed lines, and signals.
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
        # If no PID found at the start, it might be a continuation or signal line
        # Check for signal line first
        signal_match = SIGNAL_RE.match(line)
        if signal_match:
            # We don't have a PID for signal lines easily, skip for now
            log.debug(f"Ignoring signal line: {original_line}")
            return None
        # If not a signal, assume it's invalid or continuation we can't parse standalone
        log.debug(f"Could not extract PID from line: {original_line}")
        return None  # Cannot proceed without PID

    # 2. Extract Timestamp (optional)
    ts_match = TIMESTAMP_RE.match(line)
    if ts_match:
        try:
            timestamp = float(ts_match.group(1))
        except ValueError:
            log.warning(f"Could not parse timestamp from line: {original_line}")
        line = line[ts_match.end() :].lstrip()

    # Use current time if timestamp wasn't parsed from the line
    event_timestamp = timestamp if timestamp is not None else current_time

    # 3. Handle Unfinished/Resumed/Signal lines
    unfinished_match = UNFINISHED_RE.search(line)
    if unfinished_match:
        # Store the part before "<unfinished ...>"
        syscall_part = line[: unfinished_match.start()].strip()
        # Extract syscall name (rudimentary)
        syscall_name = syscall_part.split("(", 1)[0]
        unfinished_syscalls[pid] = syscall_name
        log.debug(f"Stored unfinished syscall for PID {pid}: {syscall_name}")
        return None  # Don't yield anything for unfinished lines

    resumed_match = RESUMED_RE.match(line)
    if resumed_match:
        syscall_name = resumed_match.group("syscall")
        if unfinished_syscalls.get(pid) == syscall_name:
            log.debug(f"Matched resumed syscall for PID {pid}: {syscall_name}")
            del unfinished_syscalls[pid]
            # Treat the rest of the line as a normal syscall line for parsing result
            line = resumed_match.group(2).strip()
        else:
            log.warning(
                f"Resumed syscall '{syscall_name}' for PID {pid} without matching unfinished call. Stored: {unfinished_syscalls.get(pid)}"
            )
            # Attempt to parse the rest anyway? Or discard? Discard for now.
            return None

    signal_match = SIGNAL_RE.match(line)
    if signal_match:
        # Signal lines don't represent syscall completion, ignore them for event generation
        log.debug(f"Ignoring signal line for PID {pid}: {line}")
        # If a syscall was unfinished, a signal might interrupt it without resumption
        if pid in unfinished_syscalls:
            log.debug(
                f"Clearing unfinished syscall for PID {pid} due to signal delivery."
            )
            del unfinished_syscalls[pid]
        return None

    # 4. Parse the core syscall structure
    syscall_match = SYSCALL_RE.match(line)
    if syscall_match:
        data = syscall_match.groupdict()
        syscall_name = data["syscall"]

        # Simple argument parsing
        args_list = _parse_args_simple(data.get("args", "") or "")

        # Handle potential None values from regex groups
        result_str = data.get("result_str")
        error_name = data.get("error_name")
        error_msg = data.get("error_msg")
        timing_str = data.get("timing")
        timing = float(timing_str) if timing_str else None

        # Clear unfinished state if this syscall matches the one stored
        if unfinished_syscalls.get(pid) == syscall_name:
            log.debug(
                f"Implicitly clearing unfinished syscall for PID {pid} ({syscall_name}) as a completed line was found."
            )
            del unfinished_syscalls[pid]

        return Syscall(
            pid=pid,
            syscall=syscall_name,
            args=args_list,
            result_str=result_str,
            error_name=error_name,
            error_msg=error_msg,
            timing=timing,
            timestamp=event_timestamp,
            raw_line=original_line,
        )
    else:
        # Check if it looks like a resumption line we failed to match earlier
        if "resumed" in line:
            log.debug(
                f"Ignoring potentially mismatched resume line for PID {pid}: {original_line}"
            )
        # Check if it's an exit status line
        elif line.startswith("+++ exited with") or line.startswith("+++ killed by"):
            log.debug(f"Ignoring exit status line for PID {pid}: {original_line}")
        else:
            log.warning(
                f"Failed to parse syscall line structure for PID {pid}: {original_line}"
            )
        return None


# --- Async Stream Parser ---
async def parse_strace_stream(
    lines: AsyncIterator[str],
    monitor: Monitor,  # Pass monitor for context if needed later
    stop_event: asyncio.Event,
    syscalls: list[str] | None = None,  # Optional: Filter specific syscalls
    attach_ids: list[int] | None = None,  # Optional: Initial PIDs for context
) -> AsyncIterator[Syscall]:
    """
    Asynchronously parses a stream of raw strace output lines into Syscall objects.
    """
    log.info("Starting strace stream parser...")
    unfinished_syscalls: dict[int, str] = {}  # Track unfinished syscalls per PID
    line_count = 0
    parsed_count = 0

    try:
        async for line in lines:
            line_count += 1
            if stop_event.is_set():
                log.info("Stop event detected, stopping strace stream parsing.")
                break

            current_time = time.time()  # Get time close to line processing
            parsed_event = _parse_strace_line(line, unfinished_syscalls, current_time)

            if parsed_event:
                # Optional filtering based on syscall name
                if syscalls is None or parsed_event.syscall in syscalls:
                    parsed_count += 1
                    yield parsed_event
            # Add a small sleep to prevent tight loop if input stream is very fast
            # or empty, allowing other tasks to run. Adjust as needed.
            await asyncio.sleep(0.001)

    except asyncio.CancelledError:
        log.info("Strace stream parsing task cancelled.")
    except Exception as e:
        log.exception(f"Error during strace stream parsing: {e}")
    finally:
        log.info(
            f"Exiting strace stream parser. Processed {line_count} lines, yielded {parsed_count} events."
        )
        # Log any remaining unfinished syscalls on exit
        if unfinished_syscalls:
            log.warning(
                f"Parser exiting with unfinished syscalls: {unfinished_syscalls}"
            )
