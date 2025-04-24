# Filename: src/lsoph/backend/strace/parse.py
"""Parsing logic for strace output. Operates on bytes lines using manual parsing."""

import asyncio
import logging
import os  # For os.fsdecode
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, List, Optional  # Added List

# Import TRACE_LEVEL_NUM for logging
from lsoph.log import TRACE_LEVEL_NUM
from lsoph.monitor import Monitor

# Import helpers here if needed by parsing logic itself, or keep in backend
from . import helpers

log = logging.getLogger(__name__)

# --- Constants ---
# Syscalls indicating process creation/management
PROCESS_SYSCALLS = ["clone", "fork", "vfork"]  # Keep as strings for comparison
# Syscalls indicating process termination
EXIT_SYSCALLS = ["exit", "exit_group"]  # Keep as strings for comparison
# Syscalls indicating potential resumption after signal
RESUME_SYSCALLS = ["rt_sigreturn", "sigreturn"]  # Keep as strings for comparison

# --- Regular Expressions (Simple ones for prefixes/suffixes) ---
PID_RE = re.compile(rb"^(?:\[pid\s+)?(\d+)\)?")  # bytes pattern
TIMESTAMP_RE = re.compile(rb"^\s*(\d+\.\d+)\s+")  # bytes pattern
UNFINISHED_RE = re.compile(rb"<unfinished \.\.\.>$")  # bytes pattern
RESUMED_RE = re.compile(
    rb"<\.\.\. (?P<syscall>[a-zA-Z0-9_]+) resumed> (.*)"
)  # bytes pattern
SIGNAL_RE = re.compile(rb"--- SIG(\w+) .* ---$")  # bytes pattern
# Regex to parse the result part (used for resumed lines and fallback)
RESULT_PART_RE = re.compile(
    rb"""
    .*?             # Allow anything before the result part (non-greedy)
    \s*=\s* # Equals sign
    (?P<result_str> # Result string (bytes)
        (?:-?\d+|0x[0-9a-fA-F]+|\?) # decimal, hex, or ?
    )
    # Optional error part
    (?:
        \s+ (?P<error_name>[A-Z][A-Z0-9_]+) \s* \( (?P<error_msg>.*?) \)
    )?
    # Optional timing part
    (?: \s+ <(?P<timing>\d+\.\d+)> )?
    \s* # Allow trailing whitespace
    $               # Anchor to end
    """,
    re.VERBOSE,
)


# --- Dataclass for Parsed Syscall ---
@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    pid: int
    syscall: str  # Syscall name is decoded to str
    # --- ARGS ARE NOW BYTES ---
    args: List[bytes] = field(default_factory=list)
    # -------------------------
    result_str: str | None = None  # Result string is decoded
    result_int: int | None = None
    child_pid: int | None = None
    error_name: str | None = None  # Error name is decoded
    error_msg: str | None = None  # Error message is decoded
    timing: float | None = None
    timestamp: float = field(default_factory=time.time)
    # --- RAW_LINE IS NOW BYTES ---
    raw_line: bytes = b""
    # ---------------------------

    @property
    def success(self) -> bool:
        """Determine if the syscall was successful (no error reported)."""
        if self.error_name:
            return False
        # Consider result_int < 0 as failure only if error_name is not set
        # (covers cases where strace doesn't explicitly print the error name)
        if self.result_int is not None and self.result_int < 0 and not self.error_name:
            return False
        return True  # Assume success otherwise (including result=None or ?)

    def __repr__(self) -> str:
        # Provide a more concise representation for logging
        err_part = f" ERR={self.error_name}" if self.error_name else ""
        child_part = f" CHILD={self.child_pid}" if self.child_pid else ""
        # Decode args for repr only, limit length
        args_repr_list = []
        for i, a in enumerate(self.args):
            if i >= 2:  # Show max 2 args in repr
                args_repr_list.append("...")
                break
            try:
                # Use fsdecode for potentially non-utf8 bytes in args
                args_repr_list.append(os.fsdecode(a))
            except Exception:
                args_repr_list.append(repr(a))  # Show raw bytes if decode fails
        args_repr = ", ".join(args_repr_list)

        return f"Syscall(pid={self.pid}, ts={self.timestamp:.3f}, call={self.syscall}({args_repr}), ret={self.result_str}{err_part}{child_part})"


# --- Parsing Functions ---


def _parse_args_bytes(args_bytes: bytes) -> List[bytes]:
    """
    Parses the raw bytes arguments string from strace.
    Handles basic quoted strings (b'"') and commas (b',') within bytes.
    Handles escaped quotes (b'\\"').
    """
    # Using the more robust quote/escape handling version
    args = []
    current_arg = bytearray()
    in_quotes = False
    escape_next = False
    # Add a dummy comma at the end to help flush the last argument
    args_bytes += b","

    i = 0
    n = len(args_bytes)
    while i < n:
        byte_val = args_bytes[i : i + 1]  # Get the current byte as bytes

        if escape_next:
            # If previous was escape, append current byte literally
            current_arg.extend(byte_val)
            escape_next = False
            i += 1
        elif byte_val == b"\\":
            # Found an escape character, mark it and append
            escape_next = True
            current_arg.extend(byte_val)  # Keep the backslash byte for now
            i += 1
        elif byte_val == b'"':
            # Toggle quote state, append the quote
            in_quotes = not in_quotes
            current_arg.extend(byte_val)
            i += 1
        elif byte_val == b"," and not in_quotes:
            # Argument finished (if not inside quotes)
            stripped_arg = bytes(current_arg).strip()  # Strip whitespace bytes
            if stripped_arg:  # Only add non-empty args
                args.append(stripped_arg)
            current_arg = bytearray()  # Reset for next arg
            i += 1
        else:
            # Regular byte, append it
            current_arg.extend(byte_val)
            i += 1

    # Return list of bytes arguments
    return args


def _parse_result_part(result_part_bytes: bytes) -> dict:
    """Parses the ' = result [error] [<timing>]' part of a line."""
    result_data = {
        "result_str": None,
        "error_name": None,
        "error_msg": None,
        "timing": None,
    }
    # Find the equals sign
    eq_pos = result_part_bytes.find(b"=")
    if eq_pos == -1:
        log.debug(f"Could not find '=' in result part: {result_part_bytes!r}")
        return result_data  # No result found

    # Extract potential result string (strip whitespace)
    potential_result = result_part_bytes[eq_pos + 1 :].lstrip()

    # Find the end of the numeric/hex result or '?'
    res_end_pos = 0
    current_byte = potential_result[0:1] if potential_result else b""
    if (
        current_byte == b"-"
        and len(potential_result) > 1
        and potential_result[1:2].isdigit()
    ):
        res_end_pos = 1  # Skip leading '-'
        while (
            res_end_pos < len(potential_result)
            and potential_result[res_end_pos : res_end_pos + 1].isdigit()
        ):
            res_end_pos += 1
    elif (
        current_byte == b"0"
        and len(potential_result) > 1
        and potential_result[1:2] in b"xX"
    ):
        res_end_pos = 2  # Skip leading '0x'
        while (
            res_end_pos < len(potential_result)
            and potential_result[res_end_pos : res_end_pos + 1]
            in b"0123456789abcdefABCDEF"
        ):
            res_end_pos += 1
    elif current_byte.isdigit():
        while (
            res_end_pos < len(potential_result)
            and potential_result[res_end_pos : res_end_pos + 1].isdigit()
        ):
            res_end_pos += 1
    elif current_byte == b"?":
        res_end_pos = 1

    if res_end_pos > 0:
        result_str_bytes = potential_result[:res_end_pos]
        result_data["result_str"] = result_str_bytes.decode("utf-8", "surrogateescape")
        remainder = potential_result[res_end_pos:].lstrip()
    else:
        log.debug(f"Could not parse numeric/hex/? result from: {potential_result!r}")
        remainder = potential_result  # Process remainder for error/timing

    # Look for error (e.g., " ENOENT (No such file...)")
    err_match = re.match(rb"\s*([A-Z][A-Z0-9_]+)\s*\((.*?)\)", remainder)
    if err_match:
        result_data["error_name"] = err_match.group(1).decode("ascii")
        result_data["error_msg"] = err_match.group(2).decode("utf-8", "surrogateescape")
        # Advance remainder past the error message
        remainder = remainder[err_match.end() :].lstrip()

    # Look for timing (e.g., " <0.000123>")
    time_match = re.search(rb"<(\d+\.\d+)>", remainder)
    if time_match:
        try:
            result_data["timing"] = float(time_match.group(1))
        except ValueError:
            pass  # Ignore float conversion errors

    return result_data


def _parse_strace_line(
    line_bytes: bytes,  # Accepts raw bytes line
    unfinished_syscalls: dict[int, str],  # Syscall name is still str
    current_time: float,
) -> Syscall | None:
    """
    Parses a single raw bytes line of strace output using manual parsing.
    Handles PID, timestamp, syscall, args (bytes), result, unfinished/resumed, signals.
    """
    original_line_bytes = line_bytes
    pid: int | None = None
    timestamp: float | None = None

    # 1. Extract PID
    pid_match = PID_RE.match(line_bytes)
    if pid_match:
        try:
            pid = int(pid_match.group(1))
        except ValueError:
            log.warning(f"Could not parse PID digits from: {pid_match.group(1)!r}")
            return None
        line_remainder_bytes = line_bytes[pid_match.end() :].lstrip()
    else:
        # Ignore signals or lines without PID
        if (
            not SIGNAL_RE.match(original_line_bytes)
            and not original_line_bytes.startswith(b"+++ exited")
            and not original_line_bytes.startswith(b"+++ killed")
        ):
            log.debug(f"Could not extract PID from line: {original_line_bytes!r}")
        return None

    # 2. Extract Timestamp
    ts_match = TIMESTAMP_RE.match(line_remainder_bytes)
    if ts_match:
        try:
            timestamp = float(ts_match.group(1))
        except ValueError:
            pass
        line_remainder_bytes = line_remainder_bytes[ts_match.end() :].lstrip()
    event_timestamp = timestamp if timestamp is not None else current_time

    # --- FIX: Reorder checks and ensure return ---

    # 3a. Handle Resumed lines
    resumed_match = RESUMED_RE.match(line_remainder_bytes)
    if resumed_match:
        try:
            syscall_name_str = resumed_match.group("syscall").decode("ascii")
            if unfinished_syscalls.get(pid) == syscall_name_str:
                del unfinished_syscalls[pid]
                remainder_after_resumed = resumed_match.group(2).strip()
                # --- Add try-except around result parsing ---
                try:
                    result_data = _parse_result_part(remainder_after_resumed)
                    result_int = helpers.parse_result_int(result_data["result_str"])

                    return Syscall(  # Return on success
                        pid=pid,
                        syscall=syscall_name_str,
                        args=[],  # No args on resumed line
                        result_str=result_data["result_str"],
                        result_int=result_int,
                        child_pid=None,
                        error_name=result_data["error_name"],
                        error_msg=result_data["error_msg"],
                        timing=result_data["timing"],
                        timestamp=event_timestamp,
                        raw_line=original_line_bytes,
                    )
                except (
                    Exception
                ) as e_resumed:  # Catch potential errors during result parsing
                    log.exception(
                        f"Error parsing result for resumed syscall {syscall_name_str} (PID {pid}): {e_resumed}. Remainder: {remainder_after_resumed!r}"
                    )
                    return None  # Return None if result parsing fails
                # --- End try-except ---
            else:
                log.warning(
                    f"Resumed syscall '{syscall_name_str}' for PID {pid} without matching unfinished call. Stored: {unfinished_syscalls.get(pid)}"
                )
                return None  # Ignore mismatched resumption
        except UnicodeDecodeError:
            log.warning(
                f"Could not decode resumed syscall name: {resumed_match.group('syscall')!r}"
            )
            return None  # Return None on decode error

    # 3b. Handle Unfinished lines
    unfinished_match = UNFINISHED_RE.search(line_remainder_bytes)
    if unfinished_match:
        syscall_part_bytes = line_remainder_bytes[: unfinished_match.start()].strip()
        open_paren_pos = syscall_part_bytes.find(b"(")
        if open_paren_pos != -1:
            syscall_name_bytes = syscall_part_bytes[:open_paren_pos]
            try:
                syscall_name_str = syscall_name_bytes.decode("ascii")
                unfinished_syscalls[pid] = syscall_name_str
            except UnicodeDecodeError:
                log.warning(
                    f"Could not decode unfinished syscall name: {syscall_name_bytes!r}"
                )
        else:
            log.warning(
                f"Could not find '(' in unfinished line part: {syscall_part_bytes!r}"
            )
        return None  # Don't yield unfinished events

    # 3c. Handle Signal lines
    signal_match = SIGNAL_RE.match(line_remainder_bytes)
    if signal_match:
        if pid in unfinished_syscalls:
            del unfinished_syscalls[pid]  # Clear any pending unfinished on signal
        return None  # Ignore signal lines

    # --- END FIX ---

    # 4. If none of the above, attempt to parse as a regular syscall line
    syscall_name_str: str | None = None
    args_bytes_list: List[bytes] = []
    result_data = {}

    try:
        # Use the remainder after PID/Timestamp stripping
        open_paren_pos = line_remainder_bytes.find(b"(")
        if open_paren_pos != -1:
            syscall_name_bytes = line_remainder_bytes[:open_paren_pos]
            syscall_name_str = syscall_name_bytes.decode("ascii")

            # Find matching closing parenthesis in the remainder
            close_paren_pos = -1
            paren_level = 0
            in_str_quote = False
            esc = False
            # Start search *after* the opening parenthesis found
            for i in range(open_paren_pos + 1, len(line_remainder_bytes)):
                char = line_remainder_bytes[i : i + 1]
                if esc:
                    esc = False
                elif char == b"\\":
                    esc = True
                elif char == b'"':
                    in_str_quote = not in_str_quote
                elif char == b"(" and not in_str_quote:
                    paren_level += 1
                elif char == b")" and not in_str_quote:
                    if paren_level == 0:
                        close_paren_pos = i
                        break
                    paren_level -= 1

            if close_paren_pos != -1:
                # Extract args from between the parentheses
                args_raw_bytes = line_remainder_bytes[
                    open_paren_pos + 1 : close_paren_pos
                ]
                args_bytes_list = _parse_args_bytes(args_raw_bytes)

                # Look for result part *after* the closing parenthesis
                result_part_bytes = line_remainder_bytes[close_paren_pos + 1 :]
                result_data = _parse_result_part(result_part_bytes)
            else:
                # Could be a syscall with no args and no result (e.g., getpid())
                # Or could be malformed. Check if there's an '=' after name.
                if b"=" not in line_remainder_bytes[open_paren_pos:]:
                    log.debug(
                        f"Syscall line with no apparent args or result: {original_line_bytes!r}"
                    )
                    # Assume no args, no result for now
                    args_bytes_list = []
                    result_data = {
                        "result_str": None,
                        "error_name": None,
                        "error_msg": None,
                        "timing": None,
                    }
                else:
                    # Found '=' but no closing ')' - likely malformed
                    log.debug(
                        f"Could not find matching ')' for syscall line: {original_line_bytes!r}"
                    )
                    return None  # Malformed line
        else:
            # No opening parenthesis found - likely not a standard syscall line
            log.debug(f"Could not find '(' for syscall line: {original_line_bytes!r}")
            return None  # Malformed line

    except UnicodeDecodeError:
        log.warning(
            f"Could not decode syscall name: {line_remainder_bytes[:open_paren_pos]!r}"
        )
        return None
    except Exception as e:
        log.exception(
            f"Error during manual parsing of line {original_line_bytes!r}: {e}"
        )
        return None

    # Construct the Syscall object if syscall name was found
    if syscall_name_str:
        result_int = helpers.parse_result_int(result_data["result_str"])
        child_pid = None
        if (
            syscall_name_str in PROCESS_SYSCALLS
            and not result_data["error_name"]
            and result_int is not None
            and result_int >= 0
        ):
            child_pid = result_int

        # Clear unfinished state if this syscall matches the one stored
        if unfinished_syscalls.get(pid) == syscall_name_str:
            del unfinished_syscalls[pid]

        return Syscall(
            pid=pid,
            syscall=syscall_name_str,
            args=args_bytes_list,
            result_str=result_data["result_str"],
            result_int=result_int,
            child_pid=child_pid,
            error_name=result_data["error_name"],
            error_msg=result_data["error_msg"],
            timing=result_data["timing"],
            timestamp=event_timestamp,
            raw_line=original_line_bytes,
        )
    else:
        # Should not happen if parsing logic is correct, but log just in case
        log.debug(
            f"Manual parsing failed to extract syscall name from: {original_line_bytes!r}"
        )
        return None


# --- Async Stream Parser ---
async def parse_strace_stream(
    lines_bytes: AsyncIterator[bytes],  # Accepts bytes lines
    monitor: Monitor,
    stop_event: asyncio.Event,
    syscalls: list[str] | None = None,  # List of syscall names (strings)
    attach_ids: list[int] | None = None,
) -> AsyncIterator[Syscall]:
    """
    Asynchronously parses a stream of raw strace output bytes lines into Syscall objects.
    """
    unfinished_syscalls: dict[int, str] = {}
    line_count = 0
    parsed_count = 0
    # --- Check if TRACE level is enabled once at the start ---
    trace_enabled = log.isEnabledFor(TRACE_LEVEL_NUM)
    # -------------------------------------------------------
    try:
        async for line_b in lines_bytes:  # Iterate over bytes lines
            line_count += 1
            if stop_event.is_set():
                break

            # --- Log raw line if TRACE is enabled ---
            if trace_enabled:
                log.log(TRACE_LEVEL_NUM, f"Raw strace line: {line_b!r}")
            # ----------------------------------------

            current_time = time.time()
            # Pass raw bytes line to parser
            parsed_event = _parse_strace_line(line_b, unfinished_syscalls, current_time)

            if parsed_event:
                # Compare decoded syscall name with the filter list
                if syscalls is None or parsed_event.syscall in syscalls:
                    # --- ADDED: Debug log for parsed event ---
                    log.debug(f"Parsed event: {parsed_event!r}")
                    # -----------------------------------------
                    parsed_count += 1
                    yield parsed_event
            # Prevent tight loop on fast/empty streams
            await asyncio.sleep(0.001)

    except asyncio.CancelledError:
        log.info("Strace stream parsing task cancelled.")
    finally:
        log.info(
            f"Exiting strace stream parser. Processed {line_count} lines, yielded {parsed_count} events."
        )
        if unfinished_syscalls:
            log.warning(
                f"Parser exiting with unfinished syscalls: {unfinished_syscalls}"
            )
