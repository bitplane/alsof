# Filename: src/lsoph/backend/strace/parse.py
"""
Strace output parser using the pyparsing library.
Parses decoded strace lines (UTF-8 with surrogateescape).
Yields Syscall objects with parsed arguments (int/str). Handles missing PIDs on initial process lines.
"""

import asyncio
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from typing import Any, Dict, List, Optional  # Use Dict, List, Optional from typing

# --- Import pyparsing (assume available) ---
import pyparsing as pp
from pyparsing import pyparsing_common as ppc

from lsoph.log import TRACE_LEVEL_NUM
from lsoph.monitor import Monitor

# Import helpers for result parsing
from . import helpers

# Import the line parser definition
from .parser_defs import parse_line, resumed_suffix_parser  # Import parser

# Import the Syscall dataclass (args are List[Any] for this parser)
from .syscall import EXIT_SYSCALLS, PROCESS_SYSCALLS, RESUME_SYSCALLS, Syscall

# -------------------------------------------


log = logging.getLogger(__name__)


# --- State for Continuations ---
unfinished_calls: dict[int, dict[str, Any]] = {}

# --- Parse Actions / Result Processing ---


def _parse_result_from_suffix(suffix_str: str) -> dict:
    """Parses result, error, timing from the suffix of a resumed line using pyparsing."""
    result_data = {
        "result_val": None,  # Changed key to match main parser
        "error_name": None,
        "error_msg": None,
        "timing": None,
    }
    try:
        parsed_suffix = resumed_suffix_parser.parseString(suffix_str, parseAll=True)
        result_data["result_val"] = parsed_suffix.result_val
        result_data["error_name"] = (
            parsed_suffix.error_part[0] if "error_part" in parsed_suffix else None
        )
        result_data["error_msg"] = (
            parsed_suffix.error_part[1] if "error_part" in parsed_suffix else None
        )  # Access nested error message
        result_data["timing"] = (
            parsed_suffix.timing_part[0] if "timing_part" in parsed_suffix else None
        )
    except pp.ParseException as pe_suffix:
        log.warning(
            f"Could not parse resumed suffix with pyparsing: {pe_suffix} - Suffix: {suffix_str!r}"
        )
    except Exception as e:
        log.exception(f"Error parsing resumed suffix '{suffix_str!r}': {e}")
    return result_data


# --- FIX: Correct _build_syscall_object ---
def _build_syscall_object(
    pid: int,
    syscall_name_str: str,
    # args_results: Optional[pp.ParseResults], # This holds the result of param_list
    args_list: List[Any],  # Pass the extracted list directly
    result_data: dict,
    timestamp: float,
    raw_line_bytes: bytes,
) -> Syscall:
    """Helper to create Syscall object, parsing result and child PID."""

    # Args list is already extracted with correct types
    args_parsed_list = args_list

    result_val = result_data.get("result_val")  # Already parsed type (int or '?')
    error_name = result_data.get("error_name")
    error_msg = result_data.get("error_msg")
    timing = result_data.get("timing")

    # Determine result_int and result_str based on parsed result_val
    result_int: Optional[int] = None
    result_str: Optional[str] = None
    if isinstance(result_val, int):
        result_int = result_val
        result_str = str(result_val)  # Convert int back to str for result_str
    elif result_val == "?":
        result_str = "?"
    # Handle potential None case, though parser should return int or '?'
    elif result_val is not None:
        result_str = str(result_val)

    child_pid = None
    if (
        syscall_name_str in PROCESS_SYSCALLS
        and not error_name
        and result_int is not None  # Check result_int
        and result_int >= 0
    ):
        child_pid = result_int

    return Syscall(
        pid=pid,
        syscall=syscall_name_str,
        args=args_parsed_list,  # Store list of parsed values (int/str)
        result_str=result_str,  # Store string representation
        result_int=result_int,  # Store integer representation if applicable
        child_pid=child_pid,
        error_name=error_name,
        error_msg=error_msg,
        timing=timing,
        timestamp=timestamp,
        raw_line=raw_line_bytes,  # Store original bytes
    )


# --- END FIX ---

# --- Main Parsing Function ---


async def parse_strace_stream_pyparsing(
    lines_bytes: AsyncIterator[bytes],  # Accepts bytes lines
    monitor: Monitor,  # Keep monitor arg for signature consistency
    stop_event: asyncio.Event,
    syscalls: list[str] | None = None,  # Keep syscalls arg for signature consistency
    attach_ids: list[int] | None = None,  # Pass initial PIDs if attaching
) -> AsyncIterator[Syscall]:  # Keep return type hint for consistency
    """
    Asynchronously parses a stream of raw strace output bytes lines into Syscall objects
    using pyparsing. Decodes lines before parsing. Handles missing PIDs.
    """

    line_count = 0
    parsed_count = 0
    trace_enabled = log.isEnabledFor(TRACE_LEVEL_NUM)
    # --- Track last known PID for lines potentially missing it ---
    current_pid: int | None = None
    # If attaching to a single known PID initially, use that as default
    if attach_ids and len(attach_ids) == 1:
        current_pid = attach_ids[0]
        log.debug(f"Setting initial PID context to {current_pid} (attach mode)")
    # ----------------------------------------------------------
    try:
        async for line_b in lines_bytes:
            line_count += 1
            if stop_event.is_set():
                break

            if trace_enabled:
                log.log(TRACE_LEVEL_NUM, f"Raw strace line: {line_b!r}")

            # Decode line using surrogateescape
            try:
                line_str = line_b.decode("utf-8", "surrogateescape")
            except Exception as decode_err:
                log.error(
                    f"Failed to decode strace line: {decode_err}. Bytes: {line_b!r}"
                )
                continue  # Skip this line

            event_timestamp = time.time()  # Use current time as timestamp

            try:
                # --- Try parsing as a complete syscall line first ---
                parsed = parse_line(line_str)  # Use the stricter parser

                # --- Determine PID ---
                pid_from_line: int | None = parsed.get("pid")  # Optional PID
                if pid_from_line is not None:
                    pid = pid_from_line
                    current_pid = pid  # Remember the last PID we saw explicitly
                elif current_pid is not None:
                    # If PID is missing, use the last known PID
                    log.debug(
                        f"Line missing PID, using last known PID: {current_pid}. Line: {line_str!r}"
                    )
                    pid = current_pid
                else:
                    # PID missing and no previous PID known (e.g., first line)
                    log.warning(
                        f"Line missing PID and no previous PID known. Cannot process line: {line_str!r}"
                    )
                    continue  # Skip line if PID cannot be determined

                # --- Extract data from the 'syscall_complete' group ---
                syscall_data = parsed.syscall_complete
                syscall_name_str = syscall_data.syscall
                result_val = syscall_data.result_val  # Already parsed type

                # Extract error and timing if present
                result_data = {
                    "result_val": result_val,
                    "error_name": (
                        syscall_data.error_part[0]
                        if "error_part" in syscall_data
                        else None
                    ),
                    "error_msg": (
                        syscall_data.error_part[1]
                        if "error_part" in syscall_data
                        else None
                    ),
                    "timing": (
                        syscall_data.timing_part[0]
                        if "timing_part" in syscall_data
                        else None
                    ),
                }

                # Extract arguments (already parsed types)
                args_parsed_list = []
                if "args" in syscall_data and syscall_data.args:
                    for arg_group in syscall_data.args:
                        if isinstance(arg_group, pp.ParseResults):
                            if len(arg_group) == 2:  # key=value pair
                                args_parsed_list.append(arg_group[1])
                            elif len(arg_group) == 1:  # Standalone value
                                args_parsed_list.append(arg_group[0])
                        else:  # Should not happen
                            args_parsed_list.append(str(arg_group))  # Fallback

                syscall_obj = _build_syscall_object(
                    pid,
                    syscall_name_str,
                    args_parsed_list,  # Pass the extracted list
                    result_data,
                    event_timestamp,
                    line_b,
                )
                log.debug(f"Parsed complete event: {syscall_obj!r}")  # Use repr

            except pp.ParseException:
                # --- If it's not a complete line, check for unfinished/resumed ---
                # This part needs refinement based on how unfinished/resumed lines
                # should be handled. The current `parse_line` won't match them.
                # For now, just log that it wasn't a complete syscall line.
                log.debug(f"Line did not parse as complete syscall: {line_str!r}")
                syscall_obj = None  # Explicitly set to None if parse failed

                # --- Placeholder for potential future unfinished/resumed handling ---
                # You would need separate pyparsing expressions for these line types
                # and logic here to match them if `parse_line` fails.
                # Example (conceptual):
                # try:
                #     parsed_unfinished = unfinished_line_parser.parseString(line_str, parseAll=True)
                #     # ... store unfinished state ...
                # except pp.ParseException:
                #     try:
                #         parsed_resumed = resumed_line_parser.parseString(line_str, parseAll=True)
                #         # ... combine with stored state and build syscall_obj ...
                #     except pp.ParseException:
                #          # ... handle signal/exit or log as unparseable ...
                #          log.debug(f"Line is not unfinished or resumed: {line_str!r}")
                # --------------------------------------------------------------------

            except Exception as e:
                log.exception(
                    f"Error processing parsed pyparsing result for line {line_str!r}: {e}"
                )
                syscall_obj = None

            # Yield the successfully parsed object if it matches filter
            if syscall_obj and (syscalls is None or syscall_obj.syscall in syscalls):
                parsed_count += 1
                yield syscall_obj

            await asyncio.sleep(0)  # Yield control more frequently

    except asyncio.CancelledError:
        log.info("Strace stream parsing task cancelled.")
    finally:
        log.info(
            f"Exiting pyparsing strace stream parser. Processed {line_count} lines, yielded {parsed_count} events."
        )
        if unfinished_calls:
            log.warning(f"Parser exiting with unfinished calls: {unfinished_calls}")

    # Ensure it's still an async generator type even if it yields nothing
    if False:
        yield None  # Adjusted to yield None to satisfy type hint if needed
