# Filename: src/lsoph/backend/lsof/parse.py
"""Parsing functions for lsof -F output."""

import logging
import re
from collections.abc import Iterator
from typing import Any

log = logging.getLogger(__name__)  # Use specific logger

# --- Regular Expressions ---
FD_TYPE_RE = re.compile(r"(\d+)([rwu])?")


# --- Parsing Logic ---
def _parse_fd(fd_str: str) -> tuple[int | None, str]:
    """Parse the FD column from lsof output (field 'f')."""
    # Handles common non-numeric FD types
    if fd_str in ("cwd", "rtd", "txt", "mem", "DEL", "unknown"):
        return None, fd_str
    # Attempt to parse numeric FD with optional mode
    match = FD_TYPE_RE.match(fd_str)
    if match:
        # Return int for FD, and mode ('r', 'w', 'u', or empty string)
        return int(match.group(1)), match.group(2) or ""
    # Log and return original string if unparsable
    log.debug(f"Unparsable FD string: {fd_str}")
    return None, fd_str


def _parse_lsof_f_output(
    lines: Iterator[str],
) -> Iterator[dict[str, Any]]:
    """
    Parses the output of `lsof -F pcftn`.

    Yields a dictionary for each file record found.
    """
    current_record: dict[str, Any] = {}
    current_pid: int | None = None
    current_command: str | None = None

    for line in lines:
        line = line.strip()
        if not line:
            continue  # Skip empty lines

        field_type = line[0]
        value = line[1:]

        if field_type == "p":
            # Start of a new process section identified by PID
            try:
                current_pid = int(value)
                current_command = None  # Reset command for the new PID
                current_record = {}  # Reset record fields for the new PID
                log.debug(f"Parsing records for PID: {current_pid}")
            except ValueError:
                log.warning(f"Could not parse PID from lsof line: {line}")
                current_pid = None  # Invalidate current PID context
                current_record = {}
        elif current_pid is None:
            # Skip lines if we haven't identified a valid PID yet
            # This might happen if lsof output starts unexpectedly
            log.debug(f"Skipping lsof line, no valid PID context: {line}")
            continue
        elif field_type == "c":
            # Command associated with the current PID
            current_command = value
        elif field_type == "f":
            # File descriptor field
            current_record["fd_str"] = value
            fd, mode = _parse_fd(value)
            current_record["fd"] = fd
            current_record["mode"] = mode
        elif field_type == "t":
            # Type of file (e.g., REG, DIR, CHR, FIFO, unix, IPv4, IPv6)
            current_record["type"] = value
        elif field_type == "n":
            # Name/path field, signifies the end of a file record for the current PID
            current_record["path"] = value
            # Assemble the complete record with PID and command context
            record_to_yield = {
                "pid": current_pid,
                "command": current_command,
                **current_record,  # Merge the accumulated fields (f, t, n)
            }
            yield record_to_yield
            # Reset record fields for the next file under the same PID
            # Keep current_pid and current_command context
            current_record = {}
        # Ignore other field types not specified in -F pcftn if they appear
