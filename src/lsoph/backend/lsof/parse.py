# Filename: src/lsoph/backend/lsof/parse.py
"""Parsing functions for lsof -F output. Accepts bytes lines."""

import logging
import re
from collections.abc import Iterator
from typing import Any

log = logging.getLogger(__name__)  # Use specific logger

# --- Regular Expressions (operate on strings after initial decode) ---
FD_TYPE_RE = re.compile(r"(\d+)([rwu])?")


# --- Parsing Logic ---
def _parse_fd(fd_str: str) -> tuple[int | None, str]:
    """Parse the FD column string from lsof output (field 'f')."""
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
    lines_bytes: Iterator[bytes],  # Accepts iterator of bytes
) -> Iterator[dict[str, Any]]:  # Path value will be bytes
    """
    Parses the bytes output of `lsof -F pcftn`.

    Yields a dictionary for each file record found, with path as bytes.
    """
    current_record: dict[str, Any] = {}
    current_pid: int | None = None
    current_command: str | None = None  # Command is still string

    for line_b in lines_bytes:
        if not line_b:
            continue  # Skip empty lines

        # First byte is the field type
        field_type_byte = line_b[0:1]
        # Value is the rest of the bytes
        value_bytes = line_b[1:]

        # Decode value bytes only when needed for non-path fields
        # Use surrogateescape to handle potential encoding errors gracefully
        # Default to empty string if decoding fails unexpectedly
        try:
            value_str = value_bytes.decode("utf-8", "surrogateescape")
        except Exception:
            log.warning(f"Failed to decode lsof value bytes: {value_bytes!r}")
            value_str = ""  # Fallback

        if field_type_byte == b"p":
            # Start of a new process section identified by PID
            try:
                current_pid = int(value_str)
                current_command = None  # Reset command for the new PID
                current_record = {}  # Reset record fields for the new PID
                log.debug(f"Parsing records for PID: {current_pid}")
            except ValueError:
                log.warning(f"Could not parse PID from lsof line: {line_b!r}")
                current_pid = None  # Invalidate current PID context
                current_record = {}
        elif current_pid is None:
            # Skip lines if we haven't identified a valid PID yet
            # This might happen if lsof output starts unexpectedly
            log.debug(f"Skipping lsof line, no valid PID context: {line_b!r}")
            continue
        elif field_type_byte == b"c":
            # Command associated with the current PID (store as string)
            current_command = value_str
        elif field_type_byte == b"f":
            # File descriptor field (parse from string)
            current_record["fd_str"] = value_str
            fd, mode = _parse_fd(value_str)
            current_record["fd"] = fd
            current_record["mode"] = mode
        elif field_type_byte == b"t":
            # Type of file (e.g., REG, DIR, CHR, FIFO, unix, IPv4, IPv6) (store as string)
            current_record["type"] = value_str
        elif field_type_byte == b"n":
            # Name/path field, signifies the end of a file record for the current PID
            # --- STORE PATH AS BYTES ---
            current_record["path"] = value_bytes
            # ---------------------------
            # Assemble the complete record with PID and command context
            record_to_yield = {
                "pid": current_pid,
                "command": current_command,  # String
                **current_record,  # Merge the accumulated fields (f, t, n)
            }
            yield record_to_yield
            # Reset record fields for the next file under the same PID
            # Keep current_pid and current_command context
            current_record = {}
        # Ignore other field types not specified in -F pcftn if they appear
