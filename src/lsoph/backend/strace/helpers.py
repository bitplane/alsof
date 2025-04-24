# Filename: src/lsoph/backend/strace/helpers.py
"""Helper functions specific to the strace backend."""

# Removed codecs import
import logging
import os
import re
from typing import Optional

from lsoph.monitor import Monitor

log = logging.getLogger(__name__)

# Regex to find file descriptors like AT_FDCWD or numeric FDs
DIRFD_RE = re.compile(r"^(?:AT_FDCWD|-100)$")
# REMOVED OCTAL_ESCAPE_RE and _decode_octal_match


def clean_path_arg(path_arg: Optional[str]) -> Optional[str]:
    """
    Cleans a path argument string obtained from strace output.
    Removes surrounding quotes and handles "(null)".
    Assumes correct decoding happened upstream.
    """
    if path_arg is None:
        return None

    path = path_arg.strip()

    # Handle cases where strace might output "(null)" for a null pointer path
    # This is a specific strace artifact we might need to handle.
    if path == "(null)":
        log.warning("Encountered '(null)' path argument, treating as None.")
        return None

    # Remove surrounding quotes if present
    # This is common in strace output for paths with spaces or special chars.
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        path = path[1:-1]

    # --- REMOVED ALL ESCAPE DECODING LOGIC ---
    # Trust that the initial decode("utf-8") in the reader handled bytes correctly.
    # If non-UTF8 bytes were present, that decode should have failed.
    # If strace uses escapes *instead* of raw bytes (less likely without -x flags),
    # those escapes will remain literally in the string (e.g., "\\n").

    # Final check for empty string after processing
    if not path:
        return None

    return path


def resolve_path(
    pid: int,
    path_arg: Optional[str],
    cwd_map: dict[int, str],
    monitor: Monitor,
    dirfd: Optional[int] = None,
) -> Optional[str]:
    """
    Resolves a path argument relative to CWD or dirfd.

    Args:
        pid: Process ID.
        path_arg: The raw path argument (potentially relative).
        cwd_map: Dictionary mapping PIDs to their current working directories.
        monitor: The Monitor instance (used for resolving FD paths).
        dirfd: Optional file descriptor for directory (used by *at syscalls).

    Returns:
        The absolute path as a string, or None if resolution fails.
    """
    if not path_arg:
        return None

    # If dirfd is provided and valid (not AT_FDCWD), resolve relative to its path
    if dirfd is not None and dirfd >= 0:
        base_path = monitor.get_path(pid, dirfd)
        # Check if it's actually a directory path we know
        # Allow potential errors during os.path operations to propagate
        if base_path and os.path.isdir(base_path):
            # Path arg is relative to the directory represented by dirfd
            abs_path = os.path.normpath(os.path.join(base_path, path_arg))
            return abs_path
        else:
            log.warning(
                f"Cannot resolve path relative to dirfd {dirfd} for PID {pid}: FD path unknown or not a directory ('{base_path}')."
            )
            return None

    # If path is already absolute, return it directly
    if os.path.isabs(path_arg):
        return os.path.normpath(path_arg)

    # If path is relative and no valid dirfd was used, resolve using PID's CWD
    cwd = cwd_map.get(pid)
    if cwd:
        # Allow potential errors during os.path operations to propagate
        abs_path = os.path.normpath(os.path.join(cwd, path_arg))
        return abs_path
    else:
        # Cannot resolve relative path without CWD
        log.warning(
            f"Cannot resolve relative path '{path_arg}' for PID {pid}: CWD unknown."
        )
        return None


def parse_dirfd(dirfd_arg: Optional[str]) -> Optional[int]:
    """Parses the dirfd argument (e.g., "AT_FDCWD", "3") into an integer or None."""
    if dirfd_arg is None:
        return None
    if DIRFD_RE.match(dirfd_arg):
        return None  # Represents CWD, handle as if no dirfd was passed
    try:
        return int(dirfd_arg)
    except ValueError:
        # log.warning(f"Could not parse dirfd argument: '{dirfd_arg}'") # Reduced logging
        return None


def parse_result_int(result_str: Optional[str]) -> Optional[int]:
    """Parses the result string into an integer, handling hex and decimal."""
    if result_str is None or result_str == "?":
        return None
    try:
        if result_str.startswith("0x"):
            return int(result_str, 16)
        else:
            return int(result_str)
    except ValueError:
        # log.warning(f"Could not parse result string as integer: '{result_str}'") # Reduced logging
        return None
