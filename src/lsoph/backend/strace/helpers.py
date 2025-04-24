# Filename: src/lsoph/backend/strace/helpers.py
"""General helper functions for the strace backend."""

import logging
import os
from typing import Any

# Import Monitor only for type hint if needed by resolve_path
from lsoph.monitor import Monitor

log = logging.getLogger(__name__)

# --- Parsing & Path Helpers ---


def parse_result_int(result_str: str) -> int | None:
    """Safely parses an integer result string from strace."""
    if not result_str or result_str == "?":
        return None
    try:
        return int(result_str, 0)  # Handles hex (0x...) and decimal
    except ValueError:
        log.warning(f"Could not parse integer result: '{result_str}'")
        return None


def clean_path_arg(path_arg: Any) -> str | None:
    """Cleans and decodes path arguments from strace, handling quotes and escapes."""
    if not isinstance(path_arg, str) or not path_arg:
        return None

    path = path_arg
    # Handle hex-encoded strings first (common for non-ASCII)
    # Check for \x specifically, as simple escapes like \n are handled later
    if path.startswith('"') and path.endswith('"') and "\\x" in path:
        path = path[1:-1]  # Remove quotes
        try:
            # Decode using unicode_escape, then handle potential surrogates
            # Preserve backslashes for unicode_escape, then encode to bytes
            # surrogateescape allows representing undecodable bytes
            decoded_bytes = (
                path.encode(
                    "latin-1", "backslashreplace"
                )  # Keep \x etc. as literal bytes
                .decode("unicode_escape")  # Decode \xNN, \uNNNN etc.
                .encode(
                    "utf-8", "surrogateescape"
                )  # Encode to UTF-8 allowing surrogates
            )
            # Decode back to string using surrogateescape to handle potential errors
            path = decoded_bytes.decode("utf-8", "surrogateescape")
        except Exception as e:
            log.warning(f"Failed hex/escape decode '{path_arg}': {e}")
            # Return the original quoted string if decoding fails badly
            return path_arg  # Keep original quotes
    # Handle simple quoted strings with standard escapes (like \n, \t, etc.)
    elif path.startswith('"') and path.endswith('"'):
        path = path[1:-1]  # Remove quotes
        try:
            # Use standard string escape decoding
            path = path.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception as e:
            log.warning(f"Failed simple escape decode '{path_arg}': {e}")
            return path_arg  # Return original quoted string on error

    # If it wasn't quoted or decoding failed, return the original (or partially decoded) path
    return path


def parse_dirfd(
    dirfd_arg: str | None,
) -> int | str | None:
    """Parses the dirfd argument, handling AT_FDCWD."""
    if dirfd_arg is None:
        return None
    # Check for AT_FDCWD case-insensitively
    if isinstance(dirfd_arg, str) and dirfd_arg.strip().upper() == "AT_FDCWD":
        return "AT_FDCWD"
    try:
        # Handle potential base prefixes like 0x
        return int(str(dirfd_arg), 0)
    except (ValueError, TypeError):
        log.warning(f"Could not parse dirfd: '{dirfd_arg}'")
        return None


def resolve_path(
    pid: int,
    path: str | None,
    cwd_map: dict[int, str],
    monitor: Monitor,  # Monitor needed here to lookup dirfd paths
    dirfd: int | str | None = None,
) -> str | None:
    """Resolves a path argument relative to CWD or dirfd if necessary."""
    if path is None:
        return None

    # Don't resolve special paths like sockets "<...>" or abstract namespaces "@..."
    if (path.startswith("<") and path.endswith(">")) or path.startswith("@"):
        return path

    base_dir: str | None = None

    # Determine base directory based on dirfd
    if dirfd is not None:
        if dirfd == "AT_FDCWD":
            base_dir = cwd_map.get(pid)
            if base_dir is None:
                log.warning(f"AT_FDCWD used, but CWD for PID {pid} is unknown.")
                # Fallback: treat path as relative to potentially unknown CWD
                # or absolute if it starts with '/'
        elif isinstance(dirfd, int) and dirfd >= 0:
            # Get the path associated with the directory file descriptor
            base_dir = monitor.get_path(pid, dirfd)
            if not base_dir:
                log.warning(
                    f"dirfd={dirfd} used, but path for this FD in PID {pid} is unknown."
                )
                # Cannot resolve relative path reliably, return original path
                # If the path is absolute, it will be handled below anyway.
                # If relative, returning it is the best we can do.
                # Let's allow absolute paths to still work below
        else:
            # Unhandled dirfd type (should not happen with _parse_dirfd)
            log.warning(f"Unhandled dirfd value: {dirfd!r} for PID {pid}")
            # Allow absolute paths to still work below

    # Resolve the path
    if os.path.isabs(path):
        # Path is absolute, normalize it
        try:
            return os.path.normpath(path)
        except ValueError as e:  # Catch errors during normpath
            log.warning(f"Error normalizing absolute path '{path}': {e}")
            return path  # Return original on error
    else:
        # Path is relative
        if base_dir is None:
            # If dirfd wasn't specified or was AT_FDCWD with unknown CWD, use PID's CWD
            base_dir = cwd_map.get(pid)

        if base_dir:
            try:
                # Join relative path with the determined base directory
                return os.path.normpath(os.path.join(base_dir, path))
            except ValueError as e:  # Catch errors during join/normpath
                log.warning(
                    f"Error joining path '{path}' with base '{base_dir}' for PID {pid}: {e}"
                )
                return path  # Return original relative path on error
        else:
            # Cannot resolve relative path if base_dir is unknown
            log.warning(
                f"Cannot resolve relative path '{path}' for PID {pid}: CWD/base_dir unknown."
            )
            return path  # Return original relative path
