# Filename: src/lsoph/util/short_path.py
"""Utility function for shortening file paths. Accepts bytes, returns str."""

import logging
import os

log = logging.getLogger(__name__)

# Store CWD (as bytes) at import time. Let OSError propagate if this fails.
# Ensure it ends with a path separator (bytes).
try:
    # Get CWD as string first
    _cwd_str = os.getcwd()
    # Encode to bytes using filesystem encoding
    CWD_BYTES = os.fsencode(_cwd_str)
    # Ensure it ends with bytes separator
    _sep_bytes = os.sep.encode("ascii")  # os.sep is str, encode it
    if not CWD_BYTES.endswith(_sep_bytes):
        CWD_BYTES += _sep_bytes
    log.debug(f"lsoph CWD (bytes) stored as: {CWD_BYTES!r}")
except OSError as e:
    log.error(f"Could not determine current working directory at import time: {e}")
    CWD_BYTES = b""  # Fallback to empty bytes string if CWD fails


def _relative_path_bytes(path: bytes, cwd: bytes = CWD_BYTES) -> bytes:
    """
    If path (bytes) starts with cwd (bytes), return the relative path component (bytes),
    otherwise return the original path (bytes). Returns b"." if path is identical to cwd.
    Assumes cwd ends with path separator (bytes).
    """
    # Handle edge case where CWD failed to initialize
    if not cwd:
        return path

    # Check if path starts with the CWD (bytes comparison)
    if path.startswith(cwd):
        pos = len(cwd)
        # Return the part after CWD, or b"." if it was exactly CWD
        relative = path[pos:]
        return relative or b"."
    # Return original path if it doesn't start with CWD
    return path


def _truncate_directory(directory: str, max_dir_len: int) -> str:
    """Truncates the directory string in the middle if it exceeds max_dir_len."""
    # This function operates on strings (after decoding) - no changes needed here.
    if max_dir_len <= 0:
        return ""
    ellipsis = "..."
    if max_dir_len <= len(ellipsis):
        return ""
    if len(directory) <= max_dir_len:
        return directory

    dir_keep_total = max_dir_len - len(ellipsis)
    start_len = max(1, dir_keep_total // 2)
    end_len = max(1, dir_keep_total - start_len)

    if start_len + end_len > len(directory):
        start_len = len(directory) // 2
        end_len = len(directory) - start_len
        # Check if still enough space for ellipsis after recalculation
        if start_len + end_len + len(ellipsis) <= len(directory):
            return f"{directory[:start_len]}{ellipsis}{directory[-end_len:]}"
        else:  # Fallback if directory is extremely short relative to ellipsis
            return directory[:max_dir_len]

    start_part = directory[:start_len]
    end_part = directory[-end_len:]

    return f"{start_part}{ellipsis}{end_part}"


def short_path(
    path_bytes: bytes | os.PathLike, max_length: int, cwd_bytes: bytes = CWD_BYTES
) -> str:
    """
    Shortens a file path (bytes) to fit max_length, returning a string for display.
    1. Decodes the bytes path using fsdecode (surrogateescape).
    2. Tries to make the path relative to CWD (bytes).
    3. Prioritizes keeping the full filename visible.
    4. If filename alone is too long, truncates filename from the left ("...name").
    5. If path is still too long but filename fits, truncates directory in the middle ("dir...ory/name").

    Args:
        path_bytes: The file path as bytes or a path-like object convertible to bytes.
        max_length: The maximum allowed length for the output string.
        cwd_bytes: The current working directory (bytes) to make the path relative to.

    Returns:
        The shortened path string, decoded for display.
    """
    # Ensure input is bytes
    if isinstance(path_bytes, os.PathLike):
        path_bytes = os.fsencode(path_bytes)  # Encode path-like object
    elif not isinstance(path_bytes, bytes):
        # Handle unexpected input type gracefully
        log.warning(
            f"short_path received non-bytes/PathLike input: {type(path_bytes)}. Returning empty string."
        )
        return ""

    # Make path relative (bytes operation)
    relative_path_bytes = _relative_path_bytes(path_bytes, cwd_bytes)

    # --- DECODE to string for manipulation and display ---
    # Use surrogateescape to handle potential undecodable bytes gracefully
    try:
        path_str = os.fsdecode(relative_path_bytes)
    except Exception as e:
        log.error(f"Failed to decode path bytes {relative_path_bytes!r}: {e}")
        # Fallback: return a representation of the raw bytes if decode fails
        return f"<DECODE_ERROR:{relative_path_bytes!r}>"[:max_length]
    # ----------------------------------------------------

    ellipsis = "..."

    # --- Handle Edge Cases (on decoded string length) ---
    if len(path_str) <= max_length:
        return path_str  # Path already fits
    if max_length <= 0:
        return ""  # Cannot represent anything
    if max_length <= len(ellipsis):
        # Only space for ellipsis or less, show end of path string
        return path_str[-max_length:]

    # --- Split into directory and filename (string operations) ---
    directory, filename = os.path.split(path_str)

    # --- Case 1: Filename alone (with ellipsis) is too long ---
    if len(ellipsis) + len(filename) >= max_length:
        keep_chars = max_length - len(ellipsis)
        # Ensure keep_chars isn't negative if max_length is tiny
        keep_chars = max(0, keep_chars)
        return ellipsis + filename[-keep_chars:]

    # --- Case 2: Filename fits, but directory needs shortening ---
    len_sep_before_file = len(os.sep) if directory else 0
    max_dir_len = max_length - len(filename) - len_sep_before_file
    max_dir_len = max(0, max_dir_len)  # Ensure not negative

    # Truncate the directory string part if necessary
    truncated_dir = _truncate_directory(directory, max_dir_len)

    # Combine truncated directory (if any) and filename
    if not directory:
        return filename
    else:
        final_path = truncated_dir + os.sep + filename
        # Final check
        if len(final_path) > max_length:
            keep_chars = max(0, max_length - len(ellipsis))
            return ellipsis + filename[-keep_chars:]
        return final_path
