# Filename: src/lsoph/util/short_path.py
"""Utility function for shortening file paths."""

import logging
import os

log = logging.getLogger(__name__)

# Store CWD at import time. Let OSError propagate if this fails.
# Ensure it ends with a separator for reliable startswith checks.
try:
    CWD = os.getcwd()
    if not CWD.endswith(os.sep):
        CWD += os.sep
    log.debug(f"lsoph CWD stored as: {CWD}")  # Keep this initial log
except OSError as e:
    log.error(f"Could not determine current working directory at import time: {e}")
    CWD = ""  # Fallback to empty string if CWD fails


def _relative_path(path: str, cwd: str = CWD) -> str:
    """
    If path starts with cwd, return the relative path component,
    otherwise return the original path. Returns "." if path is identical to cwd.
    Assumes cwd ends with path separator.
    """
    # Handle edge case where CWD failed to initialize
    if not cwd:
        return path

    # Check if path starts with the CWD
    if path.startswith(cwd):
        pos = len(cwd)
        # Return the part after CWD, or "." if it was exactly CWD
        relative = path[pos:]
        return relative or "."
    # Return original path if it doesn't start with CWD
    return path


def _truncate_directory(directory: str, max_dir_len: int) -> str:
    """Truncates the directory string in the middle if it exceeds max_dir_len."""
    # Handle edge cases for max_dir_len
    if max_dir_len <= 0:
        return ""
    ellipsis = "..."
    if max_dir_len <= len(ellipsis):
        # Not enough space even for ellipsis, return empty or part of ellipsis?
        # Returning empty seems safer.
        return ""
    if len(directory) <= max_dir_len:
        return directory  # No truncation needed

    # Calculate lengths for start and end parts
    dir_keep_total = max_dir_len - len(ellipsis)
    # Ensure at least one character at the start and end if possible
    start_len = max(1, dir_keep_total // 2)
    end_len = max(1, dir_keep_total - start_len)

    # Adjust lengths if directory is very short
    if start_len + end_len > len(directory):
        # This case shouldn't be reached due to initial length check, but handle defensively
        start_len = len(directory) // 2
        end_len = len(directory) - start_len
        return f"{directory[:start_len]}{ellipsis}{directory[-end_len:]}"

    # Perform truncation
    start_part = directory[:start_len]
    end_part = directory[-end_len:]  # Slice from the end

    return f"{start_part}{ellipsis}{end_part}"


def short_path(path: str | os.PathLike, max_length: int, cwd: str = CWD) -> str:
    """
    Shortens a file path string to fit max_length:
    1. Tries to make path relative to CWD.
    2. Prioritizes keeping the full filename visible.
    3. If filename alone is too long, truncates filename from the left ("...name").
    4. If path is still too long but filename fits, truncates directory in the middle ("dir...ory/name").

    Args:
        path: The file path string or path-like object.
        max_length: The maximum allowed length for the output string.
        cwd: The current working directory to make the path relative to.

    Returns:
        The shortened path string.
    """
    # Convert path-like object to string and make relative
    path_str = _relative_path(str(path), cwd)
    ellipsis = "..."

    # --- Handle Edge Cases ---
    if len(path_str) <= max_length:
        return path_str  # Path already fits
    if max_length <= 0:
        return ""  # Cannot represent anything
    if max_length <= len(ellipsis):
        # Only space for ellipsis or less, show end of path
        return path_str[-max_length:]

    # --- Split into directory and filename ---
    directory, filename = os.path.split(path_str)

    # --- Case 1: Filename alone (with ellipsis) is too long ---
    # Check if just the filename + ellipsis exceeds the max length
    if len(ellipsis) + len(filename) >= max_length:
        # Keep only the end of the filename that fits
        keep_chars = max_length - len(ellipsis)
        return ellipsis + filename[-keep_chars:]

    # --- Case 2: Filename fits, but directory needs shortening ---
    # Calculate maximum length allowed for the directory part
    len_sep_before_file = (
        len(os.sep) if directory else 0
    )  # Add 1 for separator if dir exists
    max_dir_len = max_length - len(filename) - len_sep_before_file

    # Truncate the directory part if necessary
    truncated_dir = _truncate_directory(directory, max_dir_len)

    # Combine truncated directory (if any) and filename
    if not directory:  # Handle cases where original path was just a filename
        return filename  # Should have been caught by initial length check, but safe
    else:
        final_path = truncated_dir + os.sep + filename
        # Final check in case of rounding issues or very short max_length
        if len(final_path) > max_length:
            # Fallback: just truncate the filename if combination still too long
            keep_chars = max_length - len(ellipsis)
            return ellipsis + filename[-keep_chars:]
        return final_path
