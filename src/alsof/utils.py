"""Utility functions for alsof."""

import logging
import os

log = logging.getLogger(__name__)

# Store CWD at import time. Let OSError propagate if this fails.
# Ensure it ends with a separator.
CWD = os.getcwd()
if not CWD.endswith(os.sep):
    CWD += os.sep
log.debug(f"alsof CWD stored as: {CWD}")  # Keep this initial log


def _relative_path(path: str, cwd: str = CWD) -> str:
    """
    If path starts with cwd, return the relative path component,
    otherwise return the original path. Returns "." if path is identical to cwd.
    Assumes cwd ends with path separator.
    """
    if path.startswith(cwd):
        pos = len(cwd)
        path = path[pos:]
    return path or "."


def _truncate_directory(directory: str, max_dir_len: int) -> str:
    """Truncates the directory string in the middle."""
    ellipsis = "..."
    if len(directory) <= max_dir_len:
        return directory  # Fits

    if max_dir_len < len(ellipsis):
        return ellipsis[:max_dir_len]  # Not enough space for ellipsis

    # Calculate how many directory characters to keep
    dir_keep_total = max_dir_len - len(ellipsis)
    start_len = max(0, dir_keep_total // 2)
    end_len = max(0, dir_keep_total - start_len)

    # Ensure slicing indices are valid
    start_len = min(start_len, len(directory))
    end_slice_start = max(start_len, len(directory) - end_len)
    end_part = directory[end_slice_start:]

    return f"{directory[:start_len]}{ellipsis}{end_part}"


def short_path(path: str | os.PathLike, max_length: int, cwd: str = CWD) -> str:
    """
    Shortens a file path string to fit max_length:
    1. Tries to make path relative to CWD.
    2. Prioritizes filename.
    3. If filename too long, truncate filename from left "...name".
    4. If path too long but filename fits, truncate directory in middle "dir...ectory/name".

    Args:
        path: The file path string or path-like object.
        max_length: The maximum allowed length for the output string.

    Returns:
        The shortened path string.
    """
    path_str = _relative_path(str(path), cwd)
    ellipsis = "..."

    if len(path_str) <= max_length:
        return path_str
    if max_length <= len(ellipsis):
        return path_str[:max_length]  # Simple truncation if too short for ellipsis

    directory, filename = os.path.split(path_str)

    # --- Case 1: Filename truncation needed? ---
    # Check if filename + ellipsis is too long
    if len(ellipsis) + len(filename) >= max_length:
        keep_chars = max(1, max_length - len(ellipsis))
        return ellipsis + filename[-keep_chars:]

    # --- Case 2: Directory truncation needed? ---
    # Filename fits, check if dir needs shortening.
    len_sep_before_file = len(os.sep) if directory else 0
    max_dir_len = max_length - len(filename) - len_sep_before_file

    if max_dir_len <= 0 or not directory:
        # Can't fit directory part, or no directory exists.
        # Truncate the whole path_str from the left instead of returning just filename.
        keep_chars = max(1, max_length - len(ellipsis))
        final_path = ellipsis + path_str[-keep_chars:]
    else:
        # Directory exists and there's some space for it.
        truncated_dir = _truncate_directory(directory, max_dir_len)
        final_path = os.path.join(truncated_dir, filename)

    # Final safety check removed

    return final_path
