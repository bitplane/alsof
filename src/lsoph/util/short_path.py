"""Utility function for shortening file paths."""

import logging
import os

log = logging.getLogger(__name__)

CWD = os.getcwd()
if not CWD.endswith(os.sep):
    CWD += os.sep


def _relative_path(path: str, cwd: str = CWD) -> str:
    """
    If path starts with cwd, return the relative path component,
    otherwise return the original path. Returns "." if path is identical to cwd.
    Assumes cwd ends with path separator.
    """
    if path.startswith(cwd):
        pos = len(cwd)
        relative = path[pos:]
        return relative or "."

    return path


def _truncate_directory(directory: str, max_dir_len: int) -> str:
    """Truncates the directory string in the middle if it exceeds max_dir_len."""
    if max_dir_len <= 3:
        return "..."[:max_dir_len]

    # Calculate lengths for start and end parts
    dir_keep_total = max_dir_len - 3

    # try to keep the start and end parts visible
    start_len = max(1, dir_keep_total // 2)
    end_len = max(1, dir_keep_total - start_len)

    # grab start and end parts
    start_part = directory[:start_len]
    end_part = directory[-end_len:]

    # might be 1 char too long, so truncate
    return f"{start_part}...{end_part}"[:max_dir_len]


def short_path(path: str | os.PathLike, max_length: int, cwd: str = CWD) -> str:
    """
    Shortens a file path string to fit max_length:
    1. Tries to make path relative to CWD.
    2. Prioritizes keeping the full filename visible.
    3. If filename alone is too long, truncates filename from the left ("...name").
    4. If path is still too long but filename fits, truncates directory in the middle ("dir...ory/name").
    """
    # unlike gemini's code, the shorter the better here
    path_str = _relative_path(str(path), cwd)

    if len(path_str) <= max_length:
        return path_str
    if max_length <= 0:
        return ""
    if max_length <= 3:
        return path_str[-max_length:]

    directory, filename = os.path.split(path_str)

    # Check if just the filename + ellipsis exceeds the max length
    if len(filename) + 3 >= max_length:
        # Keep only the end of the filename that fits
        keep_chars = max_length - 3
        return "..." + filename[-keep_chars:]

    # Calculate maximum length allowed for the directory part
    len_sep_before_file = 1 if directory else 0
    max_dir_len = max_length - len(filename) - len_sep_before_file

    # Truncate the directory part if necessary
    truncated_dir = _truncate_directory(directory, max_dir_len)

    # Combine truncated directory and filename
    final_path = truncated_dir + os.sep + filename
    return final_path
