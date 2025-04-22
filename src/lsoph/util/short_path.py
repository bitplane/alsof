"""Utility functions for lsoph."""

import logging
import os

log = logging.getLogger(__name__)

# Store CWD at import time. Let OSError propagate if this fails.
# Ensure it ends with a separator.
CWD = os.getcwd()
if not CWD.endswith(os.sep):
    CWD += os.sep
log.debug(f"lsoph CWD stored as: {CWD}")  # Keep this initial log


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

    dir_keep_total = max_dir_len - len(ellipsis)
    start_len = dir_keep_total // 2
    end_len = dir_keep_total - start_len

    # Ensure slicing indices are valid
    start_len = start_len
    end_slice_start = len(directory) - end_len
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
    if max_length <= 0:
        return ""
    if max_length <= len(ellipsis):
        return path_str[-max_length:]

    directory, filename = os.path.split(path_str)

    # Check if filename + ellipsis is too long
    if len(ellipsis) + len(filename) >= max_length:
        keep_chars = max_length - len(ellipsis)
        return ellipsis + filename[-keep_chars:]

    # Filename fits, check if dir needs shortening.
    len_sep_before_file = len(os.sep) if directory else 0
    max_dir_len = max_length - len(filename) - len_sep_before_file

    truncated_dir = _truncate_directory(directory, max_dir_len)
    final_path = truncated_dir + os.sep + filename

    return final_path
