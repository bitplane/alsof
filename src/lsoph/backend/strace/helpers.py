# Filename: src/lsoph/backend/strace/helpers.py
"""Helper functions specific to the strace backend. Works with bytes paths."""

import logging
import os
import re
from typing import Optional

from lsoph.monitor import Monitor

log = logging.getLogger(__name__)

DIRFD_RE = re.compile(r"^(?:AT_FDCWD|-100)$")


class PathResolutionError(KeyError):
    """Exception raised when a path cannot be resolved."""

    pass


def resolve_path(
    pid: int,
    path_bytes: Optional[bytes],
    cwd_map: dict[int, bytes],
    monitor: Monitor,
    dirfd: Optional[int] = None,
) -> bytes:
    """
    Resolves a bytes path argument relative to CWD (bytes) or dirfd.
    Raises exceptions instead of returning None for errors.

    Args:
        pid: Process ID.
        path_bytes: The path argument as bytes.
        cwd_map: Dictionary mapping PIDs to their CWDs (bytes).
        monitor: The Monitor instance (used for resolving FD paths).
        dirfd: Optional file descriptor for directory (used by *at syscalls).

    Returns:
        The absolute path as bytes.

    Raises:
        PathResolutionError: If the path cannot be resolved.
        TypeError: If path_bytes is not bytes.
    """
    # Input validation
    if path_bytes is None:
        raise PathResolutionError("Path is None")
    if not isinstance(path_bytes, bytes):
        raise TypeError(f"Expected bytes path, got {type(path_bytes)}")
    if not path_bytes:
        raise PathResolutionError("Path is empty")

    # Handle dirfd
    if dirfd is not None and dirfd >= 0:
        base_path = monitor.get_path(pid, dirfd)
        if not base_path:
            raise PathResolutionError(f"Could not get path for dirfd {dirfd}")

        try:
            stat_result = os.stat(base_path)
            is_dir = stat_result.st_mode & 0o040000
            if not is_dir:
                raise PathResolutionError(
                    f"Base path for dirfd {dirfd} is not a directory: {os.fsdecode(base_path)!r}"
                )

            joined_path = os.path.join(base_path, path_bytes)
            return os.path.normpath(joined_path)

        except FileNotFoundError:
            raise PathResolutionError(
                f"Base path for dirfd {dirfd} not found: {os.fsdecode(base_path)!r}"
            )
        except OSError as e:
            raise PathResolutionError(f"OSError stating/joining dirfd path: {e}")

    # Handle absolute path
    if os.path.isabs(path_bytes):
        return os.path.normpath(path_bytes)

    # Handle relative path using CWD
    cwd = cwd_map.get(pid)
    if not cwd:
        raise PathResolutionError(
            f"Cannot resolve relative path '{os.fsdecode(path_bytes)!r}' for PID {pid}: "
            "CWD unknown."
        )

    try:
        joined_path = os.path.join(cwd, path_bytes)
        return os.path.normpath(joined_path)
    except (TypeError, ValueError) as e:
        raise PathResolutionError(f"Error joining paths: {e}")


def parse_dirfd(dirfd_arg: Optional[str | int]) -> Optional[int]:
    """
    Parses the dirfd argument (e.g., "AT_FDCWD", "3", or 3) into an integer or None.

    Args:
        dirfd_arg: String or integer dirfd argument from the syscall.

    Returns:
        Integer file descriptor or None for AT_FDCWD case.
    """
    if dirfd_arg is None:
        return None

    # If it's already an integer, return it directly
    if isinstance(dirfd_arg, int):
        return dirfd_arg

    # Check for special strings like AT_FDCWD
    if DIRFD_RE.match(dirfd_arg):
        return None

    # Try to convert string to integer
    try:
        return int(dirfd_arg)
    except ValueError:
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
        return None
