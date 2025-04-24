# Filename: src/lsoph/backend/strace/helpers.py
"""Helper functions specific to the strace backend. Works with bytes paths."""

import logging
import os
import re
from typing import Optional

from lsoph.monitor import Monitor

log = logging.getLogger(__name__)

DIRFD_RE = re.compile(r"^(?:AT_FDCWD|-100)$")


# --- MODIFY resolve_path ---
def resolve_path(
    pid: int,
    path_bytes: Optional[bytes],  # Accepts only bytes (or None)
    cwd_map: dict[int, bytes],  # Expects bytes CWD
    monitor: Monitor,
    dirfd: Optional[int] = None,
) -> Optional[bytes]:  # Returns bytes path
    """
    Resolves a bytes path argument relative to CWD (bytes) or dirfd.

    Args:
        pid: Process ID.
        path_bytes: The path argument as bytes (or None).
        cwd_map: Dictionary mapping PIDs to their CWDs (bytes).
        monitor: The Monitor instance (used for resolving FD paths).
        dirfd: Optional file descriptor for directory (used by *at syscalls).

    Returns:
        The absolute path as bytes, or None if resolution fails.
    """
    # Input validation
    if path_bytes is None:
        log.debug("resolve_path: Received None for path_bytes.")
        return None
    if not isinstance(path_bytes, bytes):
        log.error(
            f"resolve_path received non-bytes path argument type: {type(path_bytes)} value: {path_bytes!r}"
        )
        return None  # Should not happen if parser/handlers are correct
    if not path_bytes:
        log.debug("resolve_path: path_bytes is empty.")
        return None

    # --- dirfd handling ---
    if dirfd is not None and dirfd >= 0:
        log.debug(f"resolve_path: Handling dirfd={dirfd}")
        base_path: bytes | None = monitor.get_path(pid, dirfd)  # Returns bytes
        if base_path:
            log.debug(f"resolve_path: Found base_path for dirfd {dirfd}: {base_path!r}")
            try:
                log.debug(f"resolve_path: Calling os.stat on base_path: {base_path!r}")
                stat_result = os.stat(base_path)
                is_dir = stat_result.st_mode & 0o040000
                if is_dir:
                    log.debug(
                        f"resolve_path: Joining base_path={base_path!r} and path_bytes={path_bytes!r}"
                    )
                    joined_path = os.path.join(base_path, path_bytes)
                    log.debug(f"resolve_path: Normalizing joined path: {joined_path!r}")
                    abs_path = os.path.normpath(joined_path)
                    log.debug(f"resolve_path: Resolved via dirfd to: {abs_path!r}")
                    return abs_path
                else:
                    log.warning(
                        f"resolve_path: Base path for dirfd {dirfd} is not a directory: {os.fsdecode(base_path)!r}"
                    )
                    return None
            except FileNotFoundError:
                log.warning(
                    f"resolve_path: Base path for dirfd {dirfd} not found: {os.fsdecode(base_path)!r}"
                )
                return None
            except TypeError as e:
                log.exception(
                    f"resolve_path: TypeError during dirfd handling! base_path={base_path!r}, path_bytes={path_bytes!r}: {e}"
                )
                return None
            except OSError as e:
                log.warning(f"resolve_path: OSError stating/joining dirfd path: {e}")
                return None
            except Exception as e:
                log.exception(
                    f"resolve_path: Unexpected error during dirfd handling: {e}"
                )
                return None
        else:
            log.warning(
                f"resolve_path: Could not get path for dirfd {dirfd} from monitor."
            )
            return None

    # --- Absolute path check ---
    try:
        log.debug(f"resolve_path: Checking os.path.isabs on path_bytes: {path_bytes!r}")
        is_absolute = os.path.isabs(path_bytes)
    except TypeError as e:
        log.exception(
            f"resolve_path: TypeError calling os.path.isabs! path_bytes={path_bytes!r}: {e}"
        )
        return None
    except Exception as e:
        log.exception(f"resolve_path: Unexpected error calling os.path.isabs: {e}")
        return None

    if is_absolute:
        try:
            log.debug(f"resolve_path: Normalizing absolute path_bytes: {path_bytes!r}")
            norm_path = os.path.normpath(path_bytes)
            log.debug(f"resolve_path: Resolved absolute path to: {norm_path!r}")
            return norm_path
        except TypeError as e:
            log.exception(
                f"resolve_path: TypeError calling os.path.normpath on absolute path! path_bytes={path_bytes!r}: {e}"
            )
            return None
        except Exception as e:
            log.exception(
                f"resolve_path: Unexpected error calling os.path.normpath on absolute path: {e}"
            )
            return None

    # --- CWD handling ---
    cwd: bytes | None = cwd_map.get(pid)  # Returns bytes
    if cwd:
        log.debug(f"resolve_path: Using CWD: {cwd!r}")
        try:
            log.debug(
                f"resolve_path: Joining cwd={cwd!r} and path_bytes={path_bytes!r}"
            )
            joined_path = os.path.join(cwd, path_bytes)
            log.debug(f"resolve_path: Normalizing joined path: {joined_path!r}")
            abs_path = os.path.normpath(joined_path)
            log.debug(f"resolve_path: Resolved via CWD to: {abs_path!r}")
            return abs_path
        except TypeError as e:
            log.exception(
                f"resolve_path: TypeError during CWD joining/normalizing! cwd={cwd!r}, path_bytes={path_bytes!r}: {e}"
            )
            return None
        except ValueError as e:  # Catch potential join errors too
            log.warning(f"resolve_path: ValueError joining CWD path: {e}")
            return None
        except Exception as e:
            log.exception(f"resolve_path: Unexpected error during CWD handling: {e}")
            return None
    else:
        # Use os.fsdecode safely here as path_bytes is guaranteed bytes
        log.warning(
            f"resolve_path: Cannot resolve relative path '{os.fsdecode(path_bytes)!r}' for PID {pid}: CWD unknown."
        )
        return None


# --- parse_dirfd and parse_result_int remain the same ---
def parse_dirfd(dirfd_arg: Optional[str]) -> Optional[int]:
    """Parses the dirfd argument (e.g., "AT_FDCWD", "3") into an integer or None."""
    if dirfd_arg is None:
        return None
    if DIRFD_RE.match(dirfd_arg):
        return None
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
