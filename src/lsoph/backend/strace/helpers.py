# Filename: src/lsoph/backend/strace/helpers.py
"""Helper functions specific to the strace backend. Works with bytes paths."""

import logging
import os
import re
from typing import Optional

from lsoph.monitor import Monitor

log = logging.getLogger(__name__)

# Regex to find file descriptors like AT_FDCWD or numeric FDs (operates on str)
DIRFD_RE = re.compile(r"^(?:AT_FDCWD|-100)$")


def clean_path_arg(path_arg_bytes: Optional[bytes]) -> Optional[bytes]:
    """
    Cleans a path argument bytes sequence obtained from strace parsing.
    Removes surrounding quotes (b'"'), handles b"(null)", and decodes octal escapes (\nnn)
    within the byte sequence.

    Args:
        path_arg_bytes: The path argument as bytes, potentially with quotes,
                        b"(null)", or octal escapes.

    Returns:
        The cleaned path as bytes, or None if invalid.
    """
    if path_arg_bytes is None:
        return None

    path_b = path_arg_bytes.strip()  # Strip whitespace bytes

    # Handle cases where strace might output b"(null)" for a null pointer path
    if path_b == b"(null)":
        log.warning("Encountered b'(null)' path argument, treating as None.")
        return None

    # Remove surrounding quotes (bytes) FIRST
    if len(path_b) >= 2 and path_b.startswith(b'"') and path_b.endswith(b'"'):
        path_b = path_b[1:-1]

    # Final check for empty bytes after quote stripping
    if not path_b:
        return None

    # --- DECODE OCTAL ESCAPES within bytes sequence ---
    # Simplified logic: iterate byte by byte
    result_bytes = bytearray()
    i = 0
    n = len(path_b)
    while i < n:
        current_byte = path_b[i]
        # Check for octal escape: b'\' followed by 1-3 octal digits
        if (
            current_byte == ord(b"\\")
            and i + 1 < n
            and ord(b"0") <= path_b[i + 1] <= ord(b"9")
        ):
            j = i + 1
            octal_digits_bytes = bytearray()
            # Consume up to 3 octal digits
            while (
                j < n
                and ord(b"0") <= path_b[j] <= ord(b"9")
                and len(octal_digits_bytes) < 3
            ):
                octal_digits_bytes.append(path_b[j])
                j += 1

            if octal_digits_bytes:
                try:
                    # Decode digits to string, then convert from octal string to int
                    octal_str = octal_digits_bytes.decode("ascii")
                    byte_value = int(octal_str, 8)
                    # Check if the value is a valid byte
                    if 0 <= byte_value <= 255:
                        result_bytes.append(byte_value)
                        i = j  # Move index past consumed digits
                        continue  # Continue parsing loop
                    else:
                        # Octal value > 255, treat literally (append original bytes)
                        log.warning(
                            f"Invalid octal escape value > 255 encountered: \\{octal_str} in {path_b!r}. Treating literally."
                        )
                        result_bytes.extend(
                            path_b[i:j]
                        )  # Append original b'\' and digits
                        i = j
                        continue
                except (ValueError, UnicodeDecodeError) as e:
                    # Treat literally if conversion fails
                    log.warning(
                        f"Error converting octal escape: {path_b[i:j]!r} in {path_b!r}: {e}. Treating literally."
                    )
                    result_bytes.extend(path_b[i:j])  # Append original b'\' and digits
                    i = j
                    continue
            else:
                # Just a backslash followed by non-digit or end of string
                # Append the backslash byte literally
                result_bytes.append(current_byte)
                i += 1
        else:
            # Normal byte or other escape sequence (e.g., \\, \n - treat literally)
            # Append the byte directly.
            result_bytes.append(current_byte)
            i += 1

    return bytes(result_bytes)
    # --- END OCTAL DECODING ---


def resolve_path(
    pid: int,
    path_arg: Optional[bytes],  # Accepts bytes path
    cwd_map: dict[int, bytes],  # Expects bytes CWD
    monitor: Monitor,
    dirfd: Optional[int] = None,
) -> Optional[bytes]:  # Returns bytes path
    """
    Resolves a bytes path argument relative to CWD (bytes) or dirfd.

    Args:
        pid: Process ID.
        path_arg: The raw path argument as bytes (potentially relative),
                  after octal decoding by clean_path_arg.
        cwd_map: Dictionary mapping PIDs to their CWDs (bytes).
        monitor: The Monitor instance (used for resolving FD paths).
        dirfd: Optional file descriptor for directory (used by *at syscalls).

    Returns:
        The absolute path as bytes, or None if resolution fails.
    """
    # This part remains the same as before, operating on bytes
    if not path_arg:
        return None

    if dirfd is not None and dirfd >= 0:
        base_path: bytes | None = monitor.get_path(pid, dirfd)
        if base_path:
            try:
                # Use os.stat for checking if dirfd path is actually a directory
                # This can fail if the path doesn't exist or permissions are wrong
                is_dir = os.stat(base_path).st_mode & 0o040000  # S_ISDIR check
                if is_dir:
                    abs_path = os.path.normpath(os.path.join(base_path, path_arg))
                    return abs_path
                else:
                    log.warning(
                        f"Cannot resolve path relative to dirfd {dirfd} for PID {pid}: FD path '{os.fsdecode(base_path)!r}' is not a directory."
                    )
                    return None
            except FileNotFoundError:
                log.warning(
                    f"Cannot resolve path relative to dirfd {dirfd} for PID {pid}: FD path '{os.fsdecode(base_path)!r}' not found."
                )
                return None
            except OSError as e:
                log.warning(
                    f"Cannot resolve path relative to dirfd {dirfd} for PID {pid}: Error stating FD path '{os.fsdecode(base_path)!r}': {e}"
                )
                return None
        else:
            log.warning(
                f"Cannot resolve path relative to dirfd {dirfd} for PID {pid}: FD path unknown."
            )
            return None

    if os.path.isabs(path_arg):
        return os.path.normpath(path_arg)

    cwd: bytes | None = cwd_map.get(pid)
    if cwd:
        try:
            abs_path = os.path.normpath(os.path.join(cwd, path_arg))
            return abs_path
        except ValueError as e:
            log.warning(
                f"Error joining path '{os.fsdecode(path_arg)!r}' with CWD '{os.fsdecode(cwd)!r}' for PID {pid}: {e}"
            )
            return None
    else:
        log.warning(
            f"Cannot resolve relative path '{os.fsdecode(path_arg)!r}' for PID {pid}: CWD unknown."
        )
        return None


def parse_dirfd(dirfd_arg: Optional[str]) -> Optional[int]:
    """Parses the dirfd argument (e.g., "AT_FDCWD", "3") into an integer or None."""
    # This function operates on strings parsed from strace output before encoding
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
    # This function operates on strings parsed from strace output
    if result_str is None or result_str == "?":
        return None
    try:
        if result_str.startswith("0x"):
            return int(result_str, 16)
        else:
            return int(result_str)
    except ValueError:
        return None
