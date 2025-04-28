# Filename: src/lsoph/util/pid.py
import logging
import os

import psutil

log = logging.getLogger(__name__)


def get_descendants(parent_pid: int) -> list[int]:
    """
    Retrieves a list of all descendant process IDs (PIDs) for a given parent PID.
    """
    descendant_pids: list[int] = []
    try:
        parent = psutil.Process(parent_pid)
        descendant_procs = parent.children(recursive=True)
        descendant_pids = [proc.pid for proc in descendant_procs]
        log.debug(f"Found descendants for PID {parent_pid}: {descendant_pids}")
    except psutil.NoSuchProcess:
        log.warning(f"Process with PID {parent_pid} not found.")
    except psutil.AccessDenied:
        log.warning(f"Access denied getting descendants of PID {parent_pid}.")
    except Exception as e:
        log.error(f"Unexpected error getting descendants for PID {parent_pid}: {e}")
    return descendant_pids


def get_cwd(pid: int) -> bytes | None:
    """
    Retrieves the Current Working Directory (CWD) for a given PID as bytes.

    Uses psutil for cross-platform compatibility where possible, encodes the
    result using os.fsencode(). Falls back to /proc/<pid>/cwd on Linux if needed,
    which returns bytes directly.

    Args:
        pid: The Process ID.

    Returns:
        The absolute path bytes of the CWD, or None if the process doesn't exist,
        access is denied, or the CWD cannot be determined.
    """
    try:
        proc = psutil.Process(pid)
        cwd_str = proc.cwd()  # psutil returns str
        # --- ENCODE TO BYTES ---
        cwd_bytes = os.fsencode(cwd_str)
        # -----------------------
        log.debug(f"Retrieved CWD for PID {pid}: {cwd_str!r} -> {cwd_bytes!r}")
        return cwd_bytes
    except psutil.NoSuchProcess:
        log.debug(f"Process with PID {pid} not found when getting CWD.")
        return None
    except psutil.AccessDenied:
        log.warning(f"Access denied getting CWD for PID {pid} via psutil.")
        # Attempt Linux /proc fallback (might also fail with AccessDenied)
        try:
            # --- USE BYTES PATH ---
            proc_path = os.path.join(b"/proc", str(pid).encode("ascii"), b"cwd")
            # --------------------
            # Use os.stat on bytes path to check existence/permissions before readlink
            try:
                os.stat(proc_path)
            except FileNotFoundError:
                log.warning(f"/proc path {os.fsdecode(proc_path)!r} not found.")
                return None
            except PermissionError:
                log.warning(
                    f"Permission denied accessing /proc path {os.fsdecode(proc_path)!r}."
                )
                return None
            except OSError as stat_err:
                log.warning(
                    f"Error stating /proc path {os.fsdecode(proc_path)!r}: {stat_err}"
                )
                return None

            # If stat succeeded, try readlink
            cwd_bytes = os.readlink(proc_path)  # readlink on bytes path returns bytes
            log.debug(f"Retrieved CWD via /proc for PID {pid}: {cwd_bytes!r}")
            return cwd_bytes
        except (OSError, PermissionError) as e:
            log.warning(f"Failed /proc fallback for CWD of PID {pid}: {e}")
            return None
        except Exception as e:  # Catch other potential errors
            log.error(
                f"Unexpected error during /proc fallback for CWD of PID {pid}: {e}"
            )
            return None
    except Exception as e:
        # Catch other potential psutil errors (e.g., ZombieProcess on some platforms)
        log.error(f"An unexpected error occurred getting CWD for PID {pid}: {e}")
        return None


def get_fd_path(pid: int, fd: int) -> bytes:
    """
    Retrieves the file path for a given file descriptor (fd) of a process with the specified PID.
    """
    if not psutil.pid_exists(pid):
        raise KeyError(f"PID {pid} does not exist.")

    proc = psutil.Process(pid)

    fds = list(f for f in proc.open_files() if f.fd == fd)
    if not fds:
        raise KeyError(f"File descriptor {fd} not found for PID {pid}.")

    return os.fsencode(fds[0].path)
