# Filename: src/lsoph/backend/psutil/helpers.py
"""Helper functions for the psutil backend."""

import logging
import os
from typing import Any

# Attempt to import psutil and handle failure gracefully
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # Set to None if import fails
    PSUTIL_AVAILABLE = False

log = logging.getLogger(__name__)  # Use specific logger


def _get_process_info(pid: int) -> psutil.Process | None:
    """Safely get a psutil.Process object."""
    if not PSUTIL_AVAILABLE:
        return None  # Guard clause
    try:
        return psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        # Log non-NoSuchProcess errors at debug level
        if not isinstance(e, psutil.NoSuchProcess):
            log.debug(f"Error getting psutil.Process for PID {pid}: {type(e).__name__}")
        return None


def _get_process_cwd(proc: psutil.Process) -> str | None:
    """Safely get the current working directory."""
    if not PSUTIL_AVAILABLE:
        return None  # Guard clause
    try:
        return proc.cwd()
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Could not get CWD for PID {proc.pid}: {type(e).__name__}")
        return None


def _get_process_open_files(
    proc: psutil.Process,
) -> list[dict[str, Any]]:  # Use list and dict
    """Safely get open files and connections for a process."""
    if not PSUTIL_AVAILABLE:
        return []  # Guard clause

    open_files_data: list[dict[str, Any]] = []  # Use list and dict
    pid = proc.pid
    try:  # Get regular files
        for f in proc.open_files():
            # Ensure path is a string, handle potential issues
            path = str(f.path) if hasattr(f, "path") and f.path else f"<FD:{f.fd}>"
            open_files_data.append(
                {
                    "path": path,
                    "fd": f.fd,
                    "mode": getattr(f, "mode", ""),  # Use getattr for safety
                    "type": "file",
                }
            )
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Error accessing open files for PID {pid}: {type(e).__name__}")

    try:  # Get connections
        for conn in proc.connections(kind="all"):
            try:
                # Simplify connection string representation
                if conn.laddr:
                    laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"
                else:
                    laddr_str = "<?:?>"
                if conn.raddr:
                    # Check if raddr has ip and port attributes
                    if hasattr(conn.raddr, "ip") and hasattr(conn.raddr, "port"):
                        raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                    else:  # Handle cases like UNIX sockets where raddr might be a path string
                        raddr_str = str(conn.raddr) if conn.raddr else ""
                else:
                    raddr_str = ""

                conn_type_str = (
                    conn.type.name if hasattr(conn.type, "name") else str(conn.type)
                )

                if conn.status == psutil.CONN_ESTABLISHED and raddr_str:
                    path = f"<SOCKET:{conn_type_str}:{laddr_str}->{raddr_str}>"
                elif conn.status == psutil.CONN_LISTEN:
                    path = f"<SOCKET_LISTEN:{conn_type_str}:{laddr_str}>"
                else:
                    path = f"<SOCKET:{conn_type_str}:{laddr_str} fd={conn.fd} status={conn.status}>"

                open_files_data.append(
                    {
                        "path": path,
                        "fd": conn.fd if conn.fd != -1 else -1,  # Use -1 for invalid FD
                        "mode": "rw",  # Assume read/write for sockets
                        "type": "socket",
                    }
                )
            except (AttributeError, ValueError) as conn_err:
                log.debug(
                    f"Error formatting connection details for PID {pid}: {conn_err} - {conn}"
                )
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Error accessing connections for PID {pid}: {type(e).__name__}")
    return open_files_data


def _get_process_descendants(
    proc: psutil.Process,
) -> list[int]:  # Use list
    """Safely get all descendant PIDs."""
    if not PSUTIL_AVAILABLE:
        return []  # Guard clause
    try:
        # Use list comprehension directly
        return [p.pid for p in proc.children(recursive=True)]
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Could not get descendants for PID {proc.pid}: {type(e).__name__}")
        return []
