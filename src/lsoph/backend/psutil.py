# Filename: src/lsoph/backend/psutil.py
import asyncio
import logging
import os
import subprocess
import time

# Use Python 3.10+ style hints
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from lsoph.monitor import Monitor

# Import updated base class
from .base import Backend

# Setup logging
log = logging.getLogger("lsoph.backend.psutil")

# --- Constants ---
DEFAULT_PSUTIL_POLL_INTERVAL = 0.5


# --- Helper Functions (remain synchronous as psutil is sync) ---
# _get_process_info, _get_process_cwd, _get_process_open_files, _get_process_descendants
# remain the same.
def _get_process_info(pid: int) -> Optional[psutil.Process]:
    """Safely get a psutil.Process object."""
    try:
        return psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        if not isinstance(e, psutil.NoSuchProcess):
            log.debug(f"Error getting psutil.Process for PID {pid}: {type(e).__name__}")
        return None


def _get_process_cwd(proc: psutil.Process) -> Optional[str]:
    """Safely get the current working directory."""
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


def _get_process_open_files(proc: psutil.Process) -> List[Dict[str, Any]]:
    """Safely get open files and connections for a process."""
    open_files_data = []
    pid = proc.pid
    try:  # Get regular files
        for f in proc.open_files():
            path = str(f.path) if hasattr(f, "path") and f.path else f"<FD:{f.fd}>"
            open_files_data.append(
                {
                    "path": path,
                    "fd": f.fd,
                    "mode": getattr(f, "mode", ""),
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
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    path = f"<SOCKET:{conn.type.name}:{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}>"
                elif conn.status == psutil.CONN_LISTEN:
                    path = f"<SOCKET_LISTEN:{conn.type.name}:{conn.laddr.ip}:{conn.laddr.port}>"
                elif conn.laddr:
                    path = f"<SOCKET:{conn.type.name}:{conn.laddr.ip}:{conn.laddr.port} status={conn.status}>"
                else:
                    path = (
                        f"<SOCKET:{conn.type.name} fd={conn.fd} status={conn.status}>"
                    )
                open_files_data.append(
                    {
                        "path": path,
                        "fd": conn.fd if conn.fd != -1 else -1,
                        "mode": "rw",
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


def _get_process_descendants(proc: psutil.Process) -> List[int]:
    """Safely get all descendant PIDs."""
    try:
        return [p.pid for p in proc.children(recursive=True)]
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Could not get descendants for PID {proc.pid}: {type(e).__name__}")
        return []


# --- Async Backend Class ---


class PsutilBackend(Backend):
    """Async backend implementation using psutil polling."""

    def __init__(
        self, monitor: Monitor, poll_interval: float = DEFAULT_PSUTIL_POLL_INTERVAL
    ):
        super().__init__(monitor)
        self.poll_interval = poll_interval
        # State is managed within the run methods

    # --- Internal Helpers used by _poll_cycle ---
    def _update_cwd_cache(
        self, pid: int, proc: Optional[psutil.Process], pid_cwd_cache: dict
    ):
        if proc and pid not in pid_cwd_cache:
            cwd = _get_process_cwd(proc)
            pid_cwd_cache[pid] = cwd

    def _resolve_path(self, pid: int, path: str, pid_cwd_cache: dict) -> str:
        if path.startswith(("/", "<")) or (len(path) > 1 and path[1] == ":"):
            return path
        cwd = pid_cwd_cache.get(pid)
        if cwd:
            try:
                return os.path.normpath(os.path.join(cwd, path))
            except ValueError as e:
                log.warning(
                    f"Error joining path '{path}' with CWD '{cwd}' for PID {pid}: {e}"
                )
        return path

    def _process_pid_files(
        self,
        pid: int,
        proc: psutil.Process,
        timestamp: float,
        pid_cwd_cache: dict,
        seen_fds: dict,
    ) -> Set[int]:
        current_pid_fds: Set[int] = set()
        open_files_data = _get_process_open_files(proc)
        for file_info in open_files_data:
            path, fd, mode = (
                file_info["path"],
                file_info["fd"],
                file_info.get("mode", ""),
            )
            if fd < 0:
                continue
            current_pid_fds.add(fd)
            resolved_path = self._resolve_path(pid, path, pid_cwd_cache)
            can_read = "r" in mode or "+" in mode
            can_write = "w" in mode or "a" in mode or "+" in mode
            is_new, has_changed, previous_state = (
                True,
                False,
                seen_fds.get(pid, {}).get(fd),
            )
            if previous_state:
                is_new = False
                old_path, old_read, old_write = previous_state
                has_changed = (
                    old_path != resolved_path
                    or old_read != can_read
                    or old_write != can_write
                )

            if is_new or has_changed:
                if has_changed:
                    old_path, _, _ = previous_state
                    self.monitor.close(pid, fd, True, timestamp, source="psutil_change")
                self.monitor.open(
                    pid, resolved_path, fd, True, timestamp, source="psutil", mode=mode
                )
                seen_fds.setdefault(pid, {})[fd] = (resolved_path, can_read, can_write)
                if can_read:
                    self.monitor.read(
                        pid,
                        fd,
                        resolved_path,
                        True,
                        timestamp,
                        source="psutil_mode",
                        bytes=0,
                    )
                if can_write:
                    self.monitor.write(
                        pid,
                        fd,
                        resolved_path,
                        True,
                        timestamp,
                        source="psutil_mode",
                        bytes=0,
                    )
        return current_pid_fds

    def _detect_and_handle_closures(
        self, pid: int, current_pid_fds: Set[int], timestamp: float, seen_fds: dict
    ):
        if pid not in seen_fds:
            return
        closed_count = 0
        previous_pid_fds = list(seen_fds[pid].keys())
        for fd in previous_pid_fds:
            if fd not in current_pid_fds:
                path, _, _ = seen_fds[pid][fd]
                self.monitor.close(pid, fd, True, timestamp, source="psutil_poll")
                del seen_fds[pid][fd]
                closed_count += 1
        if pid in seen_fds and not seen_fds[pid]:
            del seen_fds[pid]

    def _poll_cycle(
        self,
        monitored_pids: set[int],
        pid_exists_status: dict,
        pid_cwd_cache: dict,
        seen_fds: dict,
        track_descendants: bool,
    ):  # Removed initial_pids_for_desc_check (not needed)
        """
        Performs a single polling cycle.
        Accepts state dictionaries as arguments and returns updated monitored_pids.
        """
        timestamp = time.time()
        pids_in_this_poll = set(monitored_pids)  # Copy

        # Discover New Descendants
        if track_descendants:
            newly_found_pids = set()
            pids_to_check_children = list(monitored_pids)
            for pid in pids_to_check_children:
                proc = _get_process_info(pid)
                if proc:
                    descendants = _get_process_descendants(proc)
                    for child_pid in descendants:
                        if child_pid not in monitored_pids:
                            log.info(
                                f"Found new child process: {child_pid} (parent: {pid})"
                            )
                            newly_found_pids.add(child_pid)
                            pid_exists_status[child_pid] = True
                            child_proc = _get_process_info(child_pid)
                            self._update_cwd_cache(child_pid, child_proc, pid_cwd_cache)
            if newly_found_pids:
                log.info(
                    f"Adding {len(newly_found_pids)} new child PIDs to monitoring."
                )
                monitored_pids.update(newly_found_pids)
                pids_in_this_poll.update(newly_found_pids)

        # Process Each Monitored PID
        for pid in pids_in_this_poll:
            if pid_exists_status.get(pid) is False:
                continue
            proc = _get_process_info(pid)
            if proc:
                pid_exists_status[pid] = True
                self._update_cwd_cache(pid, proc, pid_cwd_cache)
                current_pid_fds = self._process_pid_files(
                    pid, proc, timestamp, pid_cwd_cache, seen_fds
                )
                self._detect_and_handle_closures(
                    pid, current_pid_fds, timestamp, seen_fds
                )
            else:  # Process doesn't exist or access denied
                if pid_exists_status.get(pid) is True:
                    log.info(
                        f"Monitored process PID {pid} is no longer accessible or has exited."
                    )
                pid_exists_status[pid] = False
                if pid in seen_fds:  # Close FDs if process is gone
                    self._detect_and_handle_closures(pid, set(), timestamp, seen_fds)

        # Cleanup Stale PID entries
        pids_to_remove = {
            pid
            for pid, exists in pid_exists_status.items()
            if not exists and pid in monitored_pids
        }
        if pids_to_remove:
            log.debug(
                f"Removing {len(pids_to_remove)} non-existent PIDs from monitoring set: {pids_to_remove}"
            )
            monitored_pids.difference_update(pids_to_remove)
            for pid in pids_to_remove:  # Clean up associated state
                pid_cwd_cache.pop(pid, None)
                seen_fds.pop(pid, None)

        return monitored_pids  # Return the updated set

    async def _run_loop(self, initial_pids: list[int], track_descendants: bool):
        """The core async monitoring loop, shared by attach and run_command."""
        log.info(
            f"Starting psutil monitoring loop. Initial PIDs: {initial_pids}, Track Descendants: {track_descendants}"
        )

        # --- State Management within the loop ---
        monitored_pids: Set[int] = set(initial_pids)
        pid_exists_status: Dict[int, bool] = {pid: True for pid in initial_pids}
        pid_cwd_cache: Dict[int, Optional[str]] = {}
        seen_fds: Dict[int, Dict[int, Tuple[str, bool, bool]]] = {}
        for pid in initial_pids:
            proc = _get_process_info(pid)
            self._update_cwd_cache(pid, proc, pid_cwd_cache)
        # --- End State Management ---

        try:
            while not self.should_stop:
                start_time = time.monotonic()

                # Perform the synchronous polling logic, passing state
                updated_monitored_pids = self._poll_cycle(
                    monitored_pids,
                    pid_exists_status,
                    pid_cwd_cache,
                    seen_fds,
                    track_descendants,  # Pass the flag to control descendant checking
                )
                monitored_pids = updated_monitored_pids  # Update local state

                # If no PIDs left to monitor, exit loop
                if not monitored_pids:
                    log.info("No monitored PIDs remaining. Exiting psutil loop.")
                    break

                # Check stop event again after polling
                if self.should_stop:
                    break

                # Asynchronous sleep
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, self.poll_interval - elapsed)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            log.info(
                f"Psutil backend {('attach' if not track_descendants else 'run')} cancelled."
            )
        except Exception as e:
            log.exception(f"Unexpected error in psutil async loop: {e}")
        finally:
            log.info(
                f"Exiting psutil async {('attach' if not track_descendants else 'run')} loop."
            )

    async def attach(self, pids: list[int]):
        """Implementation of the attach method."""
        if not pids:
            log.warning("PsutilBackend.attach called with no PIDs.")
            return
        # Run the loop, now ALWAYS tracking descendants for attach mode too
        await self._run_loop(initial_pids=pids, track_descendants=True)

    # run_command is inherited from the base class
