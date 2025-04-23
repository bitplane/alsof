# Filename: src/lsoph/backend/psutil.py
import logging
import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from lsoph.monitor import Monitor

# Setup logging
log = logging.getLogger("lsoph.backend.psutil")

# --- Constants ---
DEFAULT_PSUTIL_POLL_INTERVAL = 0.5  # seconds


# --- Helper Functions ---


def _get_process_info(pid: int) -> Optional[psutil.Process]:
    """Safely get a psutil.Process object, handling common exceptions."""
    try:
        return psutil.Process(pid)
    except psutil.NoSuchProcess:
        log.debug(f"Process {pid} no longer exists.")
        return None
    except psutil.AccessDenied:
        log.debug(f"Access denied for process {pid}.")
        return None
    except Exception as e:
        log.debug(f"Unexpected error getting psutil.Process for PID {pid}: {e}")
        return None


def _get_process_cwd(proc: psutil.Process) -> Optional[str]:
    """Safely get the current working directory for a process."""
    try:
        return proc.cwd()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        # ZombieProcess can occur if the process exits while we query it
        log.debug(f"Could not get CWD for PID {proc.pid}: {type(e).__name__}")
        return None
    except Exception as e:
        log.debug(f"Unexpected error getting CWD for PID {proc.pid}: {e}")
        return None


def _get_process_open_files(proc: psutil.Process) -> List[Dict[str, Any]]:
    """
    Safely get open files and connections for a process using psutil.
    Returns a list of dictionaries, each representing an open file/socket.
    """
    open_files_data = []
    pid = proc.pid

    # Get regular open files
    try:
        for f in proc.open_files():
            # Ensure path is a string, handle potential issues if path isn't straightforward
            path = str(f.path) if hasattr(f, "path") and f.path else f"<FD:{f.fd}>"
            open_files_data.append(
                {
                    "path": path,
                    "fd": f.fd,
                    # Mode might not always be available, default to empty string
                    "mode": getattr(f, "mode", ""),
                    "type": "file",  # Add type distinction
                }
            )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # Process might have exited or permissions changed during iteration
        log.debug(f"Error accessing open files for PID {pid} (process likely exited).")
    except Exception as e:
        log.debug(f"Unexpected error getting open files for PID {pid}: {e}")

    # Get network connections (treat them like open files for monitoring)
    try:
        for conn in proc.connections(kind="all"):
            # Create a representative path string for the connection
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
                        # Use fd if available, else -1 (sockets might not always have a typical fd)
                        "fd": (
                            conn.fd if conn.fd != -1 else -1
                        ),  # psutil uses -1 for unknown fd
                        "mode": "rw",  # Assume sockets are read-write capable
                        "type": "socket",  # Add type distinction
                    }
                )
            except (AttributeError, ValueError) as conn_err:
                log.debug(
                    f"Error formatting connection details for PID {pid}: {conn_err} - {conn}"
                )

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        log.debug(f"Error accessing connections for PID {pid} (process likely exited).")
    except Exception as e:
        log.debug(f"Unexpected error getting connections for PID {pid}: {e}")

    return open_files_data


def _get_process_descendants(proc: psutil.Process) -> List[int]:
    """Safely get all descendant PIDs for a process."""
    try:
        return [p.pid for p in proc.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # It's possible the parent process disappears while getting children
        log.debug(
            f"Could not get descendants for PID {proc.pid} (process likely exited)."
        )
        return []
    except Exception as e:
        log.debug(f"Unexpected error getting descendants for PID {proc.pid}: {e}")
        return []


# --- Backend Class ---


class PsutilBackend:
    """Backend implementation that uses psutil to monitor file activities."""

    def __init__(
        self, monitor: Monitor, poll_interval: float = DEFAULT_PSUTIL_POLL_INTERVAL
    ):
        self.monitor = monitor
        self.poll_interval = poll_interval
        self.running = False
        self.poll_thread: Optional[threading.Thread] = None
        self.lock = threading.RLock()  # Protect shared state access

        # State tracked across polls
        self.monitored_pids: Set[int] = set()  # All PIDs currently being watched
        self.pid_exists_status: Dict[int, bool] = {}  # Tracks if we know a PID exists
        self.pid_cwd_cache: Dict[int, Optional[str]] = {}  # Cache CWD per PID
        # Tracks FDs seen in the *previous* poll: {pid -> {fd -> (path, read_flag, write_flag)}}
        self.seen_fds: Dict[int, Dict[int, Tuple[str, bool, bool]]] = {}

    def _update_cwd_cache(self, pid: int, proc: Optional[psutil.Process]):
        """Updates the CWD cache for a given PID."""
        if proc and pid not in self.pid_cwd_cache:
            cwd = _get_process_cwd(proc)
            self.pid_cwd_cache[pid] = cwd
            if cwd:
                log.debug(f"Cached CWD for PID {pid}: {cwd}")
            else:
                log.debug(f"Failed to get CWD for PID {pid}, caching None.")

    def _resolve_path(self, pid: int, path: str) -> str:
        """Resolve a potentially relative path to absolute using cached process CWD."""
        # If path is already absolute (covers Linux and basic Windows) or special
        if path.startswith(("/", "<")) or (len(path) > 1 and path[1] == ":"):
            return path

        # Use cached CWD if available
        cwd = self.pid_cwd_cache.get(pid)
        if cwd:
            try:
                return os.path.normpath(os.path.join(cwd, path))
            except ValueError as e:  # Handle potential issues with joining weird paths
                log.warning(
                    f"Error joining path '{path}' with CWD '{cwd}' for PID {pid}: {e}"
                )
                return path  # Fallback to original path

        # If CWD wasn't cached or failed, return original path (can't resolve)
        log.debug(
            f"No cached CWD for PID {pid} to resolve path '{path}'. Returning original."
        )
        return path

    def _process_pid_files(
        self, pid: int, proc: psutil.Process, timestamp: float
    ) -> Set[int]:
        """
        Processes open files for a single PID, updates the monitor,
        and returns the set of valid FDs found for this PID in this poll.
        """
        current_pid_fds: Set[int] = set()
        open_files_data = _get_process_open_files(proc)

        for file_info in open_files_data:
            path = file_info["path"]
            fd = file_info["fd"]
            mode = file_info.get("mode", "")

            # Skip invalid FDs (psutil uses -1 for unknown)
            if fd < 0:
                continue

            current_pid_fds.add(fd)
            resolved_path = self._resolve_path(pid, path)

            # Determine access capabilities based on mode
            # '+' implies update (read/write), 'a' implies write
            can_read = "r" in mode or "+" in mode
            can_write = "w" in mode or "a" in mode or "+" in mode

            # Check if this FD is new or its path/mode changed since last poll
            is_new = True
            has_changed = False
            previous_state = self.seen_fds.get(pid, {}).get(fd)

            if previous_state:
                is_new = False
                old_path, old_read, old_write = previous_state
                # Check if path or implied capabilities changed
                has_changed = (
                    old_path != resolved_path
                    or old_read != can_read
                    or old_write != can_write
                )

            # --- Update Monitor ---
            if is_new or has_changed:
                if has_changed:
                    # If changed, first close the old representation
                    old_path, _, _ = previous_state  # Get old path for logging
                    log.debug(
                        f"File state changed for PID {pid}, FD {fd}: "
                        f"Path '{old_path}' -> '{resolved_path}', "
                        f"Mode Change: {old_read != can_read or old_write != can_write}"
                    )
                    self.monitor.close(pid, fd, True, timestamp, source="psutil_change")

                # Then open the new representation
                self.monitor.open(
                    pid, resolved_path, fd, True, timestamp, source="psutil", mode=mode
                )

                # Update the map for the *next* poll cycle comparison
                self.seen_fds.setdefault(pid, {})[fd] = (
                    resolved_path,
                    can_read,
                    can_write,
                )

                # Signal potential read/write based on mode
                # Note: This doesn't track actual I/O, just capability implied by mode
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
            # --- End Monitor Update ---

        return current_pid_fds

    def _detect_and_handle_closures(
        self, pid: int, current_pid_fds: Set[int], timestamp: float
    ):
        """Compares current FDs with previously seen FDs to detect closures."""
        if pid not in self.seen_fds:
            return  # No previous state to compare against

        closed_count = 0
        previous_pid_fds = list(
            self.seen_fds[pid].keys()
        )  # Iterate over FDs seen last time

        for fd in previous_pid_fds:
            if fd not in current_pid_fds:
                # This FD was seen last time but not this time -> closed
                path, _, _ = self.seen_fds[pid][fd]
                log.debug(
                    f"Detected closed file via poll diff: PID {pid}, FD {fd}, Path {path}"
                )
                self.monitor.close(pid, fd, True, timestamp, source="psutil_poll")
                # Remove from the state map for the next cycle
                del self.seen_fds[pid][fd]
                closed_count += 1

        if closed_count > 0:
            log.debug(f"Detected {closed_count} closed files for PID {pid} this poll.")

        # Clean up PID entry if no FDs remain
        if pid in self.seen_fds and not self.seen_fds[pid]:
            del self.seen_fds[pid]

    def _poll_cycle(self, track_descendants: bool):
        """Performs a single polling cycle for all monitored PIDs."""
        with self.lock:  # Ensure thread-safe access to shared state
            timestamp = time.time()
            pids_in_this_poll = set(self.monitored_pids)  # Copy for safe iteration

            # --- Discover New Descendants (if tracking) ---
            if track_descendants:
                newly_found_pids = set()
                for pid in list(pids_in_this_poll):  # Iterate potential parents
                    proc = _get_process_info(pid)
                    if proc:
                        descendants = _get_process_descendants(proc)
                        for child_pid in descendants:
                            if child_pid not in self.monitored_pids:
                                log.info(
                                    f"Found new child process: {child_pid} (parent: {pid})"
                                )
                                newly_found_pids.add(child_pid)
                                # Mark as existing and try to cache CWD immediately
                                self.pid_exists_status[child_pid] = True
                                child_proc = _get_process_info(child_pid)
                                self._update_cwd_cache(child_pid, child_proc)

                if newly_found_pids:
                    log.info(
                        f"Adding {len(newly_found_pids)} new child PIDs to monitoring."
                    )
                    self.monitored_pids.update(newly_found_pids)
                    pids_in_this_poll.update(
                        newly_found_pids
                    )  # Add to current poll iteration

            # --- Process Each Monitored PID ---
            pids_processed_this_cycle = set()
            for pid in pids_in_this_poll:
                # Skip if we already know it doesn't exist
                if self.pid_exists_status.get(pid) is False:
                    continue

                proc = _get_process_info(pid)
                pids_processed_this_cycle.add(pid)

                if proc:
                    self.pid_exists_status[pid] = True  # Mark as existing
                    self._update_cwd_cache(pid, proc)  # Ensure CWD is cached
                    current_pid_fds = self._process_pid_files(pid, proc, timestamp)
                    self._detect_and_handle_closures(pid, current_pid_fds, timestamp)
                else:
                    # Process doesn't exist or access denied
                    if (
                        self.pid_exists_status.get(pid) is True
                    ):  # Only log transition once
                        log.info(
                            f"Monitored process PID {pid} is no longer accessible or has exited."
                        )
                    self.pid_exists_status[pid] = False

                    # If process is gone, ensure all its tracked FDs are marked closed
                    if pid in self.seen_fds:
                        log.debug(
                            f"Closing all known FDs for exited/inaccessible PID {pid}."
                        )
                        self._detect_and_handle_closures(
                            pid, set(), timestamp
                        )  # Compare against empty set

            # --- Cleanup Stale PID entries ---
            # Remove PIDs from monitored set if they no longer exist
            pids_to_remove = {
                pid
                for pid, exists in self.pid_exists_status.items()
                if not exists and pid in self.monitored_pids
            }
            if pids_to_remove:
                log.debug(
                    f"Removing {len(pids_to_remove)} non-existent PIDs from monitoring set: {pids_to_remove}"
                )
                self.monitored_pids.difference_update(pids_to_remove)
                # Clean up associated state maps
                for pid in pids_to_remove:
                    self.pid_cwd_cache.pop(pid, None)
                    self.seen_fds.pop(pid, None)
                    # Keep pid_exists_status entry as False

    def _polling_thread_func(self, initial_pids: List[int], track_descendants: bool):
        """Background thread function that periodically runs poll cycles."""
        try:
            log.info(
                f"Starting psutil polling thread. Initial PIDs: {initial_pids}, "
                f"Track Descendants: {track_descendants}, Interval: {self.poll_interval}s"
            )
            # Initialize state for the first poll
            with self.lock:
                self.monitored_pids = set(initial_pids)
                self.pid_exists_status = {pid: True for pid in initial_pids}
                # Pre-cache CWD for initial PIDs
                for pid in initial_pids:
                    proc = _get_process_info(pid)
                    self._update_cwd_cache(pid, proc)

            while self.running:
                start_time = time.monotonic()
                try:
                    self._poll_cycle(track_descendants)
                except Exception as e:
                    # Log errors within a poll cycle but keep the thread running
                    log.exception(f"Error during psutil poll cycle: {e}")

                # Sleep accounting for poll duration to maintain interval
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, self.poll_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                # Check running flag again before next loop
                if not self.running:
                    break

        except Exception as e:
            # Catch errors in the thread setup/loop logic itself
            log.exception(f"Psutil polling thread encountered a fatal error: {e}")
        finally:
            log.info("Psutil polling thread stopped.")

    def start(self, initial_pids: List[int], track_descendants: bool):
        """Starts the polling thread."""
        if self.running:
            log.warning("PsutilBackend already running.")
            return

        if not initial_pids:
            log.warning("PsutilBackend start called with no initial PIDs.")
            # Decide if we should start anyway or return
            # return # Option: Don't start if no PIDs

        self.running = True
        self.poll_thread = threading.Thread(
            target=self._polling_thread_func,
            args=(initial_pids, track_descendants),
            daemon=True,  # Allow program exit even if thread is running
            name=f"PsutilPollingThread-{initial_pids}",
        )
        self.poll_thread.start()

    def stop(self):
        """Stops the polling thread."""
        if not self.running:
            return

        log.info("Stopping psutil polling thread...")
        self.running = False
        if self.poll_thread and self.poll_thread.is_alive():
            # Wait briefly for the thread to exit cleanly
            self.poll_thread.join(timeout=self.poll_interval * 2)
            if self.poll_thread.is_alive():
                log.warning("Polling thread did not stop gracefully after timeout.")
        self.poll_thread = None
        log.info("PsutilBackend stopped.")

        # Clear state on stop
        with self.lock:
            self.monitored_pids.clear()
            self.pid_exists_status.clear()
            self.pid_cwd_cache.clear()
            self.seen_fds.clear()


# --- Public Backend Interface ---


def attach(pids: List[int], monitor: Monitor) -> None:
    """Attach to existing processes using psutil polling. Does NOT track descendants."""
    backend = PsutilBackend(monitor)
    try:
        backend.start(initial_pids=pids, track_descendants=False)
        # Keep the main thread alive while the backend runs (e.g., until Ctrl+C)
        while backend.running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        log.info("Attach interrupted by user.")
    except Exception as e:
        log.exception(f"Unexpected error during psutil attach: {e}")
    finally:
        backend.stop()


def run(command: List[str], monitor: Monitor) -> None:
    """Run a command and monitor it and its descendants using psutil polling."""
    backend = PsutilBackend(monitor)
    proc = None
    try:
        log.info(f"Running command with psutil backend: {' '.join(command)}")
        # Start the target process
        proc = subprocess.Popen(command)
        pid = proc.pid
        log.info(f"Command '{' '.join(command)}' started with PID: {pid}")

        # Start the backend polling thread
        backend.start(initial_pids=[pid], track_descendants=True)

        # Wait for the command process to complete OR backend to stop (e.g., Ctrl+C)
        while backend.running and proc.poll() is None:
            time.sleep(0.1)

        if proc.poll() is not None:
            log.info(f"Command process {pid} exited with code: {proc.returncode}")

    except FileNotFoundError:
        log.exception(f"Command not found: {command[0]}")
    except subprocess.SubprocessError as e:
        log.exception(f"Error launching command '{' '.join(command)}': {e}")
    except KeyboardInterrupt:
        log.info("Run interrupted by user.")
    except Exception as e:
        log.exception(f"Unexpected error during psutil run: {e}")
    finally:
        log.info("Cleaning up after psutil run.")
        # Stop the backend polling thread first
        backend.stop()
        # Ensure the monitored command process is terminated if it's still running
        if proc and proc.poll() is None:
            log.info(f"Terminating command process (PID: {proc.pid})...")
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
                log.debug(f"Command process {proc.pid} terminated gracefully.")
            except subprocess.TimeoutExpired:
                log.warning(
                    f"Command process {proc.pid} did not terminate gracefully, killing."
                )
                proc.kill()
                proc.wait()
                log.debug(f"Command process {proc.pid} killed.")
            except Exception as term_err:
                log.exception(f"Error during command process termination: {term_err}")
