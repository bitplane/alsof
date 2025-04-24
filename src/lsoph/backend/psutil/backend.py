# Filename: src/lsoph/backend/psutil/backend.py
"""Psutil backend implementation using polling."""

import asyncio
import logging
import os
import time
from typing import Any

from lsoph.monitor import Monitor

# Import the base class using relative path
from ..base import Backend

# Import helper functions and availability check from sibling module
from .helpers import (
    PSUTIL_AVAILABLE,
    _get_process_cwd,
    _get_process_descendants,
    _get_process_info,
    _get_process_open_files,
)

# Import psutil conditionally for type hints if available
if PSUTIL_AVAILABLE:
    import psutil
else:
    # Define a placeholder if psutil is not available for type hinting
    # This helps linters but won't be used at runtime if PSUTIL_AVAILABLE is False.
    class PsutilProcessPlaceholder:
        pid: int

    psutil = None  # Ensure psutil is None if not imported


log = logging.getLogger(__name__)  # Use specific logger

# --- Constants ---
DEFAULT_PSUTIL_POLL_INTERVAL = 0.5


# --- Async Backend Class ---
class Psutil(Backend):
    """Async backend implementation using psutil polling."""

    # Class attribute for the command-line name
    backend_name = "psutil"

    def __init__(
        self, monitor: Monitor, poll_interval: float = DEFAULT_PSUTIL_POLL_INTERVAL
    ):
        super().__init__(monitor)
        if not PSUTIL_AVAILABLE:
            raise RuntimeError(
                "psutil library is required for Psutil backend but not installed."
            )
        self.poll_interval = max(0.1, poll_interval)  # Ensure minimum interval
        # State is managed within the run methods

    @staticmethod
    def is_available() -> bool:
        """Check if the psutil library is installed."""
        log.debug(
            f"Checking availability for {Psutil.backend_name}: {PSUTIL_AVAILABLE}"
        )  # Use class name
        return PSUTIL_AVAILABLE

    # --- Internal Helpers used by _poll_cycle ---
    # These methods remain part of the class as they operate on instance state or caches.

    def _update_cwd_cache(
        self,
        pid: int,
        proc: "psutil.Process | None",  # Use psutil.Process if available
        pid_cwd_cache: dict[int, str | None],
    ):
        """Updates the CWD cache if the PID is not already present."""
        if proc and pid not in pid_cwd_cache:
            cwd = _get_process_cwd(proc)
            pid_cwd_cache[pid] = cwd  # Store None if CWD retrieval failed

    def _resolve_path(
        self, pid: int, path: str, pid_cwd_cache: dict[int, str | None]
    ) -> str:
        """Resolves a relative path using the cached CWD."""
        # Check for absolute paths (Unix/Windows) or special markers
        if path.startswith(("/", "<", "@")) or (len(path) > 1 and path[1] == ":"):
            return path
        cwd = pid_cwd_cache.get(pid)
        if cwd:
            try:
                # Use os.path.normpath for better path normalization
                return os.path.normpath(os.path.join(cwd, path))
            except ValueError as e:  # Catch errors during join/normpath
                log.warning(
                    f"Error joining path '{path}' with CWD '{cwd}' for PID {pid}: {e}"
                )
        # Return original path if CWD is unknown or join fails
        return path

    def _process_pid_files(
        self,
        pid: int,
        proc: "psutil.Process",  # Use psutil.Process if available
        timestamp: float,
        pid_cwd_cache: dict[int, str | None],
        seen_fds: dict[int, dict[int, tuple[str, bool, bool]]],
    ) -> set[int]:
        """Processes open files for a single PID, updating monitor state."""
        current_pid_fds: set[int] = set()
        # Use helper from helpers module
        open_files_data = _get_process_open_files(proc)

        for file_info in open_files_data:
            path, fd, mode = (
                file_info["path"],
                file_info["fd"],
                file_info.get("mode", ""),
            )
            # Skip invalid FDs (like -1 for sockets)
            if fd < 0:
                continue

            current_pid_fds.add(fd)
            resolved_path = self._resolve_path(pid, path, pid_cwd_cache)

            # Determine read/write capability based on mode
            can_read = "r" in mode or "+" in mode
            can_write = "w" in mode or "a" in mode or "+" in mode

            # Check against previous state stored in seen_fds
            previous_state = seen_fds.get(pid, {}).get(fd)
            is_new = previous_state is None
            has_changed = False
            if not is_new:
                old_path, old_read, old_write = previous_state
                has_changed = (
                    old_path != resolved_path
                    or old_read != can_read
                    or old_write != can_write
                )

            # If new or changed, update monitor and seen_fds state
            if is_new or has_changed:
                # If changed, simulate close of old state first
                if has_changed:
                    old_path, _, _ = previous_state
                    self.monitor.close(pid, fd, True, timestamp, source="psutil_change")

                # Report open event
                self.monitor.open(
                    pid, resolved_path, fd, True, timestamp, source="psutil", mode=mode
                )
                # Update seen_fds cache
                seen_fds.setdefault(pid, {})[fd] = (resolved_path, can_read, can_write)

                # Report read/write based on mode (as psutil doesn't track operations)
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
        self,
        pid: int,
        current_pid_fds: set[int],
        timestamp: float,
        seen_fds: dict[int, dict[int, tuple[str, bool, bool]]],
    ):
        """Detects and reports closed FDs by comparing current and previous state."""
        if pid not in seen_fds:
            return  # No previous state for this PID

        closed_count = 0
        # Iterate over a copy of keys as we might delete from the dict
        previous_pid_fds = list(seen_fds[pid].keys())

        for fd in previous_pid_fds:
            if fd not in current_pid_fds:
                # FD was present before, but not now -> closed
                path, _, _ = seen_fds[pid][fd]  # Get path from cached state
                self.monitor.close(pid, fd, True, timestamp, source="psutil_poll")
                # Remove the closed FD from the cache
                del seen_fds[pid][fd]
                closed_count += 1

        # Clean up PID entry if it becomes empty
        if pid in seen_fds and not seen_fds[pid]:
            del seen_fds[pid]
        # if closed_count > 0: log.debug(f"Detected {closed_count} closures for PID {pid}")

    def _poll_cycle(
        self,
        monitored_pids: set[int],
        pid_exists_status: dict[int, bool],
        pid_cwd_cache: dict[int, str | None],
        seen_fds: dict[int, dict[int, tuple[str, bool, bool]]],
        track_descendants: bool,
    ) -> set[int]:
        """
        Performs a single polling cycle.
        Accepts state dictionaries as arguments and returns updated monitored_pids.
        """
        timestamp = time.time()
        pids_in_this_poll = set(monitored_pids)  # Copy to iterate safely

        # --- Discover New Descendants (if tracking) ---
        if track_descendants:
            newly_found_pids = set()
            # Check children of currently monitored *and existing* PIDs
            pids_to_check_children = [
                p for p in monitored_pids if pid_exists_status.get(p, True)
            ]
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
                            # Mark as existing and cache CWD immediately
                            pid_exists_status[child_pid] = True
                            child_proc = _get_process_info(child_pid)
                            self._update_cwd_cache(child_pid, child_proc, pid_cwd_cache)
            # Add newly found PIDs to the main sets
            if newly_found_pids:
                log.info(
                    f"Adding {len(newly_found_pids)} new child PIDs to monitoring."
                )
                monitored_pids.update(newly_found_pids)
                pids_in_this_poll.update(newly_found_pids)

        # --- Process Each Monitored PID ---
        for pid in pids_in_this_poll:
            # Skip if already marked as non-existent in this cycle
            if pid_exists_status.get(pid) is False:
                continue

            proc = _get_process_info(pid)
            if proc:
                # Process exists, update status and process files
                pid_exists_status[pid] = True
                self._update_cwd_cache(pid, proc, pid_cwd_cache)
                current_pid_fds = self._process_pid_files(
                    pid, proc, timestamp, pid_cwd_cache, seen_fds
                )
                self._detect_and_handle_closures(
                    pid, current_pid_fds, timestamp, seen_fds
                )
            else:
                # Process doesn't exist or access denied
                if (
                    pid_exists_status.get(pid) is True
                ):  # Log only if it was previously seen
                    log.info(
                        f"Monitored process PID {pid} is no longer accessible or has exited."
                    )
                pid_exists_status[pid] = False
                # If process is gone, ensure all its cached FDs are marked as closed
                if pid in seen_fds:
                    self._detect_and_handle_closures(pid, set(), timestamp, seen_fds)
                # Signal process exit to the monitor for general cleanup related to the PID
                self.monitor.process_exit(pid, timestamp)

        # --- Cleanup Stale PID entries ---
        pids_to_remove = {
            pid
            for pid, exists in pid_exists_status.items()
            if not exists
            and pid in monitored_pids  # Only remove if it was being monitored
        }
        if pids_to_remove:
            log.debug(
                f"Removing {len(pids_to_remove)} non-existent PIDs from monitoring set: {pids_to_remove}"
            )
            monitored_pids.difference_update(pids_to_remove)
            # Clean up associated state caches
            for pid in pids_to_remove:
                pid_cwd_cache.pop(pid, None)
                seen_fds.pop(pid, None)
                # Keep False status in pid_exists_status for future checks

        return monitored_pids  # Return the updated set

    async def _run_loop(
        self, initial_pids: list[int], track_descendants: bool
    ):  # Use list
        """The core async monitoring loop, shared by attach and run_command."""
        log.info(
            f"Starting psutil monitoring loop. Initial PIDs: {initial_pids}, Track Descendants: {track_descendants}"
        )

        # --- State Management within the loop ---
        monitored_pids: set[int] = set(initial_pids)
        pid_exists_status: dict[int, bool] = {
            pid: True for pid in initial_pids
        }  # Use dict
        pid_cwd_cache: dict[int, str | None] = {}  # Use dict
        seen_fds: dict[int, dict[int, tuple[str, bool, bool]]] = {}  # Use dict
        # Initial CWD cache population
        for pid in initial_pids:
            proc = _get_process_info(pid)
            self._update_cwd_cache(pid, proc, pid_cwd_cache)
        # --- End State Management ---

        try:
            while not self.should_stop:
                start_time = time.monotonic()

                # Perform the synchronous polling logic, passing state
                # This function now modifies the state dicts/sets directly
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
                    # Use asyncio.sleep for non-blocking wait
                    await asyncio.sleep(sleep_time)
                elif (
                    elapsed > self.poll_interval * 1.5
                ):  # Log if significantly over interval
                    log.warning(
                        f"Psutil poll cycle took longer than interval ({elapsed:.2f}s > {self.poll_interval:.2f}s)"
                    )
                    await asyncio.sleep(0.01)  # Yield briefly

        except asyncio.CancelledError:
            log.info(
                f"{self.__class__.__name__} backend {('attach' if not track_descendants else 'run')} cancelled."  # Use class name
            )
        except Exception as e:
            log.exception(
                f"Unexpected error in {self.__class__.__name__} async loop: {e}"
            )  # Use class name
        finally:
            log.info(
                f"Exiting {self.__class__.__name__} async {('attach' if not track_descendants else 'run')} loop."  # Use class name
            )

    async def attach(self, pids: list[int]):  # Use list
        """Implementation of the attach method."""
        if not pids:
            log.warning(
                f"{self.__class__.__name__}.attach called with no PIDs."
            )  # Use class name
            return
        # Run the loop, now ALWAYS tracking descendants for attach mode too
        # This aligns behavior with strace/lsof where attach implies following children
        await self._run_loop(initial_pids=pids, track_descendants=True)

    # run_command is inherited from the base class
    # The base implementation starts the command and then calls self.attach([pid]).
    # Since our attach now handles descendants, run_command will effectively
    # monitor the initial command and all its descendants using this Psutil backend.
