# Filename: src/lsoph/backend/lsof/backend.py
"""Lsof backend implementation using polling and descendant tracking."""

import asyncio
import logging
import shutil  # Import shutil for which()
import time
from typing import Any  # Keep Any if needed, though maybe not directly here

from lsoph.monitor import Monitor

# Import the utility function for getting descendants
from lsoph.util.pid import get_descendants

# Import the base class using relative path
from ..base import Backend

# Import helper functions from sibling module
from .helpers import _perform_lsof_poll_async

log = logging.getLogger(__name__)  # Use specific logger

# --- Constants ---
DEFAULT_LSOF_POLL_INTERVAL = 1.0
# Check for new children every N polls
DEFAULT_CHILD_CHECK_INTERVAL_MULTIPLIER = 5


# --- Async Backend Class ---
class Lsof(Backend):  # Renamed from LsofBackend
    """
    Async backend implementation using periodic `lsof` command execution.

    Monitors specified initial PIDs and automatically discovers and monitors
    their descendants over time. Detects file open/close events by comparing
    lsof output between poll cycles.
    """

    # Class attribute for the command-line name
    backend_name = "lsof"

    def __init__(
        self,
        monitor: Monitor,
        poll_interval: float = DEFAULT_LSOF_POLL_INTERVAL,
        child_check_multiplier: int = DEFAULT_CHILD_CHECK_INTERVAL_MULTIPLIER,
    ):
        """
        Initializes the Lsof backend.

        Args:
            monitor: The central Monitor instance.
            poll_interval: Time in seconds between lsof polls.
            child_check_multiplier: Check for new descendants every N polls.
        """
        super().__init__(monitor)
        self.poll_interval = max(
            0.1, poll_interval
        )  # Ensure minimum reasonable interval
        self.child_check_multiplier = max(1, child_check_multiplier)  # Ensure >= 1
        log.info(
            f"{self.__class__.__name__} initialized. Poll Interval: {self.poll_interval}s, "  # Use class name in log
            f"Child Check Multiplier: {self.child_check_multiplier}"
        )
        # Note: Internal state like seen_fds is managed within the attach/run loop

    @staticmethod
    def is_available() -> bool:
        """Check if the lsof executable is available in the system PATH."""
        available = shutil.which("lsof") is not None
        log.debug(
            f"Checking availability for {Lsof.backend_name}: {available}"
        )  # Use class name
        return available

    async def attach(self, pids: list[int]):
        """
        Attaches to and monitors a list of initial PIDs and their descendants.

        This method runs a continuous loop, polling with `lsof`, updating the
        monitor state, and periodically checking for new child processes of the
        initial PIDs.

        Args:
            pids: A list of initial process IDs to monitor.
        """
        if not pids:
            log.warning(
                f"{self.__class__.__name__}.attach called with no PIDs."
            )  # Use class name
            return

        # Store original, valid PIDs (must be positive integers)
        initial_pids: set[int] = {p for p in pids if isinstance(p, int) and p > 0}
        if not initial_pids:
            log.warning(
                f"{self.__class__.__name__}.attach called with no valid initial PIDs (must be > 0)."
            )  # Use class name
            return

        log.info(
            f"Starting {self.__class__.__name__} attach monitoring loop. Initial PIDs: {initial_pids}"  # Use class name
        )

        # --- State for the attach loop ---
        # Set of all PIDs currently being monitored (initial + discovered descendants)
        monitored_pids: set[int] = set(initial_pids)
        # State of FDs seen in the last successful poll {pid: {(fd, path), ...}}
        # Used to detect file closures between polls.
        seen_fds: dict[int, set[tuple[int, str]]] = {}
        # Counter for triggering periodic child checks
        poll_count: int = 0
        # --- End State ---

        try:
            while not self.should_stop:
                start_time = time.monotonic()
                poll_count += 1
                log.trace(f"{self.__class__.__name__} attach loop cycle: {poll_count}, Monitoring PIDs: {monitored_pids}")  # type: ignore

                # --- Periodically check for new descendants ---
                # Check descendants only based on the *original* set of PIDs provided
                if poll_count % self.child_check_multiplier == 0:
                    log.debug(
                        f"Checking for new descendants of initial PIDs: {initial_pids}"
                    )
                    newly_found_pids: set[int] = set()
                    # Check each initial parent PID for new children
                    for parent_pid in initial_pids:
                        # Only check if the parent itself is still monitored (might have exited)
                        if parent_pid in monitored_pids:
                            try:
                                # Use the utility function (requires psutil)
                                descendant_pids = get_descendants(parent_pid)
                                for child_pid in descendant_pids:
                                    # Add if it's a valid PID and not already monitored
                                    if (
                                        child_pid > 0
                                        and child_pid not in monitored_pids
                                    ):
                                        log.info(
                                            f"Found new child process: {child_pid} (parent: {parent_pid})"
                                        )
                                        newly_found_pids.add(child_pid)
                            except Exception as desc_err:
                                # Log error but continue checking other parents
                                log.error(
                                    f"Error getting descendants for PID {parent_pid}: {desc_err}"
                                )
                        # else: log.debug(f"Skipping descendant check for exited initial PID: {parent_pid}")

                    if newly_found_pids:
                        log.info(
                            f"Adding {len(newly_found_pids)} new child PIDs to monitoring."
                        )
                        monitored_pids.update(newly_found_pids)
                # --- End Descendant Check ---

                # --- Perform lsof Poll ---
                pids_to_poll = list(monitored_pids)
                if not pids_to_poll:
                    log.info(
                        "No PIDs currently being monitored. Waiting for new children or stop signal."
                    )
                    # No PIDs to poll, just wait for the next cycle/descendant check
                else:
                    # Call the helper function to run lsof and process results
                    current_fds, pids_seen = await _perform_lsof_poll_async(
                        pids_to_poll, self.monitor, seen_fds
                    )
                    # Update the state for the *next* poll's comparison
                    seen_fds = current_fds

                    # --- Clean up state for PIDs that disappeared ---
                    # Identify PIDs that were in our monitored set but NOT in the lsof output
                    exited_pids = monitored_pids - pids_seen
                    if exited_pids:
                        log.debug(
                            f"PIDs presumed exited (not in lsof output): {exited_pids}"
                        )
                        # Remove exited PIDs from the set we actively monitor
                        monitored_pids -= exited_pids
                        # Note: FD closure and process_exit for these PIDs are handled
                        # within _perform_lsof_poll_async by comparing seen_fds and pids_seen.
                        # No need to explicitly remove from seen_fds here again.
                # --- End lsof Poll ---

                # Check stop event again after polling and updates
                if self.should_stop:
                    log.debug("Stop signal detected after poll cycle.")
                    break

                # --- Sleep until next poll cycle ---
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, self.poll_interval - elapsed)
                if sleep_time > 0:
                    log.trace(f"Sleeping for {sleep_time:.3f}s")  # type: ignore
                    await asyncio.sleep(sleep_time)
                # If loop took significantly longer than interval, log warning and yield control briefly
                elif elapsed > self.poll_interval * 1.5:  # Add some buffer
                    log.warning(
                        f"lsof poll cycle took longer than interval ({elapsed:.2f}s > {self.poll_interval:.2f}s)"
                    )
                    await asyncio.sleep(
                        0.01
                    )  # Yield control briefly to prevent starving event loop

        except asyncio.CancelledError:
            log.info(
                f"{self.__class__.__name__} backend attach task cancelled."
            )  # Use class name
        except Exception as e:
            # Catch unexpected errors in the main loop
            log.exception(
                f"Unexpected error in {self.__class__.__name__} async attach loop: {e}"
            )  # Use class name
        finally:
            log.info(
                f"Exiting {self.__class__.__name__} async attach loop."
            )  # Use class name
            # Optional: Perform any final cleanup if needed, though usually handled by app exit
            # e.g., closing any remaining FDs in the monitor state if desired.

    # run_command is inherited from the base Backend class.
    # The base implementation starts the command and then calls self.attach([pid]).
    # Since our attach now handles descendants, run_command will effectively
    # monitor the initial command and all its descendants using this Lsof backend.
