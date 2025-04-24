# Filename: src/lsoph/ui/app.py
"""Main Textual application class for lsoph."""

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable, Coroutine
from typing import Any, Optional  # Added Optional

# Removed unused imports: Coordinate, CellKey, RowKey, _format_file_info_for_table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.dom import NoMatches
from textual.reactive import reactive

# Removed DataTable import
from textual.widgets import Footer, Header, Static
from textual.worker import Worker, WorkerState

from lsoph.backend.base import Backend
from lsoph.monitor import FileInfo, Monitor  # Keep FileInfo for type hint
from lsoph.util.short_path import short_path

from .detail_screen import DetailScreen

# Import the new widget from its new location
from .file_data_table import FileDataTable  # UPDATED IMPORT PATH
from .log_screen import LogScreen

# Type alias for the backend coroutine (attach or run_command)
BackendCoroutine = Coroutine[Any, Any, None]

log = logging.getLogger("lsoph.ui.app")

# REMOVED _format_file_info_for_table helper function - moved to widget

# --- Main Application ---


class LsophApp(App[None]):
    """Textual file monitor application for lsoph."""

    TITLE = "lsoph - List Open Files Helper"
    SUB_TITLE = "Monitoring file activity..."

    BINDINGS = [
        # --- Always Visible Bindings ---
        Binding("q,escape", "quit", "Quit", show=True),
        Binding("l,ctrl+l", "show_log", "Show/Hide Log", show=True),
        # --- Contextual Bindings (Hidden by default, work on main screen) ---
        Binding("x", "ignore_all", "Ignore All", show=False),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Sel.", show=False),
        Binding("d,enter", "show_detail", "Show Detail", show=False),
        # --- Debug Bindings (Always hidden) ---
        Binding("ctrl+d", "dump_monitor", "Dump Monitor", show=False),
    ]

    CSS_PATH = "app.css"  # Load CSS from file

    # Reactive variables to trigger updates
    last_monitor_version = reactive(-1)
    status_text = reactive("Status: Initializing...")

    def __init__(
        self,
        monitor: Monitor,
        log_queue: deque,
        backend_instance: Backend,
        backend_coroutine: BackendCoroutine,
    ):
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        self.backend_instance = backend_instance
        self.backend_coroutine = backend_coroutine
        self._update_interval = 0.5  # Interval for checking monitor version
        self._backend_worker: Worker | None = None
        self._backend_stop_signalled = False  # Flag to track if stop was requested
        self._backend_stopped_notified = False  # Flag to prevent repeated notifications
        # Reference to the FileDataTable widget instance
        self._file_table: Optional[FileDataTable] = None

    def compose(self) -> ComposeResult:
        """Create child widgets for the main application screen."""
        yield Header()
        # Use the custom FileDataTable widget
        yield FileDataTable(id="file-table")
        yield Static(self.status_text, id="status-bar")  # Use reactive variable
        yield Footer()

    # --- Worker Management ---
    # (start_backend_worker and cancel_backend_worker remain the same)
    def start_backend_worker(self):
        """Starts the background worker to run the backend's async method."""
        if self._backend_worker and self._backend_worker.state == WorkerState.RUNNING:
            log.warning("Backend worker already running.")
            return
        worker_name = f"backend_{self.backend_instance.__class__.__name__}"
        log.info(f"Starting worker '{worker_name}' to run backend coroutine...")
        self._backend_worker = self.run_worker(
            self.backend_coroutine,  # The async function to run
            name=worker_name,
            group="backend_workers",
            description=f"Running {self.backend_instance.__class__.__name__} backend...",
            exclusive=True,  # Ensure only one backend worker runs
        )
        # Check if worker creation failed immediately (rare)
        if not self._backend_worker:
            log.error(f"Failed to create worker {worker_name}")
            self.notify("Error starting backend worker!", severity="error", timeout=5)
            return

        log.info(
            f"Worker {self._backend_worker.name} created with state {self._backend_worker.state}"
        )

    async def cancel_backend_worker(self):
        """Signals the backend instance to stop and cancels the Textual worker."""
        # 1. Signal the backend instance itself to stop its internal loops/processes
        if (
            not self._backend_stop_signalled
        ):  # Prevent multiple signals if called rapidly
            log.debug("Calling backend_instance.stop()...")
            await self.backend_instance.stop()
            self._backend_stop_signalled = True  # Mark that we've signalled stop
            log.debug("Backend_instance.stop() returned.")

        # 2. Cancel the Textual worker managing the coroutine
        worker = self._backend_worker  # Use local variable for safety
        if worker and worker.state == WorkerState.RUNNING:
            log.info(f"Requesting cancellation for Textual worker {worker.name}...")
            try:
                await worker.cancel()
                log.info(f"Textual worker {worker.name} cancellation requested.")
            except Exception as e:
                # Log error but continue, backend stop signal is more critical
                log.error(f"Error cancelling Textual worker {worker.name}: {e}")
        elif worker:
            log.debug(
                f"Textual backend worker {worker.name} not running (state: {worker.state}). No Textual cancellation needed."
            )
        else:
            log.debug("No Textual backend worker instance to cancel.")

        # 3. Clear the worker reference after handling
        self._backend_worker = None

    # --- App Lifecycle ---

    def on_mount(self) -> None:
        """Called when the app screen is mounted."""
        log.info("LsophApp mounting...")
        try:
            # Store reference to the table widget
            self._file_table = self.query_one(FileDataTable)
            # No need to add columns here, widget does it in its on_mount
            # Initial data update will be triggered by check_monitor_version -> watch
            self._file_table.focus()
            log.debug("FileDataTable focused on mount.")
        except Exception as e:
            log.exception(f"Error getting FileDataTable on mount: {e}")

        # Start the backend worker and the UI update timer
        self.start_backend_worker()
        self.set_interval(self._update_interval, self.check_monitor_version)
        log.info("UI Mounted, update timer started, backend worker started.")

    async def on_unmount(self) -> None:
        """Called when the app is unmounted (e.g., on quit)."""
        log.info("LsophApp unmounting. Cancelling backend worker...")
        # Ensure backend worker is stopped cleanly on exit
        await self.cancel_backend_worker()

    # --- Reactive Watchers ---

    def watch_last_monitor_version(self, old_version: int, new_version: int) -> None:
        """Triggers table update when monitor version changes."""
        # Ensure table exists before trying to update
        if not self._file_table:
            log.warning("Monitor version changed, but file table widget not ready.")
            return

        if new_version > old_version:
            log.debug(
                f"Monitor version changed ({old_version} -> {new_version}), calling table update."
            )
            # Get sorted data from monitor
            all_files = list(self.monitor)
            active_files = [
                info
                for info in all_files
                if info.path not in self.monitor.ignored_paths
            ]
            active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
            # Pass data to the widget's update method
            self._file_table.update_data(active_files)
            # Update status bar here as well, after table update initiated
            self.update_status(
                f"Tracking {len(active_files)} files. Ignored: {len(self.monitor.ignored_paths)}. Monitor v{new_version}"
            )

    def watch_status_text(self, old_text: str, new_text: str) -> None:
        """Updates the status bar widget when status_text changes."""
        if self.is_mounted:  # Ensure widgets exist
            try:
                # Query for the status bar widget by ID
                status_bars = self.query("#status-bar")
                if status_bars:
                    status_bars.first(Static).update(new_text)
            except Exception as e:
                # Log warning if update fails, but don't crash UI
                log.warning(f"Could not update status bar via watcher: {e}")

    # --- Update Logic ---

    def check_monitor_version(self):
        """Periodically checks the monitor's version and worker status."""
        worker = self._backend_worker
        # Check if worker stopped unexpectedly (logic remains the same)
        if (
            worker
            and worker.state != WorkerState.RUNNING
            and not self._backend_stop_signalled
            and not self._backend_stopped_notified
        ):
            self._backend_stopped_notified = True
            status_msg = f"Error: Monitoring backend stopped unexpectedly!"
            log_msg = f"Backend worker {worker.name} stopped unexpectedly (state: {worker.state})."
            severity = "error"
            log.error(log_msg + " Check previous logs for potential errors.")
            self.update_status(status_msg)
            self.notify(
                f"{status_msg} Check logs for details.",
                title="Backend Stopped Unexpectedly",
                severity=severity,
                timeout=10,
            )
            self._backend_worker = None

        # Check monitor version and update reactive variable IF it changed
        current_version = self.monitor.version
        if current_version != self.last_monitor_version:
            # Update reactive variable, which triggers watch_last_monitor_version
            self.last_monitor_version = current_version

    def update_status(self, text: str):
        """Helper method to update the reactive status_text variable."""
        self.status_text = text

    # REMOVED update_table method - logic moved to FileDataTable and watcher

    # --- Event Handlers ---

    # Removed on_data_table_row_selected - handled by action_show_detail check

    # --- Actions ---

    async def action_quit(self) -> None:
        """Action to quit the application."""
        log.info("Quit action triggered. Signalling backend worker and exiting.")
        await self.cancel_backend_worker()
        self.exit()

    # REMOVED _get_selected_path - use self._file_table.selected_path instead

    def action_ignore_selected(self) -> None:
        """Action to ignore the currently selected file path."""
        if not self._file_table or not self._file_table.has_focus:
            log.debug("Ignore selected action ignored: Table not focused or not ready.")
            return

        path_to_ignore = self._file_table.selected_path  # Use widget property
        if not path_to_ignore:
            self.notify("No row selected.", severity="warning", timeout=2)
            return

        log.info(f"Ignoring selected path: {path_to_ignore}")
        try:
            # No need to manage cursor index here, widget handles it in update_data
            self.monitor.ignore(path_to_ignore)
            # Monitor version change will trigger table update via watcher
            self.notify(f"Ignored: {short_path(path_to_ignore, 60)}", timeout=2)
        except Exception as e:
            log.exception("Error ignoring selected.")
            self.notify(f"Error ignoring file: {e}", severity="error")

    # REMOVED _move_cursor_after_ignore - handled by widget

    def action_ignore_all(self) -> None:
        """Action to ignore all currently tracked files."""
        if not self._file_table or not self._file_table.has_focus:
            log.debug("Ignore all action ignored: Table not focused or not ready.")
            return

        log.info("Ignoring all tracked files.")
        try:
            count_before = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            if count_before == 0:
                self.notify("No active files to ignore.", timeout=2)
                return
            self.monitor.ignore_all()
            # Monitor version change will trigger table update via watcher
            self.notify(f"Ignoring {count_before} currently tracked files.", timeout=2)
        except Exception as e:
            log.exception("Error ignoring all.")
            self.notify(f"Error ignoring all files: {e}", severity="error")

    # REMOVED _move_cursor_after_ignore_all - handled by widget

    def action_show_log(self) -> None:
        """Action to show or hide the log screen."""
        # (Logic remains the same)
        is_log_screen_active = isinstance(self.screen, LogScreen)
        if is_log_screen_active:
            self.pop_screen()
            log.debug("Popped LogScreen.")
        else:
            log.info("Action: show_log triggered. Pushing LogScreen.")
            self.push_screen(LogScreen(self.log_queue))

    def action_show_detail(self) -> None:
        """Shows the detail screen for the selected row."""
        if not self._file_table or not self._file_table.has_focus:
            log.debug("Show detail action ignored: Table not focused or not ready.")
            return

        path = self._file_table.selected_path  # Use widget property
        if not path:
            self.notify("No row selected.", severity="warning", timeout=2)
            return

        log.debug(f"Showing details for selected path: {path}")
        try:
            file_info = self.monitor.files.get(path)
            if file_info:
                log.debug(f"Found FileInfo, pushing DetailScreen for {path}")
                self.push_screen(DetailScreen(file_info))
            else:
                log.warning(
                    f"File '{path}' (from selected row) not found in monitor state."
                )
                self.notify(
                    "File state not found (may have changed).",
                    severity="warning",
                    timeout=3,
                )
        except Exception as e:
            log.exception(f"Error pushing DetailScreen for path: {path}")
            self.notify(f"Error showing details: {e}", severity="error")

    def action_dump_monitor(self) -> None:
        """Debug action to dump monitor state to log."""
        # (Logic remains the same)
        log.debug("--- Monitor State Dump ---")
        try:
            log.debug(f"Identifier: {self.monitor.identifier}")
            log.debug(f"Backend PID: {self.monitor.backend_pid}")
            log.debug(
                f"Ignored Paths ({len(self.monitor.ignored_paths)}): {self.monitor.ignored_paths!r}"
            )
            log.debug(
                f"PID->FD Map ({len(self.monitor.pid_fd_map)} pids): {self.monitor.pid_fd_map!r}"
            )
            log.debug(f"Files Dict ({len(self.monitor.files)} items):")
            sorted_files = sorted(list(self.monitor), key=lambda f: f.path)
            for info in sorted_files:
                log.debug(
                    f"  {info.path}: Status={info.status}, Open={info.is_open}, R/W={info.bytes_read}/{info.bytes_written}, Last={info.last_event_type}, PIDs={list(info.open_by_pids.keys())}"
                )
            log.debug("--- End Monitor State Dump ---")
            self.notify("Monitor state dumped to log (debug level).")
        except Exception as e:
            log.exception("Error during monitor state dump.")
            self.notify("Error dumping monitor state.", severity="error")
